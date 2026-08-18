import type { NanosiemClient, SearchResponse } from '@nano-rs/investigator-core';
import { isAsyncSearchAck } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';
import {
  deploymentGuidance,
  getDeploymentProfile,
  isLakeRawSqlRefusal,
  recordRawSqlOutcome,
} from '../deployment.js';

// ---------------------------------------------------------------------------
// Helper: relative time parsing
// ---------------------------------------------------------------------------

export function parseRelativeTime(time: string): string {
  if (time === 'now') return new Date().toISOString();
  const match = time.match(/^-(\d+)(m|h|d|w)$/);
  if (match) {
    const value = parseInt(match[1], 10);
    const unit = match[2];
    const now = new Date();
    switch (unit) {
      case 'm': now.setMinutes(now.getMinutes() - value); break;
      case 'h': now.setHours(now.getHours() - value); break;
      case 'd': now.setDate(now.getDate() - value); break;
      case 'w': now.setDate(now.getDate() - value * 7); break;
    }
    return now.toISOString();
  }
  // Assume ISO 8601 — validate basic format
  if (/^\d{4}-\d{2}-\d{2}/.test(time)) {
    return time;
  }
  throw new Error(
    `Invalid time format: "${time}". Use relative ("-1h", "-7d", "-30m", "-2w"), "now", or ISO 8601 timestamp.`
  );
}

// MCP search results are for interactive investigation, not bulk export. Keeping
// this boundary local to the tool prevents a caller from asking the backend for
// a response large enough to close the MCP transport.
const DEFAULT_MCP_RESULT_LIMIT = 100;
const MAX_MCP_RESULT_LIMIT = 1_000;
// Command renderers can put a second representation of the data inside one
// reserved metadata row. In particular, `| lateral` carries a complete graph
// under `_lateral_graph`, outside normal row pagination. Keep small graphs for
// clients that render them, but do not let one nested object bypass the MCP's
// bounded-output contract. Half of PIVT's 128 KiB spill threshold leaves room
// for the actual page and JSON-RPC envelope.
const MAX_MCP_LATERAL_GRAPH_BYTES = 64 * 1024;

function mcpResultLimit(value: unknown, toolName: string): number {
  const limit = value === undefined ? DEFAULT_MCP_RESULT_LIMIT : value;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1) {
    throw new Error(`${toolName} limit must be a positive integer.`);
  }
  if (limit > MAX_MCP_RESULT_LIMIT) {
    throw new Error(
      `${toolName} limit ${limit} exceeds the MCP safety ceiling of ${MAX_MCP_RESULT_LIMIT} rows. ` +
      'Narrow the query, request a top-N aggregate, or use the nano UI/export path for bulk results.',
    );
  }
  return limit;
}

function resultLimitViolation(returnedRows: number, requestedLimit: number): ToolResult {
  return err(
    `Search result withheld: nano returned ${returnedRows} rows after the MCP requested a limit of ${requestedLimit}. ` +
    'This usually means the nano backend did not apply the output limit after a high-cardinality stats/timechart aggregation. ' +
    `For a top-N result, sort first and append \`| head ${requestedLimit}\`; otherwise add filters or lower cardinality. ` +
    'Upgrade the nano backend if the query is already bounded and this error persists. ' +
    'No rows were returned to protect the MCP connection; do not interpret this error as zero matches.',
  );
}

function returnedDataRowCount(rows: Record<string, unknown>[]): number {
  // Nano prepends at most one command-renderer metadata row. Excluding every
  // `_display_type`-shaped row would let a computed or malformed result evade
  // the MCP row ceiling, so only the first reserved row receives that treatment.
  let metadataConsumed = false;
  return rows.reduce((count, row) => {
    const isMetadata = !metadataConsumed
      && row !== null
      && typeof row === 'object'
      && !Array.isArray(row)
      && Object.prototype.hasOwnProperty.call(row, '_display_type');
    if (isMetadata) {
      metadataConsumed = true;
      return count;
    }
    return count + 1;
  }, 0);
}

function compactLateralGraphMetadata(
  rows: Record<string, unknown>[],
  requestedDataRows: number,
): Record<string, unknown>[] {
  return rows.map((row) => {
    if (row._display_type !== 'lateral' || row._lateral_graph === undefined) {
      return row;
    }

    const graphJson = JSON.stringify(row._lateral_graph);
    const graphBytes = Buffer.byteLength(graphJson, 'utf8');
    const graph = row._lateral_graph;
    const graphRecord = graph !== null && typeof graph === 'object' && !Array.isArray(graph)
      ? graph as Record<string, unknown>
      : {};
    const arrayLength = (key: string): number | null => {
      const value = graphRecord[key];
      return Array.isArray(value) ? value.length : null;
    };
    const edgeCount = arrayLength('edges');
    const exceedsByteBudget = graphBytes > MAX_MCP_LATERAL_GRAPH_BYTES;
    const exceedsRowBudget = edgeCount !== null && edgeCount > requestedDataRows;
    if (!exceedsByteBudget && !exceedsRowBudget) {
      return row;
    }

    const reasons = [
      exceedsByteBudget
        ? `serialized size ${graphBytes} exceeded ${MAX_MCP_LATERAL_GRAPH_BYTES} bytes`
        : null,
      exceedsRowBudget
        ? `${edgeCount} nested edges exceeded the requested ${requestedDataRows} data rows`
        : null,
    ].filter((reason): reason is string => reason !== null);

    return {
      ...row,
      _lateral_graph: {
        _mcp_omitted: true,
        original_bytes: graphBytes,
        original_node_count: arrayLength('nodes'),
        original_edge_count: edgeCount,
        requested_data_row_limit: requestedDataRows,
        reason: `The lateral renderer graph was omitted at the MCP boundary: ${reasons.join('; ')}.`,
        guidance:
          'Use the returned lateral edge rows for analysis. Narrow the seed/window before requesting another graph; this response contains no partial graph data.',
      },
    };
  });
}

function rawSqlUnavailableGuidance(): string {
  return (
    'Raw SQL is not available on this deployment. Its query backend is the Iceberg + chDB security ' +
    'lake, which serves nPL only so nano can enforce tenant scoping and byte-scan policy — there is ' +
    'no `logs` ClickHouse table to select from.\n\n' +
    'Use the `search` tool with nPL instead. Most SQL intents map directly:\n' +
    "  SELECT ... WHERE ...            ->  `<field>=<value> | table <fields>`\n" +
    '  GROUP BY / COUNT(*)             ->  `| stats count by <field>`\n' +
    '  ORDER BY x DESC LIMIT n         ->  `| sort -<field> | head n`\n' +
    '  time bucketing                  ->  `| timechart span=1h count`\n' +
    'Call `get_schema` first for the exact field names — this deployment is OCSF, so names are ' +
    'dotted OCSF paths, not UDM column names.'
  );
}

// ---------------------------------------------------------------------------
// Durable-job escalation (NAN-2373)
//
// A lake deployment answers a query that exceeds its scan budget with 200 and
// `{job_id, status}` instead of rows, having moved the work to a durable
// background job. To a caller that only understands the synchronous shape that
// reads as a successful search returning nothing — the worst possible failure
// mode for an investigation, because "no results" is a finding.
//
// So: recognize the handle, wait for the job, and return its rows. If it is
// still running when the MCP's patience runs out, say exactly that and hand
// back the job id — never an empty result set.
// ---------------------------------------------------------------------------

const JOB_POLL_INTERVAL_MS = 750;
const JOB_WAIT_BUDGET_MS = 90_000;

const TERMINAL_FAILURE_STATUSES = new Set(['failed', 'cancelled', 'canceled', 'expired']);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

type EscalationOutcome =
  | { kind: 'response'; response: SearchResponse; note: string }
  | { kind: 'pending'; result: ToolResult };

/**
 * Wait for an escalated durable job and materialize it as a normal search
 * response.
 *
 * A completed job carries its rows one of two ways: an in-memory job embeds the
 * whole `SearchResponse`, while a durable lake job stores the result in the
 * object store and exposes it a page at a time. Only the first page is fetched
 * — the MCP surface is bounded to an interactive page of rows anyway, and the
 * caller already declared its limit.
 */
async function awaitEscalatedJob(
  client: NanosiemClient,
  jobId: string,
  limit: number,
): Promise<EscalationOutcome> {
  const deadline = Date.now() + JOB_WAIT_BUDGET_MS;
  let lastStatus = 'queued';
  let lastProgress: unknown;

  while (Date.now() < deadline) {
    await sleep(JOB_POLL_INTERVAL_MS);

    const status = await client.getSearchJob(jobId);
    if (!status.success || !status.data) {
      return {
        kind: 'pending',
        result: err(
          `The query exceeded this deployment's scan budget and was escalated to durable job ${jobId}, ` +
            `but polling it failed: ${status.error?.message ?? 'unknown error'}. ` +
            'No rows were returned — this is not a zero-match result.',
        ),
      };
    }

    const job = status.data;
    lastStatus = job.status;
    lastProgress = job.progress;

    if (TERMINAL_FAILURE_STATUSES.has(job.status.toLowerCase())) {
      return {
        kind: 'pending',
        result: err(
          `The query was escalated to durable job ${jobId}, which ended as "${job.status}"` +
            (job.error ? `: ${job.error}` : '.') +
            ' No rows were returned — this is not a zero-match result. Narrow the time window and retry.',
        ),
      };
    }

    if (job.status.toLowerCase() !== 'completed' && job.status.toLowerCase() !== 'complete') {
      continue;
    }

    const note =
      `This query exceeded the deployment's interactive scan budget, so nano escalated it to ` +
      `durable job ${jobId} and this tool waited for it. Rows below are the job's result. ` +
      'A narrower time window would answer interactively.';

    if (job.result) {
      return { kind: 'response', response: job.result, note };
    }

    if (job.durable_result) {
      const page = await client.getSearchJobResultPage(jobId, 0);
      if (!page.success || !page.data) {
        return {
          kind: 'pending',
          result: err(
            `Durable job ${jobId} completed with ${job.durable_result.rows} rows, but fetching its ` +
              `first result page failed: ${page.error?.message ?? 'unknown error'}. ` +
              'No rows were returned — this is not a zero-match result.',
          ),
        };
      }

      const rows = (page.data.rows ?? []).slice(0, limit);
      const truncated = page.data.total_rows > rows.length;
      return {
        kind: 'response',
        response: {
          results: rows,
          total_count: page.data.total_rows,
          execution_time_ms: 0,
          fields: [],
        },
        note:
          note +
          (truncated
            ? ` The job produced ${page.data.total_rows} rows across ${page.data.pages} page(s); ` +
              `only the first ${rows.length} are shown here.`
            : ''),
      };
    }

    return {
      kind: 'pending',
      result: err(
        `Durable job ${jobId} reports "completed" but carries neither an inline result nor a ` +
          'durable result reference. No rows were returned — this is not a zero-match result.',
      ),
    };
  }

  return {
    kind: 'pending',
    result: ok({
      escalated_to_durable_job: jobId,
      status: lastStatus,
      progress: lastProgress ?? null,
      results: null,
      explanation:
        `This query exceeded the deployment's interactive scan budget, so nano escalated it to durable ` +
        `job ${jobId}. It was still "${lastStatus}" after ${JOB_WAIT_BUDGET_MS / 1000}s, so no rows are ` +
        'available yet. THIS IS NOT A ZERO-MATCH RESULT. Re-run with a narrower time window or tighter ' +
        'filters to get an interactive answer.',
    }),
  };
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

const TOOL_DEFINITIONS = [
  {
    name: 'search_sql',
    annotations: { readOnlyHint: true },
    description:
      'Advanced search tool. Run a ClickHouse SQL SELECT against the SIEM log store.\n' +
      '\n' +
      'AVAILABILITY: this tool works only on ClickHouse-backed deployments. On a lake-backed one (Iceberg + chDB) raw SQL is REFUSED — nPL is the only query language and there is no `logs` table. Call `get_schema` to see which this is; if `query_backend` is `lake`, use `search` and do not attempt SQL.\n' +
      '\n' +
      'Prefer `search` (nPL) for normal investigations everywhere; use raw SQL only for what nPL cannot express, such as cross-table joins, prevalence-state aggregates, or direct `ext` JSON access.\n' +
      '\n' +
      'On first use in a session, call `get_schema` for the deployment\'s real column inventory — it is UDM on some deployments and OCSF on others, and the two share almost no field names. For canonical query recipes (prevalence lookups, top-N, time bucketing, ASOF identity joins) read the `nano://sql-guide` resource; its recipes assume the UDM/ClickHouse shape.\n' +
      '\n' +
      'PERFORMANCE RULES — follow every time:\n' +
      '  1. Use one `WHERE` clause for the timestamp filter and every other predicate. Do not write an explicit `PREWHERE`; ClickHouse moves eligible filters automatically. The timestamp filter is non-negotiable — without it, ClickHouse cannot prune daily partitions and scans everything:\n' +
      "       WHERE timestamp >= '...' AND timestamp <= '...'\n" +
      "         AND lower(source_type) = lower('windows')\n" +
      "         AND lower(message) iLike '%logon failure%'\n" +
      '  2. Case-insensitive free-text search: use `lower(field) iLike \'%needle%\'`. Text indexes (splitByNonAlpha tokenizer, granularity 1) on `lower(message)`, `lower(command_line)`, `lower(user)`, `lower(process_name)`, `lower(file_path)`, etc. keep this fast. **Do NOT use `hasToken(...)` for variable-length needles — it silently misses substrings (NAN-1026).**\n' +
      '  3. `lower()` consistency — case-sensitive fields like `source_type` need `lower()` on both sides of the comparison.\n' +
      '  4. **`ext` is a ClickHouse JSON column** — access with `ext.field_name` or `ext[\'field_name\']`, NOT JSONExtract. Use JSONExtract only on the legacy `metadata` String column.\n' +
      '  5. Schema columns are real columns — access directly, never through `ext`.\n' +
      `  6. Always include an explicit LIMIT. Default ${DEFAULT_MCP_RESULT_LIMIT}; the interactive MCP surface refuses more than ${MAX_MCP_RESULT_LIMIT} returned rows.\n` +
      '  7. Tables (allowlisted): `logs` (raw events), `signals` (detection matches), `*_prevalence_summary` / `*_prevalence_agg` (prevalence — AggregatingMergeTree, query with uniqMerge for host_count), `identity_observations` (use ASOF JOIN for IP->hostname enrichment).\n' +
      '\n' +
      'TIME RANGE:\n' +
      '  - Both `start_time` and `end_time` are optional; omit both for the last 24h default.\n' +
      '  - Accept relative ("-1h", "-7d", "-30m"), "now", or ISO 8601.\n' +
      '  - You must STILL include `timestamp >= ? AND timestamp <= ?` (or `BETWEEN`) in the single `WHERE` clause — the time params bind the request envelope; the SQL controls partition pruning.\n' +
      '\n' +
      'Only SELECT is accepted; DROP/INSERT/UPDATE/etc. are rejected. Dangerous functions (SLEEP, HOSTNAME, system introspection) are blocked.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        sql: {
          type: 'string',
          description: 'The ClickHouse SELECT query. Use one WHERE clause and include a timestamp filter for partition pruning; do not write an explicit PREWHERE.',
        },
        start_time: {
          type: 'string',
          description: 'Start of the time range envelope. Relative ("-24h"), "now", or ISO 8601. Optional — defaults to 24h before end_time.',
        },
        end_time: {
          type: 'string',
          description: 'End of the time range envelope. Relative, "now", or ISO 8601. Optional — defaults to "now".',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_MCP_RESULT_LIMIT,
          description: `Maximum returned rows. Defaults to ${DEFAULT_MCP_RESULT_LIMIT}; MCP safety maximum is ${MAX_MCP_RESULT_LIMIT}.`,
        },
      },
      required: ['sql'],
    },
  },
  {
    name: 'get_event',
    annotations: { readOnlyHint: true },
    description:
      'Fetch ONE complete event by ID — the drill-down/expand step of an investigation.\n' +
      '\n' +
      'WHY THIS EXISTS: `search` returns a pruned projection (about 25 columns), not the whole event. ' +
      'On an OCSF deployment that is ~25 of ~278 fields, so most of what an event carries — the rest of ' +
      '`actor.*`, `cloud.*`, `file.*`, `http_request.*`, and everything under `unmapped.*` — is simply ' +
      'ABSENT from a search result. If an answer depends on a field you did not see in the row, do not ' +
      'conclude it is empty: fetch the event here first.\n' +
      '\n' +
      'SHAPE: the returned event is NESTED (`event.actor.user.name`), unlike the flat dotted keys ' +
      '(`row["actor.user.name"]`) that `search` returns. Same names, different nesting — walk the path.\n' +
      '\n' +
      'ID: use the row\'s identifier from the search result — `metadata.uid` on OCSF, `id` on UDM. ' +
      'Pass `start_time`/`end_time` around the event\'s timestamp and its log source when you know them: ' +
      'they are pruning hints that turn a wide historical scan into a fast indexed read.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Event ID. On OCSF this is the row\'s `metadata.uid`; on UDM it is `id`.',
        },
        start_time: {
          type: 'string',
          description: 'Optional pruning hint: start of a narrow window around the event. Relative or ISO 8601.',
        },
        end_time: {
          type: 'string',
          description: 'Optional pruning hint: end of that window. Relative or ISO 8601.',
        },
        source_type: {
          type: 'string',
          description: "Optional pruning hint: the event's log source (`metadata.log_source` on OCSF).",
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'get_schema',
    annotations: { readOnlyHint: true },
    description:
      'Return the ACTIVE schema of this deployment, plus how it must be queried. Call this FIRST in any session that touches event data — before writing a query — and use the names it returns rather than any field name you remember.\n' +
      '\n' +
      'Deployments differ in two independent ways, and this tool reports both:\n' +
      '  - `schema`: `udm` (flat columns — `src_ip`, `process_name`, `user`; overflow in `ext`) or `ocsf` (dotted OCSF paths — `actor.user.name`, `src_endpoint.ip`; overflow in `unmapped.*`). On an OCSF deployment the UDM names DO NOT EXIST, and vice versa.\n' +
      '  - `query_backend`: `clickhouse` (nPL and raw SQL) or `lake` (Iceberg + chDB; nPL ONLY — raw SQL is refused and there is no `logs` table).\n' +
      '\n' +
      'Returns:\n' +
      '  - `schema`, `query_backend`, `raw_sql` — what this deployment is.\n' +
      '  - `guidance` — the query model that follows from those, in prose. Read it.\n' +
      '  - `fields` — the active profile\'s field universe with name, type, category. Filtered when `category` is set.\n' +
      '  - `all_categories` — every category and its total field count (always complete, even when filtered).\n' +
      '  - `ext_fields` (UDM only) — observed JSON keys in the `ext` column.\n' +
      '  - `warnings` (optional) — non-fatal discovery problems. If present, treat field names as unverified.\n' +
      '\n' +
      'On an OCSF deployment, also read the `nanosiem://reference/ocsf` resource: OCSF 1.9 classes and their activity enums, the UDM->OCSF name cheat-sheet, and worked nPL examples.\n' +
      '\n' +
      'NOTE on result rows: `search` returns a PRUNED, FLAT projection — about 25 dotted keys, read as `row["actor.user.name"]`. `get_event` returns the COMPLETE event, NESTED, read as `event.actor.user.name`. A field absent from a search row is usually unprojected, not empty.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        category: {
          type: 'string',
          description: 'Optional. Filter UDM fields to a single category (e.g. "Network", "Process", "Auth", "Enrichment"). Omit to return all fields.',
        },
        include_ext: {
          type: 'boolean',
          description: 'Whether to include observed ext field names. Defaults to true.',
        },
      },
      required: [],
    },
  },
  {
    name: 'search',
    annotations: { readOnlyHint: true },
    description:
      'PRIMARY search tool. Execute an nPL (nano Pipe Language) query — Splunk-compatible piped syntax — against the SIEM log data. Use this for normal investigations because it is permission-safe, source-scope aware, and covers filters, tables, stats, and timecharts.\n' +
      '\n' +
      'Use `search_sql` only when nPL cannot express the query, such as a cross-table join, a prevalence-state aggregate, or direct `ext` JSON access — and note that raw SQL is unavailable entirely on lake-backed deployments.\n' +
      '\n' +
      'FIELD NAMES: call `get_schema` first. This deployment is either UDM (`src_ip`, `process_name`, `user`) or OCSF (`src_endpoint.ip`, `actor.process.name`, `actor.user.name`); the two share almost no names, and a query written against the wrong one matches nothing rather than erroring.\n' +
      '\n' +
      'ESCALATION: on a lake deployment a query that exceeds the scan budget is moved to a durable background job. This tool waits for that job and returns its rows, adding an `escalation_note`. If the job is still running when the wait budget expires you get an explicit pending response carrying the job id — NEVER an empty result set. Treat a narrow time window as the first tuning move.\n' +
      '\n' +
      `RESULT BOUNDARY: \`limit\` caps returned rows or aggregate groups, not the matching events used to compute an aggregate. The MCP surface refuses requests above ${MAX_MCP_RESULT_LIMIT} rows and returns an actionable error if an older backend violates the requested limit; it never silently slices aggregate output. For a meaningful top-N, sort before \`head\`/\`limit\`.\n` +
      '\n' +
      'REX QUOTING: If a regex contains JSON-style double quotes, wrap the whole pattern in SINGLE quotes: `| rex field=message \'"KEY":"(?<value>[^\"]+)"\'`. Backslash does not escape a double-quoted nPL delimiter; this spelling also works on older nano backends.\n' +
      '\n' +
      'Examples (UDM deployment):\n' +
      '  - "src_ip=10.0.0.0/8 | stats count by dest_ip, dest_port | sort -count"\n' +
      '  - "process_name=powershell.exe | table timestamp, user, command_line"\n' +
      '  - "source_type=firewall | timechart span=1h count by action"\n' +
      'Same intents on an OCSF deployment:\n' +
      '  - "src_endpoint.ip=10.0.0.0/8 | stats count by dst_endpoint.ip, dst_endpoint.port | sort -count"\n' +
      '  - "actor.process.name=powershell.exe | table time, actor.user.name, actor.process.cmd_line"\n' +
      '  - "metadata.log_source=firewall | timechart span=1h count by activity_name"\n' +
      'Pipe commands: stats, where, sort, head, table, timechart, eval, dedup, rename, rex.\n' +
      'Time arguments accept relative ("-15m", "-1h", "-7d"), "now", or ISO 8601.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: {
          type: 'string',
          description: 'The nPL query to execute. Supports search terms, field filters, and pipe commands.',
        },
        start_time: {
          type: 'string',
          description: 'Start of the search window. Relative (e.g. "-24h", "-7d", "-30m") or ISO 8601 timestamp.',
        },
        end_time: {
          type: 'string',
          description: 'End of the search window. Defaults to "now". Relative or ISO 8601 timestamp.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_MCP_RESULT_LIMIT,
          description: `Maximum returned events or aggregate groups. Defaults to ${DEFAULT_MCP_RESULT_LIMIT}; this does not limit the events aggregated. MCP safety maximum is ${MAX_MCP_RESULT_LIMIT}.`,
        },
        source_type: {
          type: 'string',
          description: 'Filter to a specific log source type (e.g. "windows", "firewall", "dns", "proxy").',
        },
      },
      required: ['query', 'start_time'],
    },
  },
  {
    name: 'explain_query',
    annotations: { readOnlyHint: true },
    description:
      'Show the compiled SQL that an nPL query would generate without executing it. ' +
      'ClickHouse-backed deployments only — a lake-backed deployment compiles nPL inside its query worker and returns no SQL here. ' +
      'Useful for understanding what a piped query translates to, debugging unexpected results, ' +
      'or verifying that timestamp partition pruning and indexed filters are being applied.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: {
          type: 'string',
          description: 'The nPL query to compile to SQL.',
        },
        start_time: {
          type: 'string',
          description: 'Start of the time range. Relative or ISO 8601 timestamp.',
        },
        end_time: {
          type: 'string',
          description: 'End of the time range. Defaults to "now". Relative or ISO 8601 timestamp.',
        },
      },
      required: ['query', 'start_time'],
    },
  },
  {
    name: 'get_field_values',
    annotations: { readOnlyHint: true },
    description:
      'Retrieve a limited, ranked list of the top values for a specific field in the log data. ' +
      'This is a value-discovery tool, not a population count or statistical sample. Counts cover only the returned top values; ' +
      'their sum is not the total number of matching events, and percentages are each value\'s share of the returned top-value counts only. ' +
      'The response reports `matching_event_count: null` deliberately. Use `search` with the same scope and an explicit `| stats count` ' +
      'when the investigation needs the matching population total. ' +
      'Useful for understanding the distribution of a field (e.g. top source IPs, most common process names, ' +
      'frequent user agents) or identifying outliers during threat hunting.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        field: {
          type: 'string',
          description: 'The field name to get top values for (e.g. "src_ip", "process_name", "user", "dest_port").',
        },
        query: {
          type: 'string',
          description: 'Optional nPL query to scope the field values. Defaults to "*" (all events).',
        },
        start_time: {
          type: 'string',
          description: 'Start of the time range. Relative or ISO 8601 timestamp.',
        },
        end_time: {
          type: 'string',
          description: 'End of the time range. Defaults to "now". Relative or ISO 8601 timestamp.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_MCP_RESULT_LIMIT,
          description: `Maximum number of ranked values to return. Defaults to ${DEFAULT_MCP_RESULT_LIMIT}; does not turn the result into a sample or population total.`,
        },
      },
      required: ['field', 'start_time'],
    },
  },
  {
    name: 'list_saved_searches',
    annotations: { readOnlyHint: true },
    description:
      'List all saved searches. Saved searches are reusable nPL or SQL queries that analysts have bookmarked. ' +
      'Returns the name, query, query mode, and visibility of each saved search.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'get_saved_search',
    annotations: { readOnlyHint: true },
    description:
      'Retrieve a specific saved search by its ID. Returns the full saved search details including ' +
      'the query, query mode, time range, and visibility settings.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'The unique identifier of the saved search.',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'save_search',
    description:
      'Save an nPL or SQL query as a reusable saved search. ' +
      'Saved searches can be private, public, or shared with a group. ' +
      'Use this to bookmark useful hunting queries for later reuse.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: {
          type: 'string',
          description: 'A descriptive name for the saved search.',
        },
        query: {
          type: 'string',
          description: 'The nPL or SQL query to save.',
        },
        query_mode: {
          type: 'string',
          description: 'The query language mode: "piped" for nPL or "sql" for raw SQL. Defaults to "piped".',
          enum: ['piped', 'sql'],
        },
        visibility: {
          type: 'string',
          description: 'Who can see this saved search: "private", "public", or "group".',
          enum: ['private', 'public', 'group'],
        },
      },
      required: ['name', 'query'],
    },
  },
  {
    name: 'create_shared_search',
    description:
      'Generate a shareable URL for a search query. The URL can be sent to other analysts ' +
      'so they can open the exact same search in the SIEM web UI with the same query and time range.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: {
          type: 'string',
          description: 'The query to share.',
        },
        query_mode: {
          type: 'string',
          description: 'The query language mode: "piped" or "sql".',
          enum: ['piped', 'sql'],
        },
        time_range_type: {
          type: 'string',
          description: 'The type of time range: "relative" or "absolute".',
        },
        time_range_start: {
          type: 'string',
          description: 'Start of the time range for the shared search.',
        },
        time_range_end: {
          type: 'string',
          description: 'End of the time range for the shared search.',
        },
      },
      required: ['query'],
    },
  },
];

/** Put the safe, source-scoped nPL surface first in MCP tool discovery. */
export const TOOLS = [...TOOL_DEFINITIONS].sort((left, right) => {
  const priority = (name: string) => {
    if (name === 'search') return 0;
    if (name === 'search_sql') return 2;
    return 1;
  };
  return priority(left.name) - priority(right.name);
});

// ---------------------------------------------------------------------------
// Tool handler
// ---------------------------------------------------------------------------

export async function handleSearchTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient,
): Promise<ToolResult> {
  try {
    switch (name) {
      // ---------------------------------------------------------------
      // search
      // ---------------------------------------------------------------
      case 'search': {
        const query = args.query as string;
        const startTime = parseRelativeTime(args.start_time as string);
        const endTime = parseRelativeTime((args.end_time as string) ?? 'now');
        const limit = mcpResultLimit(args.limit, 'search');
        const sourceType = args.source_type as string | undefined;

        const result = await client.search({
          query,
          time_range: { start: startTime, end: endTime },
          limit,
          table_view: true,
          skip_field_stats: true,
          skip_histogram: true,
          source_type: sourceType,
        });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Search failed'}` }],
            isError: true,
          };
        }

        // A lake deployment may answer with a durable job handle rather than
        // rows. Resolve it to rows here so the agent never sees an escalation
        // as an empty result set.
        let searchResponse: SearchResponse | undefined;
        let escalationNote: string | undefined;
        if (isAsyncSearchAck(result.data)) {
          const outcome = await awaitEscalatedJob(client, result.data.job_id, limit);
          if (outcome.kind === 'pending') return outcome.result;
          searchResponse = outcome.response;
          escalationNote = outcome.note;
        } else {
          searchResponse = result.data as SearchResponse | undefined;
        }

        // Command-page renderers may prepend a reserved metadata row (for
        // example `{ _display_type: 'lateral', ... }`) outside data
        // pagination. It must survive in the response, but it is not one of
        // the caller's requested result rows.
        const returnedRows = returnedDataRowCount(searchResponse?.results ?? []);
        if (returnedRows > limit) {
          return resultLimitViolation(returnedRows, limit);
        }

        // Agents consume result rows. The search timeline is a second full-window
        // companion query and can dwarf a bounded aggregate; timechart remains
        // available because its series is returned in `results`, not here.
        const compact: Record<string, unknown> = { ...searchResponse };
        if (Array.isArray(compact.results)) {
          compact.results = compactLateralGraphMetadata(
            compact.results as Record<string, unknown>[],
            limit,
          );
        }
        delete compact.histogram;
        if (escalationNote) compact.escalation_note = escalationNote;
        return {
          content: [{ type: 'text', text: JSON.stringify(compact, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // search_sql
      // ---------------------------------------------------------------
      case 'search_sql': {
        const sql = args.sql as string;
        const endTime = parseRelativeTime((args.end_time as string) ?? 'now');
        const startTime = parseRelativeTime((args.start_time as string) ?? '-24h');
        const limit = mcpResultLimit(args.limit, 'search_sql');

        // Refuse locally when the deployment is already known to be lake-backed.
        // Not an optimization: a round trip that can only come back refused
        // teaches the model nothing about what to do instead, and the guidance
        // below is the actual next step.
        const profile = await getDeploymentProfile(client);
        if (profile.rawSql === 'unavailable') {
          return err(rawSqlUnavailableGuidance());
        }

        const result = await client.searchSql({
          sql,
          time_range: { start: startTime, end: endTime },
          limit,
        });

        if (!result.success) {
          if (isLakeRawSqlRefusal(result.error?.message)) {
            recordRawSqlOutcome('refused-by-lake');
            return err(rawSqlUnavailableGuidance());
          }
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'SQL search failed'}` }],
            isError: true,
          };
        }

        recordRawSqlOutcome('succeeded');

        const returnedRows = result.data?.results?.length ?? 0;
        if (returnedRows > limit) {
          return resultLimitViolation(returnedRows, limit);
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // get_event
      // ---------------------------------------------------------------
      case 'get_event': {
        const id = args.id as string;
        const startTime = args.start_time as string | undefined;
        const endTime = args.end_time as string | undefined;
        const timeRange =
          startTime !== undefined
            ? {
                start: parseRelativeTime(startTime),
                end: parseRelativeTime(endTime ?? 'now'),
              }
            : undefined;

        const result = await client.fetchLog({
          id,
          time_range: timeRange,
          source_type: args.source_type as string | undefined,
        });

        if (!result.success) {
          return err(result.error?.message ?? 'Failed to fetch event');
        }

        if (!result.data?.event) {
          return err(
            `No event found with id "${id}". The ID must be the row's own identifier — ` +
              "`metadata.uid` on an OCSF deployment, `id` on UDM — not a positional index. " +
              'If the event is old, pass start_time/end_time around its timestamp so the lookup ' +
              'searches the right window.',
          );
        }

        return ok({
          event: result.data.event,
          note:
            'This is the complete stored event, in NESTED form: read `event.actor.user.name`, not ' +
            '`event["actor.user.name"]`. Search results use the flat dotted spelling for the same names.',
        });
      }

      // ---------------------------------------------------------------
      // get_schema
      // ---------------------------------------------------------------
      case 'get_schema': {
        const category = args.category as string | undefined;
        const includeExt = (args.include_ext as boolean | undefined) ?? true;

        const profile = await getDeploymentProfile(client);

        if (profile.schema === 'unknown' || profile.fields.length === 0) {
          return err(
            'Failed to load the schema for this deployment: ' +
              (profile.warnings.join(' ') || 'no field universe was returned.') +
              ' Do not guess field names — resolve this first, or discover names from the ' +
              '`fields` block of a `search` result.',
          );
        }

        const filtered = category
          ? profile.fields.filter((f) => f.category.toLowerCase() === category.toLowerCase())
          : profile.fields;

        const categoryCounts = profile.fields.reduce<Record<string, number>>((acc, f) => {
          acc[f.category] = (acc[f.category] ?? 0) + 1;
          return acc;
        }, {});

        const warnings = [...profile.warnings];
        const response: Record<string, unknown> = {
          schema: profile.schema,
          query_backend: profile.backend,
          raw_sql: profile.rawSql,
          guidance: deploymentGuidance(profile),
          fields: filtered,
          field_count: filtered.length,
          total_field_count: profile.fields.length,
          all_categories: Object.entries(categoryCounts)
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count),
        };

        // `ext` is a UDM construct. On OCSF the equivalent overflow is
        // `unmapped.*`, and the /api/fields/ext endpoint does not describe it —
        // asking anyway would return a misleading empty list rather than an
        // honest "different mechanism here".
        if (includeExt && profile.schema === 'udm') {
          const extResult = await client.getExtFields();
          if (extResult.success) {
            response.ext_fields = extResult.data ?? [];
          } else {
            warnings.push(
              `ext_fields unavailable: ${extResult.error?.message ?? 'unknown error'}. The /api/fields/ext endpoint may not exist on this nano version.`,
            );
          }
        } else if (includeExt && profile.schema === 'ocsf') {
          response.ext_fields_note =
            'This deployment is OCSF: there is no `ext` column. Data without a promoted OCSF ' +
            'column lands under `unmapped.*`. Discover what a given source actually carries by ' +
            'running a narrow `search` and reading the `fields` block of the result.';
        }

        if (warnings.length > 0) {
          response.warnings = warnings;
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // explain_query
      // ---------------------------------------------------------------
      case 'explain_query': {
        const query = args.query as string;
        const startTime = parseRelativeTime(args.start_time as string);
        const endTime = parseRelativeTime((args.end_time as string) ?? 'now');

        const result = await client.explainQuery(query, { start: startTime, end: endTime });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Explain failed'}` }],
            isError: true,
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // get_field_values
      // ---------------------------------------------------------------
      case 'get_field_values': {
        const field = args.field as string;
        const query = (args.query as string) ?? '*';
        const startTime = parseRelativeTime(args.start_time as string);
        const endTime = parseRelativeTime((args.end_time as string) ?? 'now');
        const limit = mcpResultLimit(args.limit, 'get_field_values');

        const result = await client.getFieldValues({
          field,
          query,
          start: startTime,
          end: endTime,
          limit,
        });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Field values request failed'}` }],
            isError: true,
          };
        }

        const values = result.data?.values ?? [];
        if (values.length > limit) {
          return resultLimitViolation(values.length, limit);
        }

        // The backend's legacy `total_count` and `percentage` fields are both
        // based on the limited top-value rows. Rename and recompute them at the
        // MCP boundary so an agent cannot mistake either for dataset coverage.
        const returnedValueOccurrenceCount = values.reduce((sum, value) => sum + value.count, 0);
        const formatted = {
          field: result.data?.field ?? field,
          coverage: {
            kind: 'top_values_only',
            requested_limit: limit,
            returned_value_count: values.length,
            returned_value_occurrence_count: returnedValueOccurrenceCount,
            may_have_more_values: result.data?.may_have_more_values ?? values.length >= limit,
            matching_event_count: null,
            matching_event_count_available: false,
          },
          values: values.map((value) => ({
            value: value.value,
            count: value.count,
            percentage_of_returned_value_occurrences: returnedValueOccurrenceCount > 0
              ? (value.count / returnedValueOccurrenceCount) * 100
              : 0,
          })),
          guidance:
            'These are only the returned top values. Their counts are not a sample or the total matching population. ' +
            'Run the same scoped query with an explicit `| stats count` when you need a matching-event total.',
        };

        return {
          content: [{ type: 'text', text: JSON.stringify(formatted, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // list_saved_searches
      // ---------------------------------------------------------------
      case 'list_saved_searches': {
        const result = await client.listSavedSearches();

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Failed to list saved searches'}` }],
            isError: true,
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // get_saved_search
      // ---------------------------------------------------------------
      case 'get_saved_search': {
        const id = args.id as string;

        const result = await client.getSavedSearch(id);

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Failed to get saved search'}` }],
            isError: true,
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // save_search
      // ---------------------------------------------------------------
      case 'save_search': {
        const name = args.name as string;
        const query = args.query as string;
        const queryMode = (args.query_mode as 'piped' | 'sql') ?? 'piped';
        const visibility = args.visibility as 'private' | 'public' | 'group' | undefined;

        const result = await client.createSavedSearch({
          name,
          query,
          query_mode: queryMode,
          visibility,
        });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Failed to save search'}` }],
            isError: true,
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // create_shared_search
      // ---------------------------------------------------------------
      case 'create_shared_search': {
        const query = args.query as string;
        const queryMode = (args.query_mode as string) ?? 'piped';
        const timeRangeType = (args.time_range_type as string) ?? 'relative';
        const timeRangeStart = args.time_range_start as string | undefined;
        const timeRangeEnd = args.time_range_end as string | undefined;

        const result = await client.createSharedSearch({
          query,
          query_mode: queryMode,
          time_range_type: timeRangeType,
          time_range_start: timeRangeStart,
          time_range_end: timeRangeEnd,
        });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Failed to create shared search'}` }],
            isError: true,
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // Unknown tool
      // ---------------------------------------------------------------
      default:
        return {
          content: [{ type: 'text', text: `Error: Unknown search tool "${name}"` }],
          isError: true,
        };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: 'text', text: `Error: ${message}` }],
      isError: true,
    };
  }
}

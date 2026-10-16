import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

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

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

const TOOL_DEFINITIONS = [
  {
    name: 'search_sql',
    annotations: { readOnlyHint: true },
    description:
      'Advanced SQL search. Availability depends on deployment; hosted tenants reject raw SQL. Prefer search with canonical OCSF 1.9 paths. ' +
      'Read get_schema first. Supply an explicit time range and LIMIT, at most 1000 rows. Do not assume legacy storage tables or database functions exist.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        sql: {
          type: 'string',
          description: 'A read-only SELECT supported by this deployment; include explicit time bounds and LIMIT.',
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
    name: 'get_schema',
    annotations: { readOnlyHint: true },
    description:
      'Return the active lake schema, version, canonical field paths and categories. Call before constructing queries. ' +
      'Legacy udm_fields keys remain aliases of fields for existing clients.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        category: {
          type: 'string',
          description: 'Optional. Filter schema fields to a single category (e.g. "Network", "Process", "Auth", "Enrichment"). Omit to return all fields.',
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
      'PRIMARY search tool. Execute an nPL (nano Pipe Language) query using piped syntax against the SIEM log data. Use this for normal investigations because it is permission-safe, source-scope aware, and covers filters, tables, stats, and timecharts.\n' +
      '\n' +
      'Use `search_sql` only when nPL cannot express the query and this deployment supports SQL. Hosted tenants use nPL.\n' +
      '\n' +
      `RESULT BOUNDARY: \`limit\` caps returned rows or aggregate groups, not the matching events used to compute an aggregate. The MCP surface refuses requests above ${MAX_MCP_RESULT_LIMIT} rows and returns an actionable error if an older backend violates the requested limit; it never silently slices aggregate output. For a meaningful top-N, sort before \`head\`/\`limit\`.\n` +
      '\n' +
      'REX QUOTING: If a regex contains JSON-style double quotes, wrap the whole pattern in SINGLE quotes: `| rex field=message \'"KEY":"(?<value>[^\"]+)"\'`. Backslash does not escape a double-quoted nPL delimiter; this spelling also works on older nano backends.\n' +
      '\n' +
      'Examples:\n' +
      '  - "src_endpoint.ip=10.0.0.0/8 | stats count by dst_endpoint.ip, dst_endpoint.port | sort -count"\n' +
      '  - "process.file.name=powershell.exe | table time, actor.user.name, process.cmd_line"\n' +
      '  - "metadata.log_source=firewall | timechart span=1h count by action"\n' +
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
          description: 'Deprecated: use metadata.log_source in the query before aggregation. The lake API does not accept this separate filter.',
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
          description: 'The field name to get top values for (e.g. "src_endpoint.ip", "process.file.name", "actor.user.name", "dst_endpoint.port").',
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

        // Command-page renderers may prepend a reserved metadata row (for
        // example `{ _display_type: 'lateral', ... }`) outside data
        // pagination. It must survive in the response, but it is not one of
        // the caller's requested result rows.
        const returnedRows = returnedDataRowCount(result.data?.results ?? []);
        if (returnedRows > limit) {
          return resultLimitViolation(returnedRows, limit);
        }

        // Agents consume result rows. The search timeline is a second full-window
        // companion query and can dwarf a bounded aggregate; timechart remains
        // available because its series is returned in `results`, not here.
        const compact = { ...result.data };
        if (compact.results) {
          compact.results = compactLateralGraphMetadata(compact.results, limit);
        }
        delete compact.histogram;
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

        const result = await client.searchSql({
          sql,
          time_range: { start: startTime, end: endTime },
          limit,
        });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'SQL search failed'}` }],
            isError: true,
          };
        }

        const returnedRows = result.data?.results?.length ?? 0;
        if (returnedRows > limit) {
          return resultLimitViolation(returnedRows, limit);
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // get_schema
      // ---------------------------------------------------------------
      case 'get_schema': {
        const category = args.category as string | undefined;
        const includeExt = (args.include_ext as boolean | undefined) ?? true;

        const [udmResult, extResult] = await Promise.all([
          client.getUdmFields(),
          includeExt ? client.getExtFields() : Promise.resolve(null),
        ]);

        if (!udmResult.success) {
          return {
            content: [{ type: 'text', text: `Error: ${udmResult.error?.message ?? 'Failed to load schema'}` }],
            isError: true,
          };
        }

        const allFields = udmResult.data?.fields ?? [];
        const filtered = category
          ? allFields.filter((f) => f.category.toLowerCase() === category.toLowerCase())
          : allFields;

        const categoryCounts = allFields.reduce<Record<string, number>>((acc, f) => {
          acc[f.category] = (acc[f.category] ?? 0) + 1;
          return acc;
        }, {});

        const warnings: string[] = [];
        const response: Record<string, unknown> = {
          schema: udmResult.data?.schema,
          schema_version: udmResult.data?.schema_version,
          strict_canonical_fields: udmResult.data?.strict_canonical_fields,
          fields: filtered,
          udm_fields: filtered,
          udm_field_count: filtered.length,
          all_categories: Object.entries(categoryCounts)
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count),
        };

        if (includeExt && extResult) {
          if (extResult.success) {
            response.ext_fields = extResult.data ?? [];
          } else {
            warnings.push(
              `ext_fields unavailable: ${extResult.error?.message ?? 'unknown error'}. The /api/fields/ext endpoint may not exist on this nano version.`,
            );
          }
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

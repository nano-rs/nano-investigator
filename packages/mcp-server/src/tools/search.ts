import type { NanosiemClient } from '@nano-investigator/core';
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

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

export const TOOLS = [
  {
    name: 'search_sql',
    description:
      'PRIMARY search tool. Run a ClickHouse SQL SELECT against the SIEM log store.\n' +
      '\n' +
      'On first use in a session, call `get_schema` to load the UDM column inventory. For canonical query recipes (prevalence lookups, top-N, time bucketing, ASOF identity joins, etc.) read the `nano://sql-guide` resource.\n' +
      '\n' +
      'PERFORMANCE RULES — follow every time:\n' +
      '  1. PREWHERE holds the timestamp filter plus indexed equality predicates (src_ip, dest_ip, user, source_type, event_type, file_hash, domain). WHERE holds free-text, regex, and complex booleans. The timestamp filter is non-negotiable — without it, ClickHouse cannot prune daily partitions and scans everything:\n' +
      "       PREWHERE timestamp >= '...' AND timestamp <= '...'\n" +
      "         AND lower(source_type) = lower(\'windows\')\n" +
      "       WHERE lower(message) iLike \'%logon failure%\'\n" +
      '  2. Case-insensitive free-text search: use `lower(field) iLike \'%needle%\'`. Text indexes (splitByNonAlpha tokenizer, granularity 1) on `lower(message)`, `lower(command_line)`, `lower(user)`, `lower(process_name)`, `lower(file_path)`, etc. keep this fast. **Do NOT use `hasToken(...)` for variable-length needles — it silently misses substrings (NAN-1026).**\n' +
      '  3. `lower()` consistency — case-sensitive fields like `source_type` need `lower()` on both sides of the comparison.\n' +
      '  4. **`ext` is a ClickHouse JSON column** — access with `ext.field_name` or `ext[\'field_name\']`, NOT JSONExtract. Use JSONExtract only on the legacy `metadata` String column.\n' +
      '  5. UDM columns are real columns (src_ip, process_name, user, file_hash, etc.) — access directly, never through `ext`.\n' +
      '  6. Always include an explicit LIMIT. Default 100 unless the user asks otherwise. Backend caps at 100k.\n' +
      '  7. Tables (allowlisted): `logs` (raw events), `signals` (detection matches), `*_prevalence_summary` / `*_prevalence_agg` (prevalence — AggregatingMergeTree, query with uniqMerge for host_count), `identity_observations` (use ASOF JOIN for IP→hostname enrichment).\n' +
      '\n' +
      'TIME RANGE:\n' +
      '  - Both `start_time` and `end_time` are optional; omit both for the last 24h default.\n' +
      '  - Accept relative ("-1h", "-7d", "-30m"), "now", or ISO 8601.\n' +
      '  - You must STILL include `timestamp >= ? AND timestamp <= ?` (or `BETWEEN`) in PREWHERE — the time params bind the request envelope; the SQL controls partition pruning.\n' +
      '\n' +
      'EXAMPLE:\n' +
      '  SELECT timestamp, src_ip, user, message\n' +
      '  FROM logs\n' +
      "  PREWHERE timestamp BETWEEN \'2026-05-25T00:00:00Z\' AND \'2026-05-26T00:00:00Z\'\n" +
      "    AND lower(source_type) = lower(\'windows\')\n" +
      "  WHERE lower(message) iLike \'%logon failure%\'\n" +
      '  ORDER BY timestamp DESC\n' +
      '  LIMIT 100\n' +
      '\n' +
      'Only SELECT is accepted; DROP/INSERT/UPDATE/etc. are rejected. Dangerous functions (SLEEP, HOSTNAME, system introspection) are blocked.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        sql: {
          type: 'string',
          description: 'The ClickHouse SELECT query. Must include a timestamp filter in PREWHERE for partition pruning.',
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
          type: 'number',
          description: 'Maximum result rows (backend cap is 100k).',
        },
      },
      required: ['sql'],
    },
  },
  {
    name: 'get_schema',
    description:
      'Return the UDM (Unified Data Model) schema for the log store. Call this before writing SQL the first time in a session so you know which columns exist and avoid hallucinating field names.\n' +
      '\n' +
      'Returns:\n' +
      '  - `udm_fields`: explicit columns with name, column_name, data_type, category, description. Several hundred fields grouped by category (Auth, Network, Process, File, Enrichment, Prevalence, etc.). When `category` is set, this is filtered; the inventory below stays complete.\n' +
      '  - `all_categories`: every UDM category and its total field count (always full, even when `category` filter is set — gives you a map of what else exists).\n' +
      '  - `ext_fields`: observed JSON keys in the `ext` column for per-source structured data.\n' +
      '  - `warnings` (optional): non-fatal issues encountered while loading the schema (e.g. ext fetch failed).\n' +
      '\n' +
      'When writing SQL: prefer UDM columns directly. For non-UDM data, the `ext` column is a ClickHouse JSON type — access with `ext.field_name` or `ext[\'field_name\']`, NOT JSONExtract.',
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
    description:
      'Execute an nPL (nano Pipe Language) query — Splunk-compatible piped syntax — against the SIEM log data.\n' +
      '\n' +
      'PREFER `search_sql` for most queries. Use nPL when:\n' +
      '  - The user explicitly asks for piped / SPL-style syntax\n' +
      '  - You are translating an existing Splunk SPL query the user pasted in\n' +
      '  - You want a quick stats/timechart aggregation without writing the SQL\n' +
      '\n' +
      'Examples:\n' +
      '  - "src_ip=10.0.0.0/8 | stats count by dest_ip, dest_port | sort -count"\n' +
      '  - "process_name=powershell.exe | table timestamp, user, command_line"\n' +
      '  - "source_type=firewall | timechart span=1h count by action"\n' +
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
          type: 'number',
          description: 'Maximum number of results to return. Defaults to 100.',
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
    description:
      'Show the compiled SQL that an nPL query would generate without executing it. ' +
      'Useful for understanding what a piped query translates to, debugging unexpected results, ' +
      'or verifying that the right ClickHouse optimizations (PREWHERE, hasToken, bloom filters) are being applied.',
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
    description:
      'Retrieve the top values for a specific field in the log data. ' +
      'Returns value, count, and percentage for each top value. ' +
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
          type: 'number',
          description: 'Maximum number of top values to return.',
        },
      },
      required: ['field', 'start_time'],
    },
  },
  {
    name: 'list_saved_searches',
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
        const limit = (args.limit as number) ?? 100;
        const sourceType = args.source_type as string | undefined;

        const result = await client.search({
          query,
          time_range: { start: startTime, end: endTime },
          limit,
          table_view: true,
          skip_field_stats: true,
          source_type: sourceType,
        });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error?.message ?? 'Search failed'}` }],
            isError: true,
          };
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // ---------------------------------------------------------------
      // search_sql
      // ---------------------------------------------------------------
      case 'search_sql': {
        const sql = args.sql as string;
        const endTime = parseRelativeTime((args.end_time as string) ?? 'now');
        const startTime = parseRelativeTime((args.start_time as string) ?? '-24h');
        const limit = args.limit as number | undefined;

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
            content: [{ type: 'text', text: `Error: ${udmResult.error?.message ?? 'Failed to load UDM schema'}` }],
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
        const limit = args.limit as number | undefined;

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

        return {
          content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }],
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

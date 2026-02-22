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
    name: 'search',
    description:
      'Execute an nPL (nano Pipe Language) query against the SIEM log data. ' +
      'This is the primary investigation tool for hunting through security events. ' +
      'nPL uses a piped syntax: a search term followed by optional pipe commands. ' +
      'Examples:\n' +
      '  - Simple keyword: "authentication failure"\n' +
      '  - Field match: "src_ip=192.168.1.50"\n' +
      '  - With aggregation: "src_ip=10.0.0.0/8 | stats count by dest_ip, dest_port | sort -count"\n' +
      '  - Regex: "user=/admin.*/i | where auth_result=failure"\n' +
      '  - Time chart: "source_type=firewall | timechart span=1h count by action"\n' +
      '  - Table output: "process_name=powershell.exe | table timestamp, user, command_line, src_host"\n' +
      'Pipe commands: stats, where, sort, head, table, timechart, eval, dedup, rename, rex.\n' +
      'Time arguments accept relative formats: "-15m", "-1h", "-7d", "-2w", or "now", or ISO 8601 timestamps.\n' +
      'Use source_type to scope to a specific log source (e.g. "windows", "firewall", "dns").',
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
    name: 'search_sql',
    description:
      'Execute a raw SQL query directly against the ClickHouse log store. ' +
      'Use this when you need precise control over the query that nPL cannot express, ' +
      'such as complex joins or ClickHouse-specific functions. ' +
      'The query must be a SELECT statement. Dangerous functions are blocked. ' +
      'Always include timestamp filters for partition pruning.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        sql: {
          type: 'string',
          description: 'The raw SQL SELECT query to execute against ClickHouse.',
        },
        start_time: {
          type: 'string',
          description: 'Start of the time range. Relative or ISO 8601 timestamp.',
        },
        end_time: {
          type: 'string',
          description: 'End of the time range. Relative or ISO 8601 timestamp.',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of results to return.',
        },
      },
      required: ['sql', 'start_time', 'end_time'],
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
        const startTime = parseRelativeTime(args.start_time as string);
        const endTime = parseRelativeTime(args.end_time as string);
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

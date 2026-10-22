/** One tool contract for external MCP and nano-desktop pivt. */
import type { NanosiemClient, AgentToolName } from '@nano-rs/investigator-core';
import { ok, type ToolResult } from './utils.js';
const windowProperties = {
  start: { type: 'string', description: 'Inclusive RFC3339 instant with offset, or YYYY-MM-DD local midnight. Supply both bounds or neither.' },
  end: { type: 'string', description: 'Exclusive RFC3339 instant with offset, or YYYY-MM-DD local midnight. Dates are literal; a named day ends at the next midnight.' },
  time_zone: { type: 'string', description: 'Caller IANA time zone (default UTC). Use the analyst’s zone for named dates.' },
  widen_reason: { type: 'string', description: 'Required above 7 days. State the analyst request or case first-seen reason. Never silently widen on empty/thin results; offer 24h → 7d → 30d as separate visible steps.' },
  case_context: { type: 'object', properties: { case_id: { type: 'string' }, alert_time: { type: 'string' } }, required: ['case_id', 'alert_time'], additionalProperties: false },
};
const discipline = ' Default last 24h, or alert ±1h with case_context. Explicit dates are literal local midnight-to-midnight. Every result echoes absolute bounds and caller time zone; include that window in your answer. Empty/thin results: offer the next window (24h → 7d → 30d), never automatically retry or widen. More than 7d needs widen_reason, visible in the result.';
function tool(name: AgentToolName, description: string, properties: Record<string, unknown>, required: string[]) {
  return { name, description: description + discipline, annotations: { readOnlyHint: true }, inputSchema: { type: 'object' as const, properties: { ...properties, ...windowProperties }, required, additionalProperties: false } };
}
export const TOOLS = [
  tool('lake_sql', 'Query sealed hours in nano Security Lake through the tenant-fenced gateway. SQL must be a single SELECT from one namespace.table with WHERE {window}, without its own time predicate. Discover source/schema first; fan out one source per call and merge client-side. Use =/OR instead of IN; quote actor."user".name. Prefer rollups for counts/timecharts (restricted keys cannot read mixed-source partials). Recent unsealed hours stay on search. No UNNEST or CIDR/inet functions. Provider errors/timeouts may still be charged: do not retry automatically.', { sql: { type: 'string', maxLength: 10000 } }, ['sql']),
  tool('prevalence', 'Look up rarity for up to 100 artifact values using cell partials and the tenant Settings threshold, over the exact requested window. At most 30 days; older readers without exact-bound support are refused.', { values: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 100 } }, ['values']),
  tool('risk_scores', 'Read hourly decayed seven-day risk scores from the existing cell-backed ledger API, including its clears. Return samples inside the requested window; prior evidence can contribute to a score. Supports at most seven days of samples and the existing API’s 14-day anchor history; unsupported/clamped bounds are refused.', { entity: { type: 'string' }, entity_type: { type: 'string' } }, ['entity', 'entity_type']),
  tool('resolve_identity', 'Resolve an IP to its point-in-time identity observation via the existing as-of API. Pass the event timestamp when known; otherwise the exact window end is used. Returns observed_at and reference_time. Directory user/account attributes are current sync data, separately from the historical observation.', { ip: { type: 'string' }, timestamp: { type: 'string', description: 'Event time (absolute RFC3339 with offset). Never substitute now for an explicit time.' } }, ['ip']),
  tool('lookup', 'Read a tenant lookup table by key, or its current IOC snapshot by indicator. Agent joins returned values to query results or inlines them in SQL. The echoed window is analysis context; snapshots are current with retrieval time, not historical versions. Supply table_name/key_field/values, or ioc, exclusively.', { table_name: { type: 'string' }, key_field: { type: 'string' }, values: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 100 }, output_fields: { type: 'array', items: { type: 'string' } }, case_insensitive: { type: 'boolean' }, ioc: { type: 'string' } }, []),
];
export async function handleAgentLaneTool(name: AgentToolName, args: Record<string, unknown>, client: NanosiemClient): Promise<ToolResult> {
  const result = await client.agentTool(name, args);
  return { ...ok(result.data), ...(!result.success ? { isError: true } : {}) };
}

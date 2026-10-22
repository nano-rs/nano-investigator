import type { ApiResponse } from './client.js';
import { requireValue, resolveAgentWindow, timestamp, type AgentWindow } from './agent-window.js';

export type AgentToolName = 'lake_sql' | 'prevalence' | 'risk_scores' | 'resolve_identity' | 'lookup';
export type AgentToolResponse = { window: AgentWindow | null; data?: unknown; error?: unknown; data_semantics?: string; retrieved_at?: string };
export type AgentRequest = (method: string, path: string, body?: unknown, opts?: {
  query?: Record<string, string | number | boolean | undefined>;
  originOnly?: boolean; agent?: string; timeoutMs?: number;
}) => Promise<ApiResponse<unknown>>;
const COMMON = ['start', 'end', 'time_zone', 'widen_reason', 'case_context'];
const FIELDS: Record<AgentToolName, string[]> = {
  lake_sql: ['sql'], prevalence: ['values'], risk_scores: ['entity', 'entity_type'],
  resolve_identity: ['ip', 'timestamp'], lookup: ['table_name', 'key_field', 'values', 'output_fields', 'case_insensitive', 'ioc'],
};
function text(value: unknown, name: string): string {
  requireValue(typeof value === 'string' && value.trim().length > 0 && value.length <= 2048, `invalid_${name}`);
  return value;
}
function strings(value: unknown, name: string, max = 100): string[] {
  requireValue(Array.isArray(value) && value.length > 0 && value.length <= max, `invalid_${name}`);
  return value.map(v => text(v, name));
}
function object(value: unknown): Record<string, unknown> {
  requireValue(value != null && typeof value === 'object' && !Array.isArray(value), 'invalid_api_response');
  return value as Record<string, unknown>;
}
function available(data: unknown): Record<string, unknown> {
  const result = object(data);
  if (result.availability) requireValue(object(result.availability).available === true, 'cell_feature_unavailable');
  return result;
}
/** No retries, alternate endpoints, cell scan fallback, or automatic widening. */
export async function executeAgentTool(request: AgentRequest, name: AgentToolName, args: Record<string, unknown>, agent: string): Promise<ApiResponse<AgentToolResponse>> {
  let window: AgentWindow | null = null;
  try {
    window = resolveAgentWindow(args);
    requireValue(Object.hasOwn(FIELDS, name), 'unknown_agent_tool');
    requireValue(Object.keys(args).every(k => [...COMMON, ...FIELDS[name]].includes(k)), 'unsupported_tool_argument');
    const start = Date.parse(window.start), end = Date.parse(window.end);
    let result: ApiResponse<unknown>;
    let semantics = 'bounded_events';
    if (name === 'lake_sql') {
      requireValue(typeof args.sql === 'string' && Buffer.byteLength(args.sql) <= 10000 && args.sql.includes('{window}'), 'window_placeholder_required');
      // Resolve the current key's tenant each time. No model-supplied catalog,
      // tenant, endpoint or credential; the Worker repeats authoritative auth.
      const auth = await request('GET', '/api/auth/validate');
      requireValue(auth.success, auth.error?.code ?? 'agent_auth_failed');
      const identity = object(object(auth.data).agent_lane);
      const tenant = text(identity.tenant_id, 'tenant');
      requireValue(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(tenant) && tenant !== '00000000-0000-0000-0000-000000000000', 'invalid_tenant');
      result = await request('POST', `/v1/tenants/${tenant}/lake/sql`, { sql: args.sql, start: window.start, end: window.end, time_zone: window.time_zone, ...(window.widen_reason ? { widen_reason: window.widen_reason } : {}), ...(args.case_context ? { case_context: args.case_context } : {}) }, { originOnly: true, agent, timeoutMs: 130000 });
      if (result.success) {
        const remote = object(object(result.data).window);
        requireValue(remote.start === window.start && remote.end === window.end && remote.time_zone === window.time_zone && remote.widen_reason === window.widen_reason, 'gateway_window_mismatch');
      }
    } else if (name === 'prevalence') {
      result = await request('POST', '/api/prevalence/bulk', { artifacts: strings(args.values, 'values'), start: window.start, end: window.end });
      if (result.success) {
        const data = available(result.data);
        const bounds = object(data.window);
        requireValue(bounds.start === window.start && bounds.end === window.end, 'prevalence_window_mismatch');
      }
      semantics = 'exact_window_prevalence_with_settings_threshold';
    } else if (name === 'risk_scores') {
      const entity = encodeURIComponent(text(args.entity, 'entity'));
      const type = encodeURIComponent(text(args.entity_type, 'entity_type'));
      // The existing ledger API supplies seven days of score samples at an
      // anchor. Refuse unsupported coverage instead of clipping a literal date.
      requireValue(end - start <= 7 * 86400000, 'risk_timeline_supports_at_most_7_days');
      result = await request('GET', `/api/entities/${type}/${entity}/risk-timeline`, undefined, { query: { at: window.end } });
      if (result.success) {
        const data = available(result.data);
        requireValue(Date.parse(text(data.anchor, 'risk_anchor')) === end, 'risk_anchor_was_clamped');
        requireValue(Array.isArray(data.points) && data.step_seconds === 3600 && data.window_hours === 168, 'invalid_risk_timeline');
        const points = data.points.map(object);
        requireValue(points.every(p => typeof p.t === 'string' && Number.isFinite(Date.parse(p.t)) && typeof p.score === 'number'), 'invalid_risk_timeline');
        // Do not expose unbounded markers/contribution summaries to the model.
        result = { success: true, data: { entity: args.entity, entity_type: args.entity_type, points: points.filter(p => Date.parse(p.t as string) >= start && Date.parse(p.t as string) < end), step_seconds: data.step_seconds, truncated: data.truncated, ...(data.watch_weight !== undefined ? { watch_weight: data.watch_weight } : {}) } };
      }
      semantics = 'hourly_decayed_7d_risk_scores_in_window_including_prior_evidence_and_clears';
    } else if (name === 'resolve_identity') {
      const reference = args.timestamp === undefined ? end : timestamp(args.timestamp, window.time_zone);
      const referenceTime = new Date(reference).toISOString();
      result = await request('GET', '/api/identity/resolve', undefined, { query: { ip: text(args.ip, 'ip'), timestamp: referenceTime } });
      if (result.success) {
        const data = available(result.data);
        const match = data.match == null ? undefined : object(data.match);
        // Hosted uses match.last_seen; the open endpoint uses observed_at.
        const observed = match?.last_seen ?? data.observed_at ?? null;
        requireValue(observed === null || (typeof observed === 'string' && Number.isFinite(Date.parse(observed)) && Date.parse(observed) <= reference), 'invalid_identity_observation_time');
        requireValue(!match || observed !== null, 'missing_identity_observation_time');
        result = { success: true, data: { ...data, reference_time: referenceTime, observed_at: observed } };
      }
      semantics = 'point_in_time_identity_observation_directory_attributes_current';
    } else {
      if (args.ioc !== undefined) {
        requireValue(args.table_name === undefined && args.key_field === undefined && args.values === undefined && args.output_fields === undefined && args.case_insensitive === undefined, 'lookup_modes_are_exclusive');
        result = await request('POST', '/api/threat-intel/indicator-lookup', { artifact: text(args.ioc, 'ioc') });
      } else {
        const values = strings(args.values, 'values');
        requireValue(args.case_insensitive === undefined || typeof args.case_insensitive === 'boolean', 'invalid_case_insensitive');
        result = await request('POST', '/api/lookup-tables/query', { table_name: text(args.table_name, 'table_name'), key_field: text(args.key_field, 'key_field'), key_values: values, ...(args.output_fields !== undefined ? { output_fields: strings(args.output_fields, 'output_fields') } : {}), ...(args.case_insensitive !== undefined ? { case_insensitive: args.case_insensitive } : {}) });
      }
      semantics = 'current_lookup_snapshot_not_historical';
    }
    if (!result.success) return { success: false, data: { window, error: result.error }, error: result.error };
    return { success: true, data: { window, data: result.data, data_semantics: semantics, retrieved_at: new Date().toISOString() } };
  } catch (e) {
    const error = { code: 'AGENT_TOOL_REFUSED', message: e instanceof Error ? e.message : 'agent_tool_failed' };
    return { success: false, data: { window, error }, error };
  }
}

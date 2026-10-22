/** Absolute half-open analysis windows; kept aligned with the gateway contract. */
export interface AgentWindow {
  start: string; end: string; time_zone: string; display_start: string; display_end: string;
  origin: string; widen_reason: string | null; case_id: string | null; widened: boolean;
}
export function requireValue(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error(message);
}
const DAY = 86_400_000;
export function timestamp(value: unknown, zone: string): number {
  requireValue(typeof value === 'string', 'invalid_window_timestamp');
  const date = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (date) {
    const midnight = Date.UTC(+date[1], +date[2] - 1, +date[3]);
    requireValue(new Date(midnight).toISOString().slice(0, 10) === value, 'invalid_window_timestamp');
    const format = new Intl.DateTimeFormat('en-CA', { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
    let result = midnight;
    for (let i = 0; i < 4; i++) {
      const p = Object.fromEntries(format.formatToParts(new Date(result)).map(p => [p.type, p.value]));
      const local = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
      if (local === midnight) return result;
      result += midnight - local;
    }
    throw new Error('nonexistent_local_midnight');
  }
  const instant = /^\d{4}-\d{2}-\d{2}T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  requireValue(instant && +instant[1] < 24 && +instant[2] < 60 && +instant[3] < 60 && +(instant[4] ?? 0) < 24 && +(instant[5] ?? 0) < 60, 'window_requires_absolute_time');
  const result = Date.parse(value);
  const day = Date.parse(`${value.slice(0, 10)}T00:00:00Z`);
  requireValue(Number.isFinite(result) && Number.isFinite(day) && new Date(day).toISOString().slice(0, 10) === value.slice(0, 10), 'invalid_window_timestamp');
  return result;
}
export function resolveAgentWindow(body: Record<string, unknown>, now = Date.now()): AgentWindow {
  const zone = body.time_zone ?? 'UTC';
  requireValue(typeof zone === 'string' && zone.length <= 100, 'invalid_time_zone');
  try { new Intl.DateTimeFormat('en-US', { timeZone: zone }).format(); } catch { throw new Error('invalid_time_zone'); }
  requireValue((body.start == null) === (body.end == null), 'window_requires_both_bounds');
  const reason = body.widen_reason ?? null;
  requireValue(reason === null || (typeof reason === 'string' && reason.trim().length > 0 && reason.length <= 1000), 'invalid_widen_reason');
  const context = body.case_context as Record<string, unknown> | undefined;
  if (context != null) {
    requireValue(typeof context === 'object' && !Array.isArray(context) && Object.keys(context).every(k => ['case_id', 'alert_time'].includes(k)) && typeof context.case_id === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(context.case_id), 'invalid_case_context');
    timestamp(context.alert_time, zone);
  }
  let start: number, end: number, origin: string;
  if (body.start != null) {
    start = timestamp(body.start, zone); end = timestamp(body.end, zone); origin = 'explicit';
  } else if (context != null) {
    const alert = timestamp(context.alert_time, zone);
    start = alert - 3_600_000; end = alert + 3_600_000; origin = 'caller_case_alert';
  } else { end = now; start = end - DAY; origin = 'default_24h'; }
  requireValue(Number.isFinite(start) && Number.isFinite(end) && start < end, 'invalid_window_bounds');
  requireValue(end - start <= 7 * DAY || reason !== null, 'widen_reason_required');
  const display = new Intl.DateTimeFormat('en-US', { timeZone: zone, dateStyle: 'medium', timeStyle: 'long' });
  return { start: new Date(start).toISOString(), end: new Date(end).toISOString(), time_zone: zone,
    display_start: display.format(new Date(start)), display_end: display.format(new Date(end)), origin, widen_reason: reason,
    case_id: context?.case_id as string ?? null, widened: end - start > 7 * DAY };
}

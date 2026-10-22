import { afterEach, describe, expect, it, vi } from 'vitest';
import { NanosiemClient } from './client.js';
import { resolveAgentWindow } from './agent-window.js';
const A = '00000000-0000-4000-8000-00000000000a';
const B = '00000000-0000-4000-8000-00000000000b';
const now = '2026-10-22T20:00:00.000Z';
const dates = { start: '2026-10-16', end: '2026-10-17', time_zone: 'America/New_York' };
const client = () => new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/tenant-a', apiKey: 'key-a' });
function mock(...bodies: { body: unknown; status?: number }[]) {
  const fetch = vi.fn();
  for (const { body, status } of bodies) fetch.mockImplementationOnce(async (url, options) => { const req=options?.body ? JSON.parse(options.body) : {}; const wrapped=String(url).endsWith('/api/agent/features') && (status ?? 200)===200 ? {window:{start:req.start,end:req.end,time_zone:req.time_zone,widen_reason:req.widen_reason ?? null},data:body} : body; return new Response(JSON.stringify(wrapped),{status:status ?? 200}); });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
describe('production agent client', () => {
  it('discovers only the current key tenant, uses a same-origin gateway and preserves literal dates', async () => {
    const window = resolveAgentWindow(dates);
    const fetch = mock({ body: { agent_lane: { tenant_id: A } } }, { body: { window, rows: [] } });
    const result = await client().agentTool('lake_sql', { ...dates, sql: 'SELECT count(*) FROM events.auth WHERE {window}' });
    expect(result.success).toBe(true);
    expect(result.data?.window).toEqual(window);
    expect(fetch.mock.calls.map(([u]) => u)).toEqual(['https://us.nano.rs/t/tenant-a/api/auth/validate', `https://us.nano.rs/v1/tenants/${A}/lake/sql`]);
    const options = fetch.mock.calls[1][1];
    expect(JSON.parse(options.body)).toMatchObject({ start: '2026-10-16T04:00:00.000Z', end: '2026-10-17T04:00:00.000Z' });
    expect(options.headers['X-API-Key']).toBe('key-a');
    expect(options.headers['X-Nano-Agent']).toMatch(/^nano-investigator\/0.3.0; session=/);
    expect(options.redirect).toBe('error');
  });
  it('tenant A cannot use a tool argument to select tenant B or another endpoint', async () => {
    const fetch = mock();
    for (const extra of [{ tenant_id: B }, { gateway_url: 'https://foreign.invalid' }, { catalog: 'tenant-b' }]) {
      const result = await client().agentTool('lake_sql', { sql: 'SELECT * FROM events.auth WHERE {window}', ...extra });
      expect(result.success).toBe(false);
      expect(result.data?.window).toBeTruthy();
    }
    expect(fetch).not.toHaveBeenCalled();
  });
  it('a revoked or unbound key never reaches a catalog', async () => {
    const fetch = mock({ body: { message: 'denied' }, status: 403 }, { body: { agent_lane: null } });
    for (let i = 0; i < 2; i++) expect((await client().agentTool('lake_sql', { sql: 'SELECT * FROM events.auth WHERE {window}' })).success).toBe(false);
    expect(fetch.mock.calls.every(([u]) => u.endsWith('/api/auth/validate'))).toBe(true);
  });
  it('meter/cap/unknown responses are returned once with the window and no automatic retry', async () => {
    const fetch = mock({ body: { agent_lane: { tenant_id: A } } }, { body: { error: 'tenant_daily_budget_exhausted' }, status: 429 });
    const result = await client().agentTool('lake_sql', { ...dates, sql: 'SELECT * FROM events.auth WHERE {window}' });
    expect(result.success).toBe(false);
    expect(result.data?.window?.start).toBe('2026-10-16T04:00:00.000Z');
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('withholds a gateway response that widens the window', async () => {
    mock({ body: { agent_lane: { tenant_id: A } } }, { body: { rows: [{ secret: true }], window: { ...resolveAgentWindow(dates), start: '2020-01-01T00:00:00.000Z' } } });
    const result = await client().agentTool('lake_sql', { ...dates, sql: 'SELECT * FROM events.auth WHERE {window}' });
    expect(result.success).toBe(false);
    expect(JSON.stringify(result)).not.toContain('secret');
  });
  it('passes exact prevalence bounds and keeps Settings-computed rarity', async () => {
    const window = resolveAgentWindow(dates);
    const fetch = mock({ body: { data: [{ artifact: 'example.test', is_rare: true }], requested_window: { start: window.start, end: window.end }, effective_window: { start: window.start, end: window.end }, note: 'prevalence counted over whole parts; effective window shown', availability: { available: true } } });
    const result = await client().agentTool('prevalence', { reason: 'Check the suspicious entity from lake SQL.', ...dates, values: ['example.test'] });
    expect(result.success).toBe(true);
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toMatchObject({input: {tool: 'prevalence', values: ['example.test']}, reason: expect.any(String), session_id: expect.any(String), start: window.start, end: window.end });
  });
  it('refuses an old prevalence API that silently ignores absolute bounds, and unavailable cells', async () => {
    mock({ body: { data: [] } }, { body: { data: [], availability: { available: false, reason: 'pending' } } });
    for (let i = 0; i < 2; i++) expect((await client().agentTool('prevalence', { reason: 'Check the suspicious entity from lake SQL.', ...dates, values: ['x.test'] })).success).toBe(false);
  });
  it('resolves the same IP at two explicit timestamps into distinct observations', async () => {
    const fetch = vi.fn(async (_url: string, options: RequestInit) => {
      const req = JSON.parse(String(options.body)); const at=req.input.timestamp;
      return new Response(JSON.stringify({window:{start:req.start,end:req.end,time_zone:req.time_zone,widen_reason:req.widen_reason??null},data:{ ip: '192.0.2.1', match: { hostname: at === '2026-10-16T08:00:00.000Z' ? 'before' : 'after', last_seen: at } }}));
    });
    vi.stubGlobal('fetch', fetch);
    const sdk = client();
    const first = await sdk.agentTool('resolve_identity', { reason: 'Check the suspicious entity from lake SQL.', ...dates, ip: '192.0.2.1', timestamp: '2026-10-16T04:00:00-04:00' });
    const second = await sdk.agentTool('resolve_identity', { reason: 'Check the suspicious entity from lake SQL.', ...dates, ip: '192.0.2.1', timestamp: '2026-10-16T12:00:00-04:00' });
    expect(first.data?.data).toMatchObject({ match: { hostname: 'before' }, observed_at: '2026-10-16T08:00:00.000Z' });
    expect(second.data?.data).toMatchObject({ match: { hostname: 'after' }, observed_at: '2026-10-16T16:00:00.000Z' });
  });
  it('uses the literal window end for identity when no event timestamp was supplied', async () => {
    const fetch = mock({ body: { match: null, ip: '192.0.2.1' } });
    const result = await client().agentTool('resolve_identity', { reason: 'Check the suspicious entity from lake SQL.', ...dates, ip: '192.0.2.1' });
    expect(result.success).toBe(true);
    expect(JSON.parse(fetch.mock.calls[0][1].body).input.timestamp).toBe('2026-10-17T04:00:00.000Z');
    expect(result.data?.data).toMatchObject({ observed_at: null });
  });
  it('withholds observations newer than the requested event time', async () => {
    mock({ body: { match: { last_seen: '2026-10-18T00:00:00Z' } } });
    expect((await client().agentTool('resolve_identity', { reason: 'Check the suspicious entity from lake SQL.', ...dates, ip: '192.0.2.1' })).success).toBe(false);
  });
  it('filters risk samples to the exact window and refuses clamped anchors', async () => {
    const window = resolveAgentWindow(dates);
    mock({ body: { anchor: window.end, step_seconds: 3600, window_hours: 168, points: [{ t: '2026-10-16T03:00:00Z', score: 9 }, { t: '2026-10-16T04:00:00Z', score: 2 }, { t: window.end, score: 5 }], markers: [{ private: true }] } }, { body: { anchor: now } });
    const result = await client().agentTool('risk_scores', { reason: 'Check the suspicious entity from lake SQL.', ...dates, entity: 'user/a', entity_type: 'user' });
    expect(result.data?.data).toMatchObject({ points: [{ t: '2026-10-16T04:00:00Z', score: 2 }] });
    expect(JSON.stringify(result)).not.toContain('private');
    expect((await client().agentTool('risk_scores', { reason: 'Check the suspicious entity from lake SQL.', ...dates, entity: 'a', entity_type: 'user' })).success).toBe(false);
  });
  it('labels lookup snapshots current while preserving a historical analysis window', async () => {
    const fetch = mock({ body: { results: [] } }, { body: { matches: [] } });
    const sdk = client();
    const result = await sdk.agentTool('lookup', { reason: 'Check the suspicious entity from lake SQL.', ...dates, table_name: 'owners', key_field: 'host', values: ['h'] });
    expect(result.data).toMatchObject({ window: resolveAgentWindow(dates), data_semantics: 'current_lookup_snapshot_not_historical', retrieved_at: expect.any(String) });
    await sdk.agentTool('lookup', { reason: 'Check the suspicious entity from lake SQL.', ...dates, ioc: 'evil.test' });
    expect(fetch.mock.calls[1][0]).toBe('https://us.nano.rs/t/tenant-a/api/agent/features');
    expect(JSON.parse(fetch.mock.calls[1][1].body)).toMatchObject({input:{tool:'lookup',ioc:'evil.test'}});
  });
  it('does not send invalid bounds or widening without a reason for any tool', async () => {
    const fetch = mock();
    for (const name of ['lake_sql', 'prevalence', 'risk_scores', 'resolve_identity', 'lookup'] as const) {
      for (const args of [{ start: '2026-10-01' }, { start: '2026-10-01', end: '2026-10-22' }, { start: '10/16', end: '10/17' }]) expect((await client().agentTool(name, args)).success).toBe(false);
    }
    expect(fetch).not.toHaveBeenCalled();
  });
});
describe('window discipline', () => {
  it('defaults to 24h, keeps case ±1h and explicit bounds override case defaults', () => {
    const at = Date.parse(now);
    expect(resolveAgentWindow({}, at)).toMatchObject({ start: '2026-10-21T20:00:00.000Z', end: now, origin: 'default_24h' });
    const case_context = { case_id: 'case-1', alert_time: now };
    expect(resolveAgentWindow({ case_context }, at)).toMatchObject({ start: '2026-10-22T19:00:00.000Z', end: '2026-10-22T21:00:00.000Z' });
    expect(resolveAgentWindow({ ...dates, case_context }, at).start).toBe('2026-10-16T04:00:00.000Z');
  });
  it('uses local literal midnights across both DST transitions', () => {
    expect(resolveAgentWindow({ start: '2026-03-08', end: '2026-03-09', time_zone: 'America/New_York' })).toMatchObject({ start: '2026-03-08T05:00:00.000Z', end: '2026-03-09T04:00:00.000Z' });
    expect(resolveAgentWindow({ start: '2026-11-01', end: '2026-11-02', time_zone: 'America/New_York' })).toMatchObject({ start: '2026-11-01T04:00:00.000Z', end: '2026-11-02T05:00:00.000Z' });
  });
  it('echoes widening reason and rejects invalid timestamps/zones/reasons', () => {
    expect(resolveAgentWindow({ start: '2026-10-01', end: '2026-10-22', widen_reason: 'analyst asked' })).toMatchObject({ widened: true, widen_reason: 'analyst asked' });
    for (const args of [{ start: '2026-02-30', end: '2026-03-01' }, { time_zone: 'invalid' }, { widen_reason: ' ' }, { case_context: { case_id: 'a', alert_time: 'yesterday' } }]) expect(() => resolveAgentWindow(args)).toThrow();
  });
});

it('preserves microsecond event timestamps and refuses observations one microsecond in the future', async () => {
  const at = '2026-10-16T08:00:00.123456Z';
  const fetch = mock({ body: { match: { last_seen: at, hostname: 'precise' } } }, { body: { match: { last_seen: '2026-10-16T08:00:00.123457Z' } } });
  const sdk = client();
  const args = { reason: 'Check the suspicious event attribution.', ...dates, ip: '192.0.2.1', timestamp: '2026-10-16T04:00:00.123456-04:00' };
  const first = await sdk.agentTool('resolve_identity', args);
  expect(first.success).toBe(true);
  expect(JSON.parse(fetch.mock.calls[0][1].body).input.timestamp).toBe(at);
  expect(first.data?.data).toMatchObject({ reference_time: at, observed_at: at });
  expect((await sdk.agentTool('resolve_identity', args)).success).toBe(false);
});

it('refuses missing reasons and broad entities and reports budget once', async()=>{
 const fetch=mock(); const sdk=client();
 for(const args of [{values:['a.test']},{reason:'Investigate.',values:['all']},{reason:'Investigate.',values:['*.test']},{reason:'Investigate.',values:Array(11).fill('a.test')}]) expect((await sdk.agentTool('prevalence',args)).success).toBe(false);
 expect(fetch).not.toHaveBeenCalled();
 const denied=mock({body:{message:'budget: budget_session; back off'},status:429});
 const result=await sdk.agentTool('prevalence',{reason:'Investigate.',values:['a.test']});expect(result.error?.code).toBe('budget');expect(denied).toHaveBeenCalledTimes(1);
});
it('echoes wider whole-part coverage rather than claiming the requested range is exact',async()=>{
 const requested=resolveAgentWindow(dates), effective={start:'2026-10-16T03:00:00.000Z',end:'2026-10-17T05:00:00.000Z'};
 const fetch=vi.fn(async (_url,opts)=>{const req=JSON.parse(opts.body);return new Response(JSON.stringify({window:{...effective,time_zone:req.time_zone,widen_reason:null},data:{data:[{total_occurrences:3}],requested_window:{start:requested.start,end:requested.end},effective_window:effective,note:'prevalence counted over whole parts; effective window shown'}}));});vi.stubGlobal('fetch',fetch);
 const result=await client().agentTool('prevalence',{...dates,values:['a.test'],reason:'Verify current rarity.'});
 expect(result.success).toBe(true);expect(result.data?.window).toMatchObject(effective);expect(result.data?.requested_window).toMatchObject({start:requested.start,end:requested.end});expect(result.data?.effective_window).toEqual(effective);
});

it('refuses a prevalence echo shifted by one microsecond',async()=>{
 const requested=resolveAgentWindow(dates);
 vi.stubGlobal('fetch',vi.fn(async (_url,opts)=>{const req=JSON.parse(opts.body);return new Response(JSON.stringify({window:{start:requested.start,end:requested.end,time_zone:req.time_zone,widen_reason:null},data:{data:[{secret:true}],requested_window:{start:'2026-10-16T04:00:00.000001Z',end:requested.end},effective_window:{start:requested.start,end:requested.end},note:'prevalence counted over whole parts; effective window shown'}}));}));
 const result=await client().agentTool('prevalence',{...dates,values:['a.test'],reason:'Verify current rarity.'});expect(result.success).toBe(false);expect(JSON.stringify(result)).not.toContain('secret');
});

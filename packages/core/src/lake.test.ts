import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NanosiemClient } from './client.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/lake.json', import.meta.url), 'utf8'));
const req = { query: '* | stats count by device.hostname', time_range: { start: '2026-10-15T00:00:00Z', end: '2026-10-16T00:00:00Z' }, limit: 2 };
const client = (extra = {}) => new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/b12', apiKey: 'fixture-key', ...extra });
function mock(...responses: { body: unknown; status?: number }[]) {
  const fetch = vi.fn();
  for (const { body, status } of responses) fetch.mockResolvedValueOnce(new Response(JSON.stringify(body), { status: status ?? 200 }));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('lake search contracts', () => {
  it('preserves the tenant URL, API key and curl User-Agent on submission, polling and every page', async () => {
    const fetch = mock({ body: fixture.accepted, status: 202 }, { body: fixture.completed }, ...fixture.pages.map((body: unknown) => ({ body })));
    const result = await client().search(req);
    expect(result.success).toBe(true);
    expect(result.data?.results).toEqual(fixture.pages.flatMap((p: { rows: unknown[] }) => p.rows));
    expect(result.data?.has_more).toBe(true);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://us.nano.rs/t/b12/api/search', 'https://us.nano.rs/t/b12/api/search/jobs/job-fixture',
      'https://us.nano.rs/t/b12/api/search/jobs/job-fixture/results/0', 'https://us.nano.rs/t/b12/api/search/jobs/job-fixture/results/1',
    ]);
    for (const [, options] of fetch.mock.calls) {
      expect(options.headers['X-API-Key']).toBe('fixture-key');
      expect(options.headers['User-Agent']).toMatch(/^curl\//);
      expect(options.redirect).toBe('error');
    }
  });

  it('accepts inline and post-processed job results without reading candidate pages', async () => {
    const fetch = mock({ body: fixture.inline }, { body: fixture.accepted }, { body: { ...fixture.completed, durable_result: undefined, result: fixture.inline } });
    expect((await client().search(req)).data).toEqual(fixture.inline);
    expect((await client().search(req)).data).toEqual(fixture.inline);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('polls queued/running jobs and surfaces failures instead of empty success', async () => {
    vi.useFakeTimers();
    mock({ body: fixture.accepted }, { body: fixture.running }, { body: { job_id: 'job-fixture', status: 'failed', error: 'fixture failure' } });
    const pending = client().search(req);
    await vi.runAllTimersAsync();
    expect((await pending).error).toMatchObject({ code: 'SEARCH_JOB_FAILED' });
  });

  it('rejects oversized manifests before fetching any result pages', async () => {
    const fetch = mock({ body: fixture.accepted }, { body: { ...fixture.completed, durable_result: { rows: 1001, pages: 2, has_more: false } } });
    expect((await client().search(req)).error?.code).toBe('RESULT_LIMIT');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('withholds inconsistent pages and never returns partial data', async () => {
    mock({ body: fixture.accepted }, { body: fixture.completed }, { body: fixture.pages[0] }, { body: { ...fixture.pages[1], row_offset: 0 } });
    const result = await client().search(req);
    expect(result.success).toBe(false);
    expect(result.data).toBeUndefined();
  });

  it('preserves authorization errors on pages', async () => {
    mock({ body: fixture.accepted }, { body: fixture.completed }, { body: { message: 'Access denied' }, status: 403 });
    expect((await client().search(req)).error?.code).toBe('HTTP_403');
  });

  it('never treats an incomplete completed job as zero results', async () => {
    mock({ body: fixture.accepted }, { body: { status: 'completed' } });
    expect((await client().search(req)).success).toBe(false);
  });

  it('keeps the search result ceiling for direct SDK callers', async () => {
    const fetch = mock();
    for (const limit of [0, 1001, 1.5]) expect((await client().search({ ...req, limit })).error?.code).toBe('RESULT_LIMIT');
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('deployment contracts', () => {
  it('reads the active schema endpoint without translating canonical paths', async () => {
    const fetch = mock({ body: fixture.schema });
    expect((await client().getUdmFields()).data).toEqual(fixture.schema);
    expect(fetch.mock.calls[0][0]).toBe('https://us.nano.rs/t/b12/api/schema/fields');
  });

  it('reports hosted route gating clearly', async () => {
    mock({ body: fixture.closed, status: 404 });
    expect((await client().getSourceTypes()).error).toMatchObject({ code: 'NOT_AVAILABLE', message: expect.stringContaining('not available for hosted tenants') });
  });

  it('gates absent open-core surfaces without sending requests', async () => {
    const fetch = mock();
    const open = client({ deployment: 'open-core' });
    const results = await Promise.all([open.listCases(), open.listNotebooks(), open.getRiskOverview(), open.getEntityContext('ip', '192.0.2.1'), open.lookupIoc('192.0.2.1')]);
    for (const result of results) expect(result.error?.message).toContain('not available in open core');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('gates hosted SQL but keeps open-core SQL available', async () => {
    const fetch = mock({ body: fixture.inline });
    const sql = { sql: 'SELECT 1 LIMIT 1', time_range: req.time_range, limit: 1 };
    expect((await client().searchSql(sql)).error?.code).toBe('NOT_AVAILABLE');
    expect((await client({ deployment: 'open-core' }).searchSql(sql)).success).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('uses the entity context and actual risk timeline routes with encoded path segments', async () => {
    const fetch = mock({ body: { entity: 'alice/bob', entity_type: 'user', alerts: [], cases: [], matches: [], risk: null } }, { body: { entity: 'alice/bob', entity_type: 'user', points: [] } });
    await client().getEntityContext('user', 'alice/bob');
    await client().getEntityRiskTimeline('alice/bob', 'user');
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(['https://us.nano.rs/t/b12/api/entities/user/alice%2Fbob/context', 'https://us.nano.rs/t/b12/api/entities/user/alice%2Fbob/risk-timeline']);
  });
});

describe('lake compatibility failures', () => {
  it('refuses a legacy source filter rather than silently widening the search', async () => {
    const fetch = mock();
    const result = await client().search({ ...req, source_type: 'firewall' });
    expect(result.error?.message).toContain('metadata.log_source');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('withholds oversized inline results and malformed envelopes', async () => {
    mock({ body: { ...fixture.inline, results: [{}, {}, {}] } }, { body: {} });
    expect((await client().search(req)).error?.code).toBe('RESULT_LIMIT');
    expect((await client().search(req)).error?.code).toBe('INVALID_RESPONSE');
  });

  it('explains hosted browser-only and platform-managed operations before sending data', async () => {
    const fetch = mock();
    const hosted = client();
    expect((await hosted.assignCase('case-id', 'user-id')).error?.message).toContain('interactive tenant session');
    expect((await hosted.deploySourceConfig('config-id')).error?.message).toContain('managed by the platform');
    expect((await hosted.getOrgContext()).error?.code).toBe('NOT_AVAILABLE');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('stops polling within the configured budget and keeps the job id for diagnosis', async () => {
    vi.useFakeTimers();
    mock({ body: fixture.accepted }, { body: fixture.running });
    const pending = client({ timeout: 100 }).search(req);
    await vi.runAllTimersAsync();
    const result = await pending;
    expect(result.error).toMatchObject({ code: 'TIMEOUT', message: expect.stringContaining('job-fixture') });
    expect(result.data).toBeUndefined();
  });
});

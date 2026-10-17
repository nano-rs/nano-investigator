import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NanosiemClient } from '@nano-rs/investigator-core';
import { INGESTION_TOOLS, handleIngestionTool } from './ingestion.js';
import { getBuildParserPrompt } from '../prompts/build-parser.js';

const fixture = JSON.parse(readFileSync(new URL('../../../core/src/fixtures/ingestion.json', import.meta.url), 'utf8'));
const source_id = '00000000-0000-4000-8000-000000000001';
const credential_id = '00000000-0000-4000-8000-000000000002';
const repository_id = '00000000-0000-4000-8000-000000000003';
const client = () => new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/fixture', apiKey: 'fixture-key' });
function mock(overrides: Record<string, unknown> = {}, denied: string[] = []) {
  const data = { ...fixture, ...overrides };
  const fetch = vi.fn(async (url: string) => {
    const parsed = new URL(url);
    parsed.searchParams.delete('_');
    const path = parsed.pathname.replace('/t/fixture', '') + parsed.search;
    const body = data[path];
    return new Response(JSON.stringify(body ?? {}), { status: denied.includes(path) ? 403 : body === undefined ? 404 : 200 });
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
const call = (name: string, args = {}) => handleIngestionTool(name, args, client());
const body = (result: Awaited<ReturnType<typeof call>>) => JSON.parse(result.content[0].text);
afterEach(() => vi.unstubAllGlobals());

describe('ingestion diagnostic contracts', () => {
  it('distinguishes saved drafts, active versions, capabilities and mixed input processes', async () => {
    mock();
    const pipeline = body(await call('get_pipeline', { source_id }));
    expect(pipeline).toMatchObject({ has_draft_changes: true, active_version_number: 2, active_parser_vrl: '.old = true' });
    const explanation = body(await call('explain_pipeline', { source_id }));
    expect(explanation.inputs.data).toMatchObject({ mixed_processes: true, pull: [{ state: 'pending_bundle' }] });
    expect(explanation.runtime.data).toMatchObject({ preview_enabled: false, capture: { enabled: false } });
    expect(explanation.stages[0].kind).toBe('vrl');
    const releases = body(await call('get_pipeline_releases', { source_id }));
    expect(releases.versions[0]).toMatchObject({ version_number: 2, is_active: true });
    expect(releases.rollouts.data[0]).toMatchObject({ state: 'pending', terminal: false });
  });

  it('maps source labels to lanes and keeps edge receipt distinct from searchability', async () => {
    mock();
    expect(body(await call('get_pipeline_inputs')).sources[0]).toMatchObject({ log_source_id: source_id, source_slugs: ['gateway'] });
    expect(body(await call('get_add_data_status')).push.data.issuance_requests[0].state).toBe('pending');
    expect(body(await call('get_ingest_credential_activity', { credential_id }))).toMatchObject({
      first_event: { state: 'received_at_edge', searchable_at: null }, lake: { events: 0 }, redacted: true,
    });
    expect(body(await call('get_log_source_health', { source_id })).health_status).toBe('no_data');
  });

  it('preserves pull verification, connector enrollment and failed collection facts', async () => {
    mock();
    expect(body(await call('list_data_sources')).pulls.sources[0]).toMatchObject({ state: 'pending_bundle', verified_at: '2026-10-17T11:00:00Z' });
    expect(body(await call('get_connector_status', { connector: 'okta' }))[0]).toMatchObject({ credential_readiness: 'pending', last_status: 'failed', last_success_at: null });
  });

  it('keeps completed onboarding regression and unknown telemetry visible', async () => {
    mock();
    const plan = body(await call('get_onboarding_status'));
    expect(plan.waves[0].id).toBe('wave-1');
    expect(plan.sources[0]).toMatchObject({ completed: true, linkedLogSourceId: source_id, progress: { ready: false, parsingKnown: false } });
    expect(plan.sources[0].live.signals).toMatchObject({ eps: null, parseSuccessPct: null, status: 'unknown' });
  });

  it('reads synced catalog metadata, exact encoded paths and import links', async () => {
    mock();
    expect(body(await call('list_parser_repositories')).repositories[0]).toMatchObject({ branch: 'main', last_sync_status: 'syncing' });
    expect(body(await call('get_parser_repository_sync_status', { repository_id })).status).toBe('syncing');
    expect(body(await call('browse_parser_repository', { repository_id })).parsers[0].linked_log_source_id).toBe(source_id);
    expect(body(await call('get_repository_parser', { repository_id, path: 'network/gateway.yaml' })).parser_vrl).toBe('.');
  });

  it('uses scoped, cache-busted GETs for diagnostics', async () => {
    const fetch = mock();
    for (const definition of INGESTION_TOOLS.filter((tool) => tool.annotations.readOnlyHint)) {
      const result = await call(definition.name, definition.name === 'get_add_data_guidance' ? { inspect_workspace: true } :
        Object.fromEntries(definition.inputSchema.required.map((key) => [key, ({ source_id, credential_id, repository_id, connector: 'okta', path: 'network/gateway.yaml' } as Record<string, string>)[key]])));
      expect(result.isError, definition.name).not.toBe(true);
      expect(definition.annotations.readOnlyHint).toBe(true);
    }
    for (const [url, options] of fetch.mock.calls as unknown as [string, RequestInit][]) {
      expect(url).toMatch(/^https:\/\/us.nano.rs\/t\/fixture\/api\//);
      expect(new URL(url).searchParams.has('_')).toBe(true);
      expect(options.method).toBe('GET');
      expect(options.body).toBeUndefined();
      expect(options.redirect).toBe('error');
      expect(options.headers).toMatchObject({ 'X-API-Key': 'fixture-key' });
    }
    expect(INGESTION_TOOLS.map((tool) => tool.name)).not.toContain('publish_log_source');
  });

  it('rejects invalid IDs, traversal, bounds, unsupported args and writes before fetching', async () => {
    const fetch = mock();
    for (const [name, args] of [
      ['get_pipeline', { source_id: '../settings' }], ['list_pipelines', { limit: 101 }],
      ['get_connector_status', { connector: '../users' }], ['get_repository_parser', { repository_id, path: '../secret' }],
      ['get_add_data_status', { tenant_id: 'other' }], ['publish_log_source', { source_id }],
    ] as [string, Record<string, unknown>][]) expect((await call(name, args)).isError).toBe(true);
    expect((await client().readIngestion('/api/users')).success).toBe(false);
    expect((await client().readIngestion('/api/log-sources/%2e%2e/health')).success).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('withholds error bodies and secrets in metadata, VRL, error text and URLs', async () => {
    const path = `/api/log-sources/${source_id}/draft-status`;
    mock({ [path]: { ...fixture[path], parser_vrl: '.password = "sensitive-fixture"\n# Bearer fixture-bearer', description: 'https://user:pass@example.test/?api_key=fixture-query', api_key: 'fixture-api-key', credentials: { private_key: 'fixture-private' } } });
    const text = (await call('get_pipeline', { source_id })).content[0].text;
    for (const secret of ['sensitive-fixture', 'fixture-bearer', 'user:pass', 'fixture-query', 'fixture-api-key', 'fixture-private']) expect(text).not.toContain(secret);
    mock({ [path]: { secret: 'server-error-secret' } }, [path]);
    const denied = await call('get_pipeline', { source_id });
    expect(denied.isError).toBe(true);
    expect(denied.content[0].text).not.toContain('server-error-secret');
  });

  it('reports unavailable and malformed state instead of empty successful inventories', async () => {
    mock({ '/api/source-onboarding': {} });
    expect((await call('get_onboarding_status')).isError).toBe(true);
    mock({}, ['/api/pull-sources', '/api/marketplace/collectors']);
    expect((await call('list_data_sources')).isError).toBe(true);
    mock({}, [`/api/log-sources/${source_id}/pipe-capabilities`]);
    expect(body(await call('explain_pipeline', { source_id })).runtime.available).toBe(false);
  });

  it('withholds oversized results and treats unverified pipeline headers as raw VRL', async () => {
    const path = `/api/log-sources/${source_id}/draft-status`;
    mock({ [path]: { ...fixture[path], parser_vrl: 'x'.repeat(2 * 1024 * 1024) } });
    expect((await call('get_pipeline', { source_id })).isError).toBe(true);
    const plan = { version: 2, steps: [{ id: 'one', kind: 'route', enabled: true, name: 'Feed route', config: { input: `push:${credential_id}` } }] };
    const header = '# nano-pipe-v2 ' + JSON.stringify(plan) + '\n';
    mock({ [path]: { ...fixture[path], parser_vrl: header + '# Processing plan compiled by Nano at publication.\nnano_pipe_plan_v2()' } });
    expect(body(await call('explain_pipeline', { source_id })).stages[0]).toMatchObject({ order: 1, kind: 'route', config: { input: `push:${credential_id}` } });
    mock({ [path]: { ...fixture[path], parser_vrl: header + '. = "edited"' } });
    expect(body(await call('explain_pipeline', { source_id })).stages[0].kind).toBe('vrl');
  });

  it('hands authoring to nanodac and preserves snapshot, capture and rollout safeguards', () => {
    const text = getBuildParserPrompt({ source_type: 'gateway' }).messages[0].content.text;
    for (const term of ['nanodac', 'expected_updated_at', 'explicit consent', 'unknown', 'rollback']) expect(text).toContain(term);
    expect(text).not.toContain('deploy_source_config');
  });
});

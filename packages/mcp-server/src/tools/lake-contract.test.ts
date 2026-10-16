import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NanosiemClient } from '@nano-rs/investigator-core';
import { handleAlertsTool } from './alerts.js';
import { handleDetectionsTool } from './detections.js';
import { handleEnrichmentTool } from './enrichment.js';
import { handlePrevalenceTool } from './prevalence.js';
import { handleCasesTool } from './cases.js';

const fixture = JSON.parse(readFileSync(new URL('../../../core/src/fixtures/operations.json', import.meta.url), 'utf8'));
const client = new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/fixture', apiKey: 'fixture-key' });
afterEach(() => vi.unstubAllGlobals());
function respond(body: unknown) {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(body)));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('MCP with lake wire fixtures', () => {
  it('formats an actual alert array and preserves nested OCSF evidence', async () => {
    respond(fixture.alerts);
    const list = await handleAlertsTool('list_alerts', { limit: 1 }, client);
    expect(list.isError).not.toBe(true);
    expect(list.content[0].text).toContain('Fixture process');
    respond(fixture.alerts[0]);
    const detail = await handleAlertsTool('get_alert', { id: fixture.alerts[0].id }, client);
    expect(JSON.parse(detail.content[0].text).matched_events[0].process.file.path).toBe('/usr/bin/sh');
  });

  it('paginates the rule array and reports page coverage', async () => {
    const fetch = respond(fixture.rules);
    const result = await handleDetectionsTool('list_detections', { limit: 1, offset: 2 }, client);
    expect(fetch.mock.calls[0][0]).toBe('https://us.nano.rs/t/fixture/api/rules?limit=1&offset=2');
    expect(JSON.parse(result.content[0].text)).toMatchObject({ rules: [{ name: 'Fixture process' }], limit: 1, offset: 2, may_have_more: true });
  });

  it('keeps prevalence data wrapped, distinct from the client success envelope', async () => {
    respond(fixture.prevalence);
    const result = await handlePrevalenceTool('get_prevalence', { type: 'domain', value: 'example.invalid' }, client);
    expect(JSON.parse(result.content[0].text)).toEqual(fixture.prevalence);
  });

  it('preserves the full entity context instead of silently dropping failed components', async () => {
    respond(fixture.entity);
    const result = await handleEnrichmentTool('get_entity_context', { entity_type: 'ip', value: '192.0.2.1' }, client);
    expect(JSON.parse(result.content[0].text)).toEqual(fixture.entity);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ message: 'Missing cases:view' }), { status: 403 })));
    const denied = await handleEnrichmentTool('get_entity_context', { entity_type: 'ip', value: '192.0.2.1' }, client);
    expect(denied.isError).toBe(true);
    expect(denied.content[0].text).toContain('Missing cases:view');
  });

  it('accepts hosted case pagination and cleanly gates open-core cases', async () => {
    respond(fixture.cases);
    const result = await handleCasesTool('list_cases', { limit: 1 }, client);
    expect(result.isError).not.toBe(true);
    const open = new NanosiemClient({ apiUrl: 'http://localhost:3000', apiKey: 'fixture-key', deployment: 'open-core' });
    const absent = await handleCasesTool('list_cases', {}, open);
    expect(absent.isError).toBe(true);
    expect(absent.content[0].text).toContain('not available in open core');
  });
});

import { getHuntCampaignPrompt } from '../prompts/hunt.js';
import { afterEach, expect, it, vi } from 'vitest';
import { NanosiemClient } from '@nano-rs/investigator-core';
import { TOOLS, handleAgentLaneTool } from './agent-lane.js';
import { withPermissionRequirements } from '../tool-permissions.js';
afterEach(() => vi.unstubAllGlobals());
it('registers all five read tools with bounded arguments and authoritative permission metadata', () => {
  expect(TOOLS.map(t => t.name)).toEqual(['lake_sql', 'prevalence', 'risk_scores', 'resolve_identity', 'lookup']);
  for (const tool of withPermissionRequirements(TOOLS)) {
    expect(tool.annotations.readOnlyHint).toBe(true);
    expect(tool.inputSchema.additionalProperties).toBe(false);
    expect(tool.inputSchema.properties).toHaveProperty('start');
    expect(tool.inputSchema.properties).toHaveProperty('end');
    expect(tool.description).toContain('never automatically retry or widen');
    expect(tool._meta['io.nano/permission-requirements']).toBeTruthy();
  }
});
it.each(TOOLS.map(t => t.name))('%s returns the window on refusal through the production client', async name => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  const sdk = new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/a', apiKey: 'key-a' });
  const result = await handleAgentLaneTool(name, { start: '2026-10-16', end: '2026-10-17', tenant_id: 'foreign' }, sdk);
  expect(result.isError).toBe(true);
  expect(JSON.parse(result.content[0].text)).toMatchObject({ window: { start: '2026-10-16T00:00:00.000Z', end: '2026-10-17T00:00:00.000Z' }, error: { code: 'AGENT_TOOL_REFUSED' } });
  expect(fetch).not.toHaveBeenCalled();
});
it('resolves the same IP at two event times through the MCP handler', async () => {
  const fetch = vi.fn(async (url: string) => {
    const timestamp = new URL(url).searchParams.get('timestamp');
    return new Response(JSON.stringify({ match: { last_seen: timestamp, hostname: timestamp?.startsWith('2026-10-16T01') ? 'first' : 'second' } }));
  });
  vi.stubGlobal('fetch', fetch);
  const sdk = new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/a', apiKey: 'key-a' });
  const run = async (timestamp: string) => JSON.parse((await handleAgentLaneTool('resolve_identity', { ip: '192.0.2.1', timestamp, start: '2026-10-16', end: '2026-10-17' }, sdk)).content[0].text);
  expect((await run('2026-10-16T01:00:00Z')).data).toMatchObject({ match: { hostname: 'first' }, observed_at: '2026-10-16T01:00:00.000Z' });
  expect((await run('2026-10-16T02:00:00Z')).data).toMatchObject({ match: { hostname: 'second' }, observed_at: '2026-10-16T02:00:00.000Z' });
});

it('campaign guidance uses the bounded lane and a 24h default, without the legacy SQL escape hatch', () => {
  const prompt = getHuntCampaignPrompt({ description: 'fixture hunt' }).messages[0].content.text;
  expect(prompt).toContain('Time range: -24h');
  expect(prompt).toContain('WHERE {window}');
  expect(prompt).toContain('never silently widen');
  expect(prompt).not.toContain('reach for `search_sql`');
});

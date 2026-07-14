import { describe, it, expect, vi } from 'vitest';
import type { NanosiemClient } from '@nano-rs/investigator-core';
import { handleSearchTool, parseRelativeTime, TOOLS } from './search.js';

function makeMockClient(overrides: Partial<NanosiemClient> = {}): NanosiemClient {
  return overrides as unknown as NanosiemClient;
}

describe('parseRelativeTime', () => {
  it('parses relative shorthand', () => {
    const out = parseRelativeTime('-1h');
    expect(out).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('passes through ISO 8601', () => {
    expect(parseRelativeTime('2026-05-25T00:00:00Z')).toBe('2026-05-25T00:00:00Z');
  });

  it('resolves "now"', () => {
    const out = parseRelativeTime('now');
    expect(new Date(out).getTime()).toBeLessThanOrEqual(Date.now() + 1000);
  });

  it('throws on garbage', () => {
    expect(() => parseRelativeTime('not-a-time')).toThrow();
  });
});

describe('TOOLS registration', () => {
  it('lists search_sql before search (SQL is the default surface)', () => {
    const names = TOOLS.map((t) => t.name);
    const sqlIdx = names.indexOf('search_sql');
    const nplIdx = names.indexOf('search');
    expect(sqlIdx).toBeGreaterThanOrEqual(0);
    expect(nplIdx).toBeGreaterThanOrEqual(0);
    expect(sqlIdx).toBeLessThan(nplIdx);
  });

  it('registers get_schema', () => {
    expect(TOOLS.map((t) => t.name)).toContain('get_schema');
  });

  it('search_sql does not require start_time or end_time (defaults to 24h)', () => {
    const sql = TOOLS.find((t) => t.name === 'search_sql');
    expect(sql).toBeDefined();
    expect(sql!.inputSchema.required).toEqual(['sql']);
  });

  it('search_sql description embeds the perf rules', () => {
    const sql = TOOLS.find((t) => t.name === 'search_sql');
    expect(sql!.description).toContain('PREWHERE');
    expect(sql!.description).toContain('iLike');
    expect(sql!.description).toContain('lower(source_type)');
    expect(sql!.description).toContain('NAN-1026');
    expect(sql!.description).not.toMatch(/hasToken\([^)]*_search/);
  });

  it('search (nPL) description tells the LLM to prefer search_sql', () => {
    const npl = TOOLS.find((t) => t.name === 'search');
    expect(npl!.description).toMatch(/PREFER `search_sql`/);
  });
});

describe('handleSearchTool: search_sql time-range defaulting', () => {
  it('defaults to last 24h when start_time and end_time are omitted', async () => {
    const searchSql = vi.fn().mockResolvedValue({ success: true, data: { results: [] } });
    const client = makeMockClient({ searchSql });

    const result = await handleSearchTool(
      'search_sql',
      { sql: "SELECT * FROM logs PREWHERE timestamp >= '2026-05-25' LIMIT 10" },
      client,
    );

    expect(result.isError).not.toBe(true);
    expect(searchSql).toHaveBeenCalledOnce();
    const arg = searchSql.mock.calls[0][0];
    const startMs = new Date(arg.time_range.start).getTime();
    const endMs = new Date(arg.time_range.end).getTime();
    const spanMs = endMs - startMs;
    expect(spanMs).toBeGreaterThanOrEqual(23 * 3600 * 1000);
    expect(spanMs).toBeLessThanOrEqual(25 * 3600 * 1000);
  });

  it('passes through explicit time_range', async () => {
    const searchSql = vi.fn().mockResolvedValue({ success: true, data: { results: [] } });
    const client = makeMockClient({ searchSql });

    await handleSearchTool(
      'search_sql',
      {
        sql: "SELECT * FROM logs PREWHERE timestamp >= '2026-05-25' LIMIT 10",
        start_time: '2026-05-25T00:00:00Z',
        end_time: '2026-05-26T00:00:00Z',
      },
      client,
    );

    const arg = searchSql.mock.calls[0][0];
    expect(arg.time_range.start).toBe('2026-05-25T00:00:00Z');
    expect(arg.time_range.end).toBe('2026-05-26T00:00:00Z');
  });
});

describe('handleSearchTool: get_schema', () => {
  const udmFields = [
    { name: 'src_ip', column_name: 'src_ip', data_type: 'String', category: 'Network', description: 'Source IP' },
    { name: 'dest_ip', column_name: 'dest_ip', data_type: 'String', category: 'Network', description: 'Dest IP' },
    { name: 'process_name', column_name: 'process_name', data_type: 'String', category: 'Process', description: 'Process name' },
    { name: 'user', column_name: 'user', data_type: 'String', category: 'Auth', description: 'User' },
  ];

  it('returns udm_fields, all_categories, and ext_fields', async () => {
    const getUdmFields = vi.fn().mockResolvedValue({ success: true, data: { fields: udmFields } });
    const getExtFields = vi.fn().mockResolvedValue({ success: true, data: ['event_id', 'image_path'] });
    const client = makeMockClient({ getUdmFields, getExtFields });

    const result = await handleSearchTool('get_schema', {}, client);
    expect(result.isError).not.toBe(true);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.udm_field_count).toBe(4);
    expect(parsed.udm_fields).toHaveLength(4);
    expect(parsed.all_categories).toEqual(
      expect.arrayContaining([
        { name: 'Network', count: 2 },
        { name: 'Process', count: 1 },
        { name: 'Auth', count: 1 },
      ]),
    );
    expect(parsed.ext_fields).toEqual(['event_id', 'image_path']);
    expect(parsed.warnings).toBeUndefined();
  });

  it('filters by category (case-insensitive) but keeps all_categories complete', async () => {
    const getUdmFields = vi.fn().mockResolvedValue({ success: true, data: { fields: udmFields } });
    const getExtFields = vi.fn().mockResolvedValue({ success: true, data: [] });
    const client = makeMockClient({ getUdmFields, getExtFields });

    const result = await handleSearchTool('get_schema', { category: 'network' }, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.udm_field_count).toBe(2);
    expect(parsed.udm_fields.every((f: { category: string }) => f.category === 'Network')).toBe(true);
    expect(parsed.all_categories).toHaveLength(3);
  });

  it('skips ext fetch when include_ext is false', async () => {
    const getUdmFields = vi.fn().mockResolvedValue({ success: true, data: { fields: udmFields } });
    const getExtFields = vi.fn();
    const client = makeMockClient({ getUdmFields, getExtFields });

    const result = await handleSearchTool('get_schema', { include_ext: false }, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(getExtFields).not.toHaveBeenCalled();
    expect(parsed.ext_fields).toBeUndefined();
    expect(parsed.warnings).toBeUndefined();
  });

  it('attaches a warning when ext fetch fails but UDM succeeds', async () => {
    const getUdmFields = vi.fn().mockResolvedValue({ success: true, data: { fields: udmFields } });
    const getExtFields = vi.fn().mockResolvedValue({
      success: false,
      error: { code: 'HTTP_404', message: 'Not Found' },
    });
    const client = makeMockClient({ getUdmFields, getExtFields });

    const result = await handleSearchTool('get_schema', {}, client);
    expect(result.isError).not.toBe(true);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.udm_field_count).toBe(4);
    expect(parsed.ext_fields).toBeUndefined();
    expect(parsed.warnings).toBeDefined();
    expect(parsed.warnings[0]).toContain('ext_fields unavailable');
    expect(parsed.warnings[0]).toContain('Not Found');
  });

  it('surfaces an error if the UDM fetch fails', async () => {
    const getUdmFields = vi.fn().mockResolvedValue({
      success: false,
      error: { code: 'HTTP_500', message: 'boom' },
    });
    const getExtFields = vi.fn().mockResolvedValue({ success: true, data: [] });
    const client = makeMockClient({ getUdmFields, getExtFields });

    const result = await handleSearchTool('get_schema', {}, client);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('boom');
  });
});

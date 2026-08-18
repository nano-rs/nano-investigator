import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { NanosiemClient } from '@nano-rs/investigator-core';
import { handleSearchTool, parseRelativeTime, TOOLS } from './search.js';
import { resetDeploymentProfile } from '../deployment.js';

const UDM_SCHEMA_FIELDS = [
  { name: 'src_ip', type: 'ip_address', category: 'Network' },
  { name: 'dest_ip', type: 'ip_address', category: 'Network' },
  { name: 'process_name', type: 'string', category: 'Process' },
  { name: 'user', type: 'string', category: 'Auth' },
];

/**
 * Every search tool now resolves the deployment profile before it acts, so the
 * default mock has to answer discovery. Overrides still win, which is how the
 * OCSF/lake cases below install a different deployment.
 */
function makeMockClient(overrides: Partial<NanosiemClient> = {}): NanosiemClient {
  return {
    getSchemaFields: vi
      .fn()
      .mockResolvedValue({ success: true, data: { schema: 'udm', fields: UDM_SCHEMA_FIELDS } }),
    getCapabilities: vi
      .fn()
      .mockResolvedValue({ success: true, data: { edition: 'open', version: '0.0.0', capabilities: {} } }),
    ...overrides,
  } as unknown as NanosiemClient;
}

// The profile is memoized for the process, so a test that installs a lake or
// OCSF deployment would otherwise leak into every test after it.
beforeEach(() => {
  resetDeploymentProfile();
});

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
  it('lists search before search_sql (nPL is the default surface)', () => {
    const names = TOOLS.map((t) => t.name);
    const sqlIdx = names.indexOf('search_sql');
    const nplIdx = names.indexOf('search');
    expect(sqlIdx).toBeGreaterThanOrEqual(0);
    expect(nplIdx).toBeGreaterThanOrEqual(0);
    expect(nplIdx).toBeLessThan(sqlIdx);
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
    expect(sql!.description).toContain('one `WHERE` clause');
    expect(sql!.description).toContain('Do not write an explicit `PREWHERE`');
    expect(sql!.description).toContain('iLike');
    expect(sql!.description).toContain('lower(source_type)');
    expect(sql!.description).toContain('NAN-1026');
    expect(sql!.description).not.toMatch(/hasToken\([^)]*_search/);
  });

  it('search (nPL) description declares the safe default', () => {
    const npl = TOOLS.find((t) => t.name === 'search');
    expect(npl!.description).toContain('PRIMARY search tool');
    expect(npl!.description).toContain('Use `search_sql` only when nPL cannot express');
    expect(npl!.description).toContain('never silently slices aggregate output');
    expect(npl!.description).toContain('REX QUOTING');
    expect(npl!.description).toContain('wrap the whole pattern in SINGLE quotes');
  });

  it('get_field_values describes top-value coverage without implying a population total', () => {
    const fieldValues = TOOLS.find((t) => t.name === 'get_field_values');
    expect(fieldValues!.description).toContain('not a population count or statistical sample');
    expect(fieldValues!.description).toContain('matching_event_count: null');
    expect(fieldValues!.description).toContain('`| stats count`');
  });
});

describe('handleSearchTool: search_sql time-range defaulting', () => {
  it('defaults to last 24h when start_time and end_time are omitted', async () => {
    const searchSql = vi.fn().mockResolvedValue({ success: true, data: { results: [] } });
    const client = makeMockClient({ searchSql });

    const result = await handleSearchTool(
      'search_sql',
      { sql: "SELECT * FROM logs WHERE timestamp >= '2026-05-25' LIMIT 10" },
      client,
    );

    expect(result.isError).not.toBe(true);
    expect(searchSql).toHaveBeenCalledOnce();
    const arg = searchSql.mock.calls[0][0];
    const startMs = new Date(arg.time_range.start).getTime();
    const endMs = new Date(arg.time_range.end).getTime();
    const spanMs = endMs - startMs;
    expect(arg.limit).toBe(100);
    expect(spanMs).toBeGreaterThanOrEqual(23 * 3600 * 1000);
    expect(spanMs).toBeLessThanOrEqual(25 * 3600 * 1000);
  });

  it('passes through explicit time_range', async () => {
    const searchSql = vi.fn().mockResolvedValue({ success: true, data: { results: [] } });
    const client = makeMockClient({ searchSql });

    await handleSearchTool(
      'search_sql',
      {
        sql: "SELECT * FROM logs WHERE timestamp >= '2026-05-25' LIMIT 10",
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

describe('handleSearchTool: compact nPL search', () => {
  it('suppresses the companion histogram in both the request and agent response', async () => {
    const search = vi.fn().mockResolvedValue({
      success: true,
      data: {
        results: [{ dest_ip: '203.0.113.10', count: 40 }],
        total_count: 1,
        execution_time_ms: 12,
        fields: [],
        histogram: [{ time: '2026-08-05T00:00:00Z', count: 900_000 }],
      },
    });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      {
        query: 'source_type=windows_sysmon | stats count by dest_ip | head 40',
        start_time: '2026-08-04T00:00:00Z',
        end_time: '2026-08-05T00:00:00Z',
        limit: 40,
      },
      client,
    );

    expect(search).toHaveBeenCalledWith(expect.objectContaining({
      limit: 40,
      skip_field_stats: true,
      skip_histogram: true,
      table_view: true,
    }));
    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed.results).toEqual([{ dest_ip: '203.0.113.10', count: 40 }]);
    expect(parsed.histogram).toBeUndefined();
  });

  it('withholds an over-limit aggregate instead of silently truncating it', async () => {
    const search = vi.fn().mockResolvedValue({
      success: true,
      data: {
        results: [
          { dest_ip: 'first', count: 30 },
          { dest_ip: 'second', count: 20 },
          { dest_ip: 'secret-third', count: 10 },
        ],
      },
    });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      {
        query: 'source_type=firewall | stats count by dest_ip',
        start_time: '-1h',
        limit: 2,
      },
      client,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('returned 3 rows');
    expect(result.content[0].text).toContain('limit of 2');
    expect(result.content[0].text).toContain('| head 2');
    expect(result.content[0].text).toContain('Upgrade the nano backend');
    expect(result.content[0].text).toContain('do not interpret this error as zero matches');
    expect(result.content[0].text).not.toContain('secret-third');
  });

  it('returns an aggregate that exactly meets the requested limit', async () => {
    const rows = [
      { dest_ip: 'first', count: 30 },
      { dest_ip: 'second', count: 20 },
    ];
    const search = vi.fn().mockResolvedValue({ success: true, data: { results: rows } });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      { query: '* | stats count by dest_ip', start_time: '-1h', limit: 2 },
      client,
    );

    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text as string).results).toEqual(rows);
  });

  it('does not count a reserved display metadata row against the data-row limit', async () => {
    const graph = {
      nodes: [{ id: 'first', type: 'host' }, { id: 'second', type: 'host' }],
      edges: [{ from: 'first', to: 'second', method: 'network-ssh' }],
      evidence: {},
    };
    const rows = [
      { _display_type: 'lateral', _lateral_graph: graph },
      { src_host: 'first', dest_host: 'second' },
      { src_host: 'second', dest_host: 'third' },
    ];
    const search = vi.fn().mockResolvedValue({ success: true, data: { results: rows } });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      { query: '* | lateral src_host -> dest_host', start_time: '-1h', limit: 2 },
      client,
    );

    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text as string).results).toEqual(rows);
  });

  it('excludes at most one display metadata row from the result ceiling', async () => {
    const rows = [
      { _display_type: 'lateral', _lateral_graph: { nodes: [], edges: [] } },
      { _display_type: 'lateral', _lateral_graph: { nodes: [], edges: [] } },
      { src_host: 'first', dest_host: 'second' },
    ];
    const search = vi.fn().mockResolvedValue({ success: true, data: { results: rows } });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      { query: '* | lateral src_host -> dest_host', start_time: '-1h', limit: 1 },
      client,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('returned 2 rows');
  });

  it('omits an oversized nested lateral graph instead of returning partial graph data', async () => {
    const graph = {
      // Match nano's real renderer ceiling: at most 200 nodes, with a denser
      // edge/evidence payload capable of exceeding the wire budget.
      nodes: Array.from({ length: 200 }, (_, index) => ({
        id: `host-${index}`,
        type: 'host',
        label: `host-${index}`,
      })),
      edges: Array.from({ length: 400 }, (_, index) => ({
        from: `host-${index}`,
        to: `host-${index + 1}`,
        method: 'network-ssh',
        detail: `sensitive-edge-${index}-${'x'.repeat(256)}`,
      })),
      evidence: {},
    };
    const rows = [
      { _display_type: 'lateral', _lateral_graph: graph },
      { src_host: 'first', dest_host: 'second' },
    ];
    const search = vi.fn().mockResolvedValue({ success: true, data: { results: rows } });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      { query: '* | lateral src_host -> dest_host', start_time: '-1h', limit: 1 },
      client,
    );

    expect(result.isError).not.toBe(true);
    const text = result.content[0].text as string;
    const parsed = JSON.parse(text);
    expect(parsed.results[1]).toEqual(rows[1]);
    expect(parsed.results[0]._lateral_graph).toMatchObject({
      _mcp_omitted: true,
      original_node_count: 200,
      original_edge_count: 400,
      requested_data_row_limit: 1,
    });
    expect(parsed.results[0]._lateral_graph.original_bytes).toBeGreaterThan(64 * 1024);
    expect(parsed.results[0]._lateral_graph).not.toHaveProperty('nodes');
    expect(parsed.results[0]._lateral_graph).not.toHaveProperty('edges');
    expect(parsed.results[0]._lateral_graph.guidance).toContain('no partial graph data');
    expect(text).not.toContain('sensitive-edge-399');
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThan(8 * 1024);
  });

  it('omits a small-byte graph whose nested edges exceed the requested row budget', async () => {
    const graph = {
      nodes: [{ id: 'a' }, { id: 'b' }, { id: 'c' }],
      edges: [
        { from: 'a', to: 'b' },
        { from: 'b', to: 'c' },
      ],
    };
    const rows = [
      { _display_type: 'lateral', _lateral_graph: graph },
      { src_host: 'a', dest_host: 'b' },
    ];
    const search = vi.fn().mockResolvedValue({ success: true, data: { results: rows } });
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      { query: '* | lateral src_host -> dest_host', start_time: '-1h', limit: 1 },
      client,
    );

    const graphResult = JSON.parse(result.content[0].text as string).results[0]._lateral_graph;
    expect(graphResult).toMatchObject({
      _mcp_omitted: true,
      original_edge_count: 2,
      requested_data_row_limit: 1,
    });
    expect(graphResult.reason).toContain('nested edges exceeded');
    expect(graphResult).not.toHaveProperty('edges');
  });

  it('rejects a request above the MCP safety ceiling before calling nano', async () => {
    const search = vi.fn();
    const client = makeMockClient({ search });

    const result = await handleSearchTool(
      'search',
      { query: '*', start_time: '-1h', limit: 1_001 },
      client,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('safety ceiling of 1000 rows');
    expect(search).not.toHaveBeenCalled();
  });
});

describe('handleSearchTool: get_field_values coverage', () => {
  it('renames limited coverage fields and does not expose a matching total', async () => {
    const getFieldValues = vi.fn().mockResolvedValue({
      success: true,
      data: {
        field: 'source_type',
        values: [
          { value: 'windows', count: 80, percentage: 0.008 },
          { value: 'dns', count: 20, percentage: 0.002 },
        ],
        may_have_more_values: true,
        // The legacy backend total is deliberately misleading here. The MCP
        // response must derive and label only its returned-value coverage.
        total_count: 999_999,
      },
    });
    const client = makeMockClient({ getFieldValues });

    const result = await handleSearchTool(
      'get_field_values',
      { field: 'source_type', start_time: '-1h', limit: 2 },
      client,
    );

    expect(result.isError).not.toBe(true);
    expect(getFieldValues).toHaveBeenCalledWith(expect.objectContaining({
      field: 'source_type',
      query: '*',
      limit: 2,
    }));

    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed).not.toHaveProperty('total_count');
    expect(parsed.coverage).toEqual({
      kind: 'top_values_only',
      requested_limit: 2,
      returned_value_count: 2,
      returned_value_occurrence_count: 100,
      may_have_more_values: true,
      matching_event_count: null,
      matching_event_count_available: false,
    });
    expect(parsed.values).toEqual([
      { value: 'windows', count: 80, percentage_of_returned_value_occurrences: 80 },
      { value: 'dns', count: 20, percentage_of_returned_value_occurrences: 20 },
    ]);
    expect(parsed.values[0]).not.toHaveProperty('percentage');
    expect(parsed.guidance).toContain('not a sample or the total matching population');
    expect(parsed.guidance).toContain('| stats count');
  });
});

describe('handleSearchTool: get_schema', () => {
  const schemaFields = UDM_SCHEMA_FIELDS;

  const udmClient = (overrides: Record<string, unknown> = {}) =>
    makeMockClient({
      getSchemaFields: vi
        .fn()
        .mockResolvedValue({ success: true, data: { schema: 'udm', fields: schemaFields } }),
      ...overrides,
    } as Partial<NanosiemClient>);

  it('returns the active profile, its fields, all_categories, and ext_fields', async () => {
    const getExtFields = vi.fn().mockResolvedValue({ success: true, data: ['event_id', 'image_path'] });
    const client = udmClient({ getExtFields });

    const result = await handleSearchTool('get_schema', {}, client);
    expect(result.isError).not.toBe(true);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.schema).toBe('udm');
    expect(parsed.field_count).toBe(4);
    expect(parsed.fields).toHaveLength(4);
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

  it('reads the profile-aware endpoint, never the UDM-only one', async () => {
    // The whole bug: /api/udm/fields answers with UDM on an OCSF deployment.
    const getUdmFields = vi.fn();
    const client = udmClient({ getUdmFields, getExtFields: vi.fn().mockResolvedValue({ success: true, data: [] }) });

    await handleSearchTool('get_schema', {}, client);
    expect(getUdmFields).not.toHaveBeenCalled();
  });

  it('filters by category (case-insensitive) but keeps all_categories complete', async () => {
    const client = udmClient({ getExtFields: vi.fn().mockResolvedValue({ success: true, data: [] }) });

    const result = await handleSearchTool('get_schema', { category: 'network' }, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.field_count).toBe(2);
    expect(parsed.total_field_count).toBe(4);
    expect(parsed.fields.every((f: { category: string }) => f.category === 'Network')).toBe(true);
    expect(parsed.all_categories).toHaveLength(3);
  });

  it('skips ext fetch when include_ext is false', async () => {
    const getExtFields = vi.fn();
    const client = udmClient({ getExtFields });

    const result = await handleSearchTool('get_schema', { include_ext: false }, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(getExtFields).not.toHaveBeenCalled();
    expect(parsed.ext_fields).toBeUndefined();
    expect(parsed.warnings).toBeUndefined();
  });

  it('attaches a warning when ext fetch fails but the schema loads', async () => {
    const getExtFields = vi.fn().mockResolvedValue({
      success: false,
      error: { code: 'HTTP_404', message: 'Not Found' },
    });
    const client = udmClient({ getExtFields });

    const result = await handleSearchTool('get_schema', {}, client);
    expect(result.isError).not.toBe(true);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.field_count).toBe(4);
    expect(parsed.ext_fields).toBeUndefined();
    expect(parsed.warnings[0]).toContain('ext_fields unavailable');
    expect(parsed.warnings[0]).toContain('Not Found');
  });

  it('falls back to /api/udm/fields on a build without the profile endpoint, and says so', async () => {
    const client = makeMockClient({
      getSchemaFields: vi.fn().mockResolvedValue({ success: false, error: { code: 'HTTP_404', message: 'Not Found' } }),
      getUdmFields: vi.fn().mockResolvedValue({
        success: true,
        data: {
          fields: [
            { name: 'src_ip', column_name: 'src_ip', data_type: 'String', category: 'Network', description: 'Source IP' },
          ],
        },
      }),
      getExtFields: vi.fn().mockResolvedValue({ success: true, data: [] }),
    } as Partial<NanosiemClient>);

    const result = await handleSearchTool('get_schema', {}, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.schema).toBe('udm');
    expect(parsed.warnings.join(' ')).toContain('/api/schema/fields is unavailable');
  });

  it('surfaces an error, not a guessable field list, when schema discovery fails entirely', async () => {
    const client = makeMockClient({
      getSchemaFields: vi.fn().mockResolvedValue({ success: false, error: { code: 'HTTP_500', message: 'boom' } }),
      getUdmFields: vi.fn().mockResolvedValue({ success: false, error: { code: 'HTTP_500', message: 'boom' } }),
    } as Partial<NanosiemClient>);

    const result = await handleSearchTool('get_schema', {}, client);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('boom');
  });

  describe('OCSF deployment', () => {
    const ocsfClient = () =>
      makeMockClient({
        getSchemaFields: vi.fn().mockResolvedValue({
          success: true,
          data: {
            schema: 'ocsf',
            fields: [
              { name: 'actor.user.name', type: 'string', category: 'Identity' },
              { name: 'src_endpoint.ip', type: 'ip_address', category: 'Network' },
            ],
          },
        }),
        getExtFields: vi.fn(),
      } as Partial<NanosiemClient>);

    it('reports the OCSF profile and its dotted field names', async () => {
      const result = await handleSearchTool('get_schema', {}, ocsfClient());
      const parsed = JSON.parse(result.content[0].text as string);

      expect(parsed.schema).toBe('ocsf');
      expect(parsed.fields.map((f: { name: string }) => f.name)).toContain('actor.user.name');
    });

    it('distinguishes the flat search projection from the nested full event', async () => {
      const result = await handleSearchTool('get_schema', {}, ocsfClient());
      const parsed = JSON.parse(result.content[0].text as string);

      // Both shapes are real and they are not interchangeable: `search` sends
      // table_view, so its rows are flat dotted keys; `get_event` returns the
      // stored event, which is nested.
      expect(parsed.guidance).toContain('row["actor.user.name"]');
      expect(parsed.guidance).toContain('event.actor.user.name');
    });

    it('warns that a search row is a pruned projection, not the whole event', async () => {
      const result = await handleSearchTool('get_schema', {}, ocsfClient());
      const parsed = JSON.parse(result.content[0].text as string);

      expect(parsed.guidance).toContain('PRUNED projection');
      expect(parsed.guidance).toContain('get_event');
    });

    it('does not offer ext_fields — OCSF overflow is unmapped.*, not ext', async () => {
      const client = ocsfClient();
      const result = await handleSearchTool('get_schema', {}, client);
      const parsed = JSON.parse(result.content[0].text as string);

      expect(client.getExtFields).not.toHaveBeenCalled();
      expect(parsed.ext_fields).toBeUndefined();
      expect(parsed.ext_fields_note).toContain('unmapped.*');
    });
  });
});

describe('handleSearchTool: lake deployments', () => {
  const lakeClient = (overrides: Record<string, unknown> = {}) =>
    makeMockClient({
      getSchemaFields: vi.fn().mockResolvedValue({
        success: true,
        data: { schema: 'ocsf', fields: [{ name: 'src_endpoint.ip', type: 'ip_address', category: 'Network' }] },
      }),
      getCapabilities: vi.fn().mockResolvedValue({
        success: true,
        data: { edition: 'open', version: '0.0.0', capabilities: {}, logQueryBackend: 'lake' },
      }),
      ...overrides,
    } as Partial<NanosiemClient>);

  it('refuses search_sql without a round trip, and names nPL as the way forward', async () => {
    const searchSql = vi.fn();
    const client = lakeClient({ searchSql });

    const result = await handleSearchTool('search_sql', { sql: 'SELECT 1' }, client);

    expect(result.isError).toBe(true);
    expect(searchSql).not.toHaveBeenCalled();
    expect(result.content[0].text).toContain('Raw SQL is not available');
    expect(result.content[0].text).toContain('stats count by');
  });

  it('learns the backend from a refusal on a build that does not publish it', async () => {
    const searchSql = vi.fn().mockResolvedValue({
      success: false,
      error: {
        code: 'QUERY_ERROR',
        message: 'Query error: raw SQL is not supported by the lake MVP; use nPL so Nano can enforce tenant and byte-scan policy',
      },
    });
    // No logQueryBackend published, so the first call has to go out to learn.
    const client = makeMockClient({
      getSchemaFields: vi.fn().mockResolvedValue({ success: true, data: { schema: 'ocsf', fields: UDM_SCHEMA_FIELDS } }),
      searchSql,
    } as Partial<NanosiemClient>);

    const first = await handleSearchTool('search_sql', { sql: 'SELECT 1' }, client);
    expect(first.isError).toBe(true);
    expect(first.content[0].text).toContain('Raw SQL is not available');
    expect(searchSql).toHaveBeenCalledOnce();

    // Second call is answered from the learned profile — no further round trip.
    const second = await handleSearchTool('search_sql', { sql: 'SELECT 2' }, client);
    expect(second.isError).toBe(true);
    expect(searchSql).toHaveBeenCalledOnce();
  });

  it('resolves an escalated durable job to its rows instead of reporting nothing', async () => {
    const search = vi.fn().mockResolvedValue({ success: true, data: { job_id: 'job-1', status: 'queued' } });
    const getSearchJob = vi
      .fn()
      .mockResolvedValueOnce({ success: true, data: { job_id: 'job-1', status: 'running' } })
      .mockResolvedValue({
        success: true,
        data: {
          job_id: 'job-1',
          status: 'completed',
          durable_result: { rows: 2, pages: 1, page_rows: 2 },
        },
      });
    const getSearchJobResultPage = vi.fn().mockResolvedValue({
      success: true,
      data: { page: 0, pages: 1, total_rows: 2, row_offset: 0, rows: [{ a: 1 }, { a: 2 }] },
    });
    const client = lakeClient({ search, getSearchJob, getSearchJobResultPage });

    const result = await handleSearchTool(
      'search',
      { query: '* | head 2', start_time: '-1h' },
      client,
    );

    expect(result.isError).not.toBe(true);
    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed.results).toHaveLength(2);
    expect(parsed.total_count).toBe(2);
    expect(parsed.escalation_note).toContain('durable job job-1');
  });

  it('returns an inline job result when the job carries one', async () => {
    const search = vi.fn().mockResolvedValue({ success: true, data: { job_id: 'job-2', status: 'queued' } });
    const getSearchJob = vi.fn().mockResolvedValue({
      success: true,
      data: {
        job_id: 'job-2',
        status: 'completed',
        result: { results: [{ b: 1 }], total_count: 1, execution_time_ms: 5, fields: [] },
      },
    });
    const client = lakeClient({ search, getSearchJob });

    const result = await handleSearchTool('search', { query: '*', start_time: '-1h' }, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.results).toEqual([{ b: 1 }]);
    expect(parsed.escalation_note).toContain('durable job job-2');
  });

  it('never reports a failed escalation as a zero-match result', async () => {
    const search = vi.fn().mockResolvedValue({ success: true, data: { job_id: 'job-3', status: 'queued' } });
    const getSearchJob = vi.fn().mockResolvedValue({
      success: true,
      data: { job_id: 'job-3', status: 'failed', error: 'scan budget exceeded' },
    });
    const client = lakeClient({ search, getSearchJob });

    const result = await handleSearchTool('search', { query: '*', start_time: '-1h' }, client);

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('scan budget exceeded');
    expect(result.content[0].text).toContain('not a zero-match result');
  });
});

describe('handleSearchTool: get_event', () => {
  it('returns the complete event and flags that it is nested', async () => {
    const fetchLog = vi.fn().mockResolvedValue({
      success: true,
      data: { event: { actor: { user: { name: 'mharris' } }, metadata: { uid: 'evt-1' } } },
    });
    const client = makeMockClient({ fetchLog } as Partial<NanosiemClient>);

    const result = await handleSearchTool('get_event', { id: 'evt-1' }, client);
    expect(result.isError).not.toBe(true);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed.event.actor.user.name).toBe('mharris');
    expect(parsed.note).toContain('NESTED');
  });

  it('passes the pruning hints through when given', async () => {
    const fetchLog = vi.fn().mockResolvedValue({ success: true, data: { event: {} } });
    const client = makeMockClient({ fetchLog } as Partial<NanosiemClient>);

    await handleSearchTool(
      'get_event',
      {
        id: 'evt-1',
        start_time: '2026-08-18T20:00:00Z',
        end_time: '2026-08-18T20:05:00Z',
        source_type: 'windows_event',
      },
      client,
    );

    expect(fetchLog).toHaveBeenCalledWith({
      id: 'evt-1',
      time_range: { start: '2026-08-18T20:00:00Z', end: '2026-08-18T20:05:00Z' },
      source_type: 'windows_event',
    });
  });

  it('omits the time range entirely when no start_time is given', async () => {
    const fetchLog = vi.fn().mockResolvedValue({ success: true, data: { event: {} } });
    const client = makeMockClient({ fetchLog } as Partial<NanosiemClient>);

    await handleSearchTool('get_event', { id: 'evt-1' }, client);

    expect(fetchLog.mock.calls[0][0].time_range).toBeUndefined();
  });

  it('explains what a null event means instead of returning an empty object', async () => {
    const fetchLog = vi.fn().mockResolvedValue({ success: true, data: { event: null } });
    const client = makeMockClient({ fetchLog } as Partial<NanosiemClient>);

    const result = await handleSearchTool('get_event', { id: 'result-0' }, client);

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('metadata.uid');
    expect(result.content[0].text).toContain('not a positional index');
  });
});

describe('deployment discovery caching', () => {
  it('retries after a failed discovery instead of poisoning the session', async () => {
    // A transient outage at session start must not permanently convince the
    // server it has no schema.
    const getSchemaFields = vi
      .fn()
      .mockResolvedValueOnce({ success: false, error: { code: 'HTTP_503', message: 'unavailable' } })
      .mockResolvedValue({ success: true, data: { schema: 'ocsf', fields: UDM_SCHEMA_FIELDS } });
    const client = makeMockClient({
      getSchemaFields,
      getUdmFields: vi.fn().mockResolvedValue({ success: false, error: { code: 'HTTP_503', message: 'unavailable' } }),
      getExtFields: vi.fn(),
    } as Partial<NanosiemClient>);

    const first = await handleSearchTool('get_schema', {}, client);
    expect(first.isError).toBe(true);

    const second = await handleSearchTool('get_schema', {}, client);
    expect(second.isError).not.toBe(true);
    expect(JSON.parse(second.content[0].text as string).schema).toBe('ocsf');
  });

  it('memoizes a successful discovery rather than re-fetching per tool call', async () => {
    const getSchemaFields = vi
      .fn()
      .mockResolvedValue({ success: true, data: { schema: 'udm', fields: UDM_SCHEMA_FIELDS } });
    const client = makeMockClient({
      getSchemaFields,
      getExtFields: vi.fn().mockResolvedValue({ success: true, data: [] }),
    } as Partial<NanosiemClient>);

    await handleSearchTool('get_schema', {}, client);
    await handleSearchTool('get_schema', {}, client);

    expect(getSchemaFields).toHaveBeenCalledOnce();
  });
});

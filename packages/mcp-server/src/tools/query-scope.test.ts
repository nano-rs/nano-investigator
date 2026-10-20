import { describe, it, expect, vi } from 'vitest';
import type { NanosiemClient } from '@nano-rs/investigator-core';
import { bareStarRefusal, classifyQueryScope, splitPipeline } from './query-scope.js';
import { handleSearchTool, TOOLS } from './search.js';

const START = '2026-10-12T00:00:00Z';
const END_4H = '2026-10-12T04:00:00Z';
const END_4H_1S = '2026-10-12T04:00:01Z';
const END_7D = '2026-10-19T00:00:00Z';

describe('splitPipeline', () => {
  it('ignores pipes inside quotes and parentheses', () => {
    expect(splitPipeline(`* | where message="a|b" | stats count`)).toEqual([
      '*',
      'where message="a|b"',
      'stats count',
    ]);
    expect(splitPipeline(`* | rex field=m '(?<x>a|b)' | head 5`)).toHaveLength(3);
  });
});

describe('classifyQueryScope', () => {
  it.each([
    '*',
    '',
    '| stats count',
    '* | stats count',
    '* | stats count by metadata.log_source',
    '* | eval a=b | where metadata.log_source=x',
    '* | where severity_id > 3',
    '* | where message="svchost"',
    '* | where actor.user.name!="svc"',
  ])('%s is bare', (query) => {
    expect(classifyQueryScope(query).bare).toBe(true);
  });

  it.each([
    'error',
    'metadata.log_source=x',
    'class_uid=4001',
    'device.hostname=h',
    'src_endpoint.ip=1.2.3.4',
    'user=x',
    '* error',
    'metadata.log_source=x | stats count',
    '* | where metadata.log_source=x',
    '* | where class_uid=4001 | stats count',
    '* | where device.hostname="ws-1.corp.local" | stats count',
    '* | where file.hashes.value IN ("abc") | stats count',
    '* | where metadata.log_source=x | where severity_id > 3',
  ])('%s is scoped', (query) => {
    expect(classifyQueryScope(query).bare).toBe(false);
  });

  it('only listing commands keep a bare query a listing', () => {
    expect(classifyQueryScope('*').aggregates).toBe(false);
    expect(classifyQueryScope('* | head 20').aggregates).toBe(false);
    expect(classifyQueryScope('* | sort -time | table time, message').aggregates).toBe(false);
    for (const query of [
      '* | stats count',
      '* | timechart span=1h count',
      '* | eval x=1',
      '* | where severity_id > 3',
      '* | dedup device.hostname',
    ]) {
      expect(classifyQueryScope(query).aggregates, query).toBe(true);
    }
  });
});

describe('bareStarRefusal', () => {
  it('refuses a bare aggregation only past 4h', () => {
    expect(bareStarRefusal('* | stats dc(device.hostname)', START, END_4H, 'search')).toBeNull();
    expect(bareStarRefusal('* | stats dc(device.hostname)', START, END_4H_1S, 'search')).toContain('bare `*` aggregation');
  });

  it('never refuses a listing or a scoped aggregation', () => {
    expect(bareStarRefusal('*', START, END_7D, 'search')).toBeNull();
    expect(bareStarRefusal('* | head 50', START, END_7D, 'search')).toBeNull();
    expect(bareStarRefusal('metadata.log_source=okta | stats count by actor.user.name', START, END_7D, 'search')).toBeNull();
  });

  it('suggests scoped rewrites that keep the pipeline', () => {
    const refusal = bareStarRefusal('* | stats count by device.hostname', START, END_7D, 'search')!;
    expect(refusal).toContain('`metadata.log_source=<source> | stats count by device.hostname`');
    expect(refusal).toContain('class_uid=<class> | stats count by device.hostname');
    expect(refusal).toContain('get_source_types');
    expect(refusal).toContain('4h or less');
    expect(refusal).toContain('allow_bare_star=true');
  });

  it('treats a self-aggregating tool as an aggregation even for plain *', () => {
    expect(bareStarRefusal('*', START, END_7D, 'get_field_values', { aggregates: true })).not.toBeNull();
    expect(bareStarRefusal('*', START, END_4H, 'get_field_values', { aggregates: true })).toBeNull();
  });
});

function client(overrides: Partial<NanosiemClient>): NanosiemClient {
  return overrides as unknown as NanosiemClient;
}

const okSearch = () =>
  vi.fn().mockResolvedValue({ success: true, data: { results: [], total_count: 0, fields: [] } });

describe('search tool bare * guard', () => {
  it('refuses a 7d bare stats without calling nano', async () => {
    const search = okSearch();
    const result = await handleSearchTool(
      'search',
      { query: '* | stats count by actor.user.name', start_time: START, end_time: END_7D },
      client({ search }),
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('metadata.log_source=<source> | stats count by actor.user.name');
    expect(search).not.toHaveBeenCalled();
  });

  it('runs a 7d bare listing', async () => {
    const search = okSearch();
    const result = await handleSearchTool(
      'search',
      { query: '* | head 20', start_time: START, end_time: END_7D },
      client({ search }),
    );
    expect(result.isError).not.toBe(true);
    expect(search).toHaveBeenCalledOnce();
  });

  it('runs a bare aggregation within 4h and an explicit override past it', async () => {
    const search = okSearch();
    await handleSearchTool('search', { query: '* | stats dc(device.hostname)', start_time: START, end_time: END_4H }, client({ search }));
    await handleSearchTool(
      'search',
      { query: '* | stats dc(device.hostname)', start_time: START, end_time: END_7D, allow_bare_star: true },
      client({ search }),
    );
    expect(search).toHaveBeenCalledTimes(2);
  });

  it('refuses unscoped get_field_values past 4h but runs a scoped one', async () => {
    const getFieldValues = vi.fn().mockResolvedValue({ success: true, data: { field: 'f', values: [] } });
    const refused = await handleSearchTool(
      'get_field_values',
      { field: 'device.hostname', start_time: START, end_time: END_7D },
      client({ getFieldValues }),
    );
    expect(refused.isError).toBe(true);
    expect(getFieldValues).not.toHaveBeenCalled();

    const scoped = await handleSearchTool(
      'get_field_values',
      { field: 'device.hostname', query: 'metadata.log_source=okta', start_time: START, end_time: END_7D },
      client({ getFieldValues }),
    );
    expect(scoped.isError).not.toBe(true);
    expect(getFieldValues).toHaveBeenCalledOnce();
  });

  it('tells agents to scope first in the tool description', () => {
    const search = TOOLS.find((t) => t.name === 'search')!;
    expect(search.description).toContain('SCOPE FIRST');
    expect(search.inputSchema.properties).toHaveProperty('allow_bare_star');
  });
});

describe('rollup-answered bare counts stay interactive (NAN-4184)', () => {
  it.each([
    '* | stats count by metadata.log_source',
    '* | stats count by metadata.log_source | sort -count',
    '* | stats count by metadata.log_source | sort -count | head 10',
    '* | stats count by metadata.log_source | where count > 100',
    '* | stats count() as n by source_type',
    '* | stats count() as n by class_uid | sort -n',
    '* | stats count',
    '* | timechart span=1h count by metadata.log_source',
    '* | timechart span=5m count',
    '* | stats count() as cnt by metadata.log_source | sort -cnt | head 1000',
    '* | stats count() as event_count by metadata.log_source | sort -event_count',
    '* | stats count() as event_count by metadata.log_source | sort -event_count | head 50',
    '* | stats count() as count by metadata.log_source | sort -count',
  ])('%s runs over 7d', (query) => {
    expect(classifyQueryScope(query).rollup).toBe(true);
    expect(bareStarRefusal(query, START, END_7D, 'search')).toBeNull();
  });

  it.each([
    '* | stats dc(device.hostname) by metadata.log_source',
    '* | stats sum(severity_id) by metadata.log_source',
    '* | stats count by actor.process.user.name',
    '* | timechart span=1m count by metadata.log_source',
    '* | timechart span=7m count',
    '* | eval s=metadata.log_source | stats count by s',
    '* | stats count by metadata.log_source | eval x=1',
  ])('%s is refused over 7d', (query) => {
    expect(bareStarRefusal(query, START, END_7D, 'search')).not.toBeNull();
  });

  it('runs the literal system inventory through the search tool over 7d', async () => {
    const search = okSearch();
    const result = await handleSearchTool(
      'search',
      {
        query: '* | stats count() as event_count by metadata.log_source | sort -event_count | head 50',
        start_time: START,
        end_time: END_7D,
      },
      client({ search }),
    );
    expect(result.isError).not.toBe(true);
    expect(search).toHaveBeenCalledOnce();

    const refused = await handleSearchTool(
      'search',
      { query: '* | stats dc(device.hostname) by metadata.log_source', start_time: START, end_time: END_7D },
      client({ search }),
    );
    expect(refused.isError).toBe(true);
    expect(search).toHaveBeenCalledOnce();
  });
});

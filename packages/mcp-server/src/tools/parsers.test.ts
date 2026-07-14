import { describe, it, expect, vi } from 'vitest';
import type { NanosiemClient } from '@nano-rs/investigator-core';
import { handleParsersTool, TOOLS } from './parsers.js';

function makeMockClient(overrides: Partial<NanosiemClient> = {}): NanosiemClient {
  return overrides as unknown as NanosiemClient;
}

describe('parsers TOOLS registration', () => {
  const names = TOOLS.map((t) => t.name);

  it('registers the Phase 1 authoring spine', () => {
    for (const n of [
      'list_log_sources',
      'get_log_source',
      'validate_vrl',
      'test_parse_sample',
      'create_log_source',
      'update_log_source',
      'deploy_log_source',
      'get_log_source_health',
    ]) {
      expect(names).toContain(n);
    }
  });

  it('registers the Phase 3 ingress + library tools', () => {
    for (const n of [
      'list_source_config_types',
      'list_source_configs',
      'create_routing_rule',
      'check_rule_reachability',
      'test_parse_live',
      'undeploy_log_source',
      'get_log_source_deployments',
      'list_parser_repositories',
      'sync_parser_repository',
      'list_repository_parsers',
      'import_parser',
    ]) {
      expect(names).toContain(n);
    }
  });

  it('does NOT register the Enterprise-only AI tools (open-edition parity goal)', () => {
    expect(names).not.toContain('ai_generate_parser');
    expect(names).not.toContain('ai_edit_parser');
  });

  it('create_log_source requires only name, source_type, parser_vrl', () => {
    const tool = TOOLS.find((t) => t.name === 'create_log_source');
    expect(tool!.inputSchema.required).toEqual(['name', 'source_type', 'parser_vrl']);
  });

  it('validate_vrl requires vrl_code', () => {
    const tool = TOOLS.find((t) => t.name === 'validate_vrl');
    expect(tool!.inputSchema.required).toEqual(['vrl_code']);
  });

  it('deploy_log_source description warns the deploy is best-effort', () => {
    const tool = TOOLS.find((t) => t.name === 'deploy_log_source');
    expect(tool!.description).toMatch(/best-effort/i);
    expect(tool!.description).toContain('get_log_source_health');
  });

  it('every tool has a non-empty description and an object input schema', () => {
    for (const t of TOOLS) {
      expect(t.description.length).toBeGreaterThan(0);
      expect(t.inputSchema.type).toBe('object');
    }
  });
});

describe('handleParsersTool dispatch', () => {
  it('validate_vrl forwards vrl_code and returns the validation result', async () => {
    const validateVrl = vi.fn().mockResolvedValue({
      success: true,
      data: { valid: true, errors: [], diagnostics: [] },
    });
    const client = makeMockClient({ validateVrl });

    const result = await handleParsersTool('validate_vrl', { vrl_code: '.x = 1' }, client);

    expect(result.isError).not.toBe(true);
    expect(validateVrl).toHaveBeenCalledWith('.x = 1');
    expect(JSON.parse(result.content[0].text as string).valid).toBe(true);
  });

  it('test_parse_sample passes vrl_code + sample_log through', async () => {
    const testVrl = vi.fn().mockResolvedValue({
      success: true,
      data: { input: 'l', success: true, output: { udm: { src_ip: '1.2.3.4' } }, extracted_field_count: 1 },
    });
    const client = makeMockClient({ testVrl });

    const result = await handleParsersTool(
      'test_parse_sample',
      { vrl_code: '.udm.src_ip = "1.2.3.4"', sample_log: 'raw line' },
      client,
    );

    expect(result.isError).not.toBe(true);
    expect(testVrl).toHaveBeenCalledWith({ vrl_code: '.udm.src_ip = "1.2.3.4"', sample_log: 'raw line' });
  });

  it('create_log_source builds the request and flags the draft is not deployed', async () => {
    const createLogSource = vi.fn().mockResolvedValue({
      success: true,
      data: { id: 'logsource_abc', name: 'Apache', source_type: 'apache', deployed: false },
    });
    const client = makeMockClient({ createLogSource });

    const result = await handleParsersTool(
      'create_log_source',
      { name: 'Apache', source_type: 'apache', parser_vrl: '.message = string!(.message)' },
      client,
    );

    expect(createLogSource).toHaveBeenCalledWith({
      name: 'Apache',
      source_type: 'apache',
      parser_vrl: '.message = string!(.message)',
    });
    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed.id).toBe('logsource_abc');
    expect(parsed.note).toMatch(/NOT deployed/i);
  });

  it('deploy_log_source appends the confirm-with-health advisory', async () => {
    const deployLogSource = vi.fn().mockResolvedValue({
      success: true,
      data: { success: true, log_source_id: 'logsource_abc', action: 'deploy', message: 'ok' },
    });
    const client = makeMockClient({ deployLogSource });

    const result = await handleParsersTool('deploy_log_source', { id: 'logsource_abc' }, client);

    expect(deployLogSource).toHaveBeenCalledWith('logsource_abc');
    expect(JSON.parse(result.content[0].text as string).note).toMatch(/get_log_source_health/);
  });

  it('create_log_source carries the routed-feed match_values (the central router key)', async () => {
    const createLogSource = vi.fn().mockResolvedValue({
      success: true,
      data: { id: 'logsource_cs', name: 'CrowdStrike', source_type: 'routed', deployed: false },
    });
    const client = makeMockClient({ createLogSource });

    await handleParsersTool(
      'create_log_source',
      {
        name: 'CrowdStrike Falcon',
        source_type: 'routed',
        parser_vrl: '.message = string!(.message)',
        match_values: ['crowdstrike_falcon'],
      },
      client,
    );

    // Without match_values the parser would deploy deaf — assert they reach the API.
    expect(createLogSource).toHaveBeenCalledWith({
      name: 'CrowdStrike Falcon',
      source_type: 'routed',
      parser_vrl: '.message = string!(.message)',
      match_values: ['crowdstrike_falcon'],
    });
  });

  it('update_log_source carries match_values through', async () => {
    const updateLogSource = vi.fn().mockResolvedValue({ success: true, data: { id: 'logsource_cs' } });
    const client = makeMockClient({ updateLogSource });

    await handleParsersTool(
      'update_log_source',
      { id: 'logsource_cs', match_values: ['crowdstrike_falcon', 'crowdstrike'] },
      client,
    );

    expect(updateLogSource).toHaveBeenCalledWith('logsource_cs', {
      match_values: ['crowdstrike_falcon', 'crowdstrike'],
    });
  });

  it('deploy_source_config redeploys the ingress and advises confirming health', async () => {
    const deploySourceConfig = vi.fn().mockResolvedValue({
      success: true,
      data: { success: true, source_configuration_id: 'srcfg_1', action: 'deploy', message: 'ok' },
    });
    const client = makeMockClient({ deploySourceConfig });

    const result = await handleParsersTool('deploy_source_config', { id: 'srcfg_1' }, client);

    expect(deploySourceConfig).toHaveBeenCalledWith('srcfg_1');
    expect(JSON.parse(result.content[0].text as string).note).toMatch(/get_log_source_health/);
  });

  it('list_log_sources filters by source_type and returns a summary projection', async () => {
    const listLogSources = vi.fn().mockResolvedValue({
      success: true,
      data: [
        { id: 'a', name: 'Apache', source_type: 'apache', kind: 'log', deployed: true, validated: true, enabled: true, parser_vrl: 'BIG' },
        { id: 'b', name: 'Sysmon', source_type: 'sysmon', kind: 'log', deployed: false, validated: true, enabled: true, parser_vrl: 'BIG' },
      ],
    });
    const client = makeMockClient({ listLogSources });

    const result = await handleParsersTool('list_log_sources', { source_type: 'APACHE' }, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(parsed).toHaveLength(1);
    expect(parsed[0].id).toBe('a');
    // Summary projection must NOT leak the full VRL.
    expect(parsed[0].parser_vrl).toBeUndefined();
  });

  it('list_parser_repositories unwraps the { repositories } envelope', async () => {
    const listParserRepositories = vi.fn().mockResolvedValue({
      success: true,
      data: { repositories: [{ id: 'repo_1', name: 'nano-parsers' }] },
    });
    const client = makeMockClient({ listParserRepositories });

    const result = await handleParsersTool('list_parser_repositories', {}, client);
    const parsed = JSON.parse(result.content[0].text as string);

    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].id).toBe('repo_1');
  });

  it('import_parser forwards id + path and only the provided optional fields', async () => {
    const importParser = vi.fn().mockResolvedValue({
      success: true,
      data: { log_source_id: 'logsource_z', import_type: 'linked' },
    });
    const client = makeMockClient({ importParser });

    const result = await handleParsersTool(
      'import_parser',
      { repository_id: 'repo_1', path: 'parsers/apache.toml', source_type: 'apache' },
      client,
    );

    expect(importParser).toHaveBeenCalledWith('repo_1', 'parsers/apache.toml', { source_type: 'apache' });
    expect(JSON.parse(result.content[0].text as string).note).toMatch(/deploy_log_source/);
  });

  it('surfaces the API error message on failure', async () => {
    const validateVrl = vi.fn().mockResolvedValue({
      success: false,
      error: { code: 'HTTP_403', message: 'Missing permission: log_sources:view' },
    });
    const client = makeMockClient({ validateVrl });

    const result = await handleParsersTool('validate_vrl', { vrl_code: '.x = 1' }, client);

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Missing permission');
  });

  it('returns an error for an unknown tool name', async () => {
    const result = await handleParsersTool('nope', {}, makeMockClient());
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Unknown tool');
  });
});

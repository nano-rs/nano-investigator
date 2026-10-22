/**
 * NAN-4375 — SOAR tools against the real tenant OpenAPI contract.
 *
 * `soar-openapi.json` is cut from the served nanosiem tenant spec
 * (scripts/refresh-soar-openapi.mjs). Every request a SOAR tool sends must hit a
 * documented operation with a body the schema accepts (the Rust DTOs are
 * `deny_unknown_fields`, so an extra key is a 400 in production), and the
 * recorded responses the tools parse must satisfy the response schemas.
 *
 * Like the parser client contract before it, this also asserts the client
 * methods exist on the prototype that vitest resolves through core's `exports`
 * → `dist`, so a stale core build fails here rather than in a published bundle.
 */

import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NanosiemClient } from '@nano-rs/investigator-core';
import { TOOLS, handleSoarTool } from './soar.js';

type Json = Record<string, unknown>;
const spec = JSON.parse(readFileSync(new URL('../../../core/src/fixtures/soar-openapi.json', import.meta.url), 'utf8'));
const fixture = JSON.parse(readFileSync(new URL('../../../core/src/fixtures/soar.json', import.meta.url), 'utf8'));
const schemas: Record<string, Json> = spec.components.schemas;

// ---------- minimal JSON Schema (OpenAPI 3.1 subset used by utoipa) ----------

function resolve(schema: Json): Json {
  const ref = schema.$ref;
  return typeof ref === 'string' ? resolve(schemas[ref.split('/').pop()!]) : schema;
}

function typeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

function violations(raw: Json, value: unknown, at = '$'): string[] {
  const schema = resolve(raw);
  if (Array.isArray(schema.allOf)) return (schema.allOf as Json[]).flatMap((part) => violations(part, value, at));
  if (Array.isArray(schema.oneOf)) {
    const passing = (schema.oneOf as Json[]).filter((part) => violations(part, value, at).length === 0);
    return passing.length === 1 ? [] : [`${at}: matches ${passing.length} oneOf branches`];
  }
  const out: string[] = [];
  if (schema.type !== undefined) {
    const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = typeOf(value);
    if (!allowed.includes(actual) && !(actual === 'integer' && allowed.includes('number'))) {
      return [`${at}: expected ${allowed.join('|')}, got ${actual}`];
    }
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) out.push(`${at}: not in enum`);
  if (typeof value === 'string' && schema.format === 'uuid' && !/^[0-9a-f-]{36}$/i.test(value)) out.push(`${at}: not a uuid`);
  if (typeof value === 'string' && schema.format === 'date-time' && Number.isNaN(Date.parse(value))) out.push(`${at}: not a date-time`);
  if (Array.isArray(value) && schema.items) value.forEach((item, i) => out.push(...violations(schema.items as Json, item, `${at}[${i}]`)));
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const record = value as Json;
    const properties = (schema.properties ?? {}) as Record<string, Json>;
    for (const key of (schema.required ?? []) as string[]) if (!(key in record)) out.push(`${at}.${key}: required`);
    for (const [key, item] of Object.entries(record)) {
      if (properties[key]) out.push(...violations(properties[key], item, `${at}.${key}`));
      else if (schema.additionalProperties === false) out.push(`${at}.${key}: not allowed`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        out.push(...violations(schema.additionalProperties as Json, item, `${at}.${key}`));
      }
    }
  }
  return out;
}

// ---------- route matching ----------

type Operation = { method: string; template: string; op: Json };
const OPERATIONS: Operation[] = Object.entries(spec.paths as Record<string, Json>).flatMap(([template, item]) =>
  Object.entries(item).map(([method, op]) => ({ method: method.toUpperCase(), template, op: op as Json })),
);

function operationFor(method: string, path: string): Operation | undefined {
  const same = OPERATIONS.filter((candidate) => candidate.method === method);
  // Literal segments (flows/validate) win over {id}.
  return (
    same.find((candidate) => candidate.template === path) ??
    same.find((candidate) => new RegExp(`^${candidate.template.replace(/\{[^}]+\}/g, '[^/]+')}$`).test(path))
  );
}

function queryParameterNames(operation: Operation): string[] {
  const placeholders = new Set([...operation.template.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]));
  // utoipa documents RunDetailQuery as `in: path` (it lacks
  // `parameter_in = Query`); anything that is not a template placeholder is a
  // query parameter on the wire, which is how axum's Query extractor reads it.
  return ((operation.op.parameters ?? []) as Json[])
    .filter((param) => param.in === 'query' || (param.in === 'path' && !placeholders.has(String(param.name))))
    .map((param) => String(param.name));
}

function successSchema(operation: Operation): Json | undefined {
  const responses = operation.op.responses as Record<string, Json>;
  const ok = Object.entries(responses).find(([status]) => status.startsWith('2'))?.[1];
  return (ok?.content as Record<string, Json> | undefined)?.['application/json']?.schema as Json | undefined;
}

// ---------- tool calls ----------

const ID = '00000000-0000-4000-8000-000000000011';
const SECRET = 'fixture-secret-value-0001';
const CALLS: Array<[string, Json, unknown]> = [
  ['get_soar_settings', {}, fixture.settings],
  ['list_soar_packs', {}, fixture.packs],
  ['get_soar_pack', { name: 'crowdstrike_falcon' }, fixture.pack],
  ['install_soar_pack', { name: 'okta', version: '1.2.0', user_confirmed: true }, fixture.packs],
  ['upgrade_soar_pack', { name: 'crowdstrike_falcon', version: '1.2.0', user_confirmed: true }, fixture.packs],
  ['remove_soar_pack', { name: 'okta', user_confirmed: true }, fixture.deleted],
  ['list_soar_connections', {}, fixture.connections],
  ['get_soar_connection', { connection_id: ID }, fixture.connection],
  [
    'create_soar_connection',
    { pack_name: 'crowdstrike_falcon', label: 'Falcon prod', config: { base_url: 'https://api.crowdstrike.com' }, credentials: { client_secret: SECRET }, user_confirmed: true },
    fixture.connection,
  ],
  ['update_soar_connection', { connection_id: ID, credentials: { client_secret: SECRET }, user_confirmed: true }, fixture.connection],
  ['test_soar_connection', { connection_id: ID, user_confirmed: true }, fixture.test_result],
  ['remove_soar_connection', { connection_id: ID, user_confirmed: true }, fixture.deleted],
  ['run_soar_action', { connection_id: ID, action: 'contain_host', inputs: { hostname: 'ws-eng-001' }, dry_run: true }, fixture.run],
  [
    'run_soar_action',
    { connection_id: ID, action: 'contain_host', inputs: { hostname: 'ws-eng-001' }, case_id: ID, user_confirmed: true },
    fixture.run,
  ],
  ['list_soar_flows', {}, fixture.flows],
  ['get_soar_flow', { flow_id: ID }, fixture.flow],
  ['validate_soar_flow', { definition: fixture.flow_definition }, fixture.flow_validation],
  ['create_soar_flow', { name: 'Contain host', definition: fixture.flow_definition, trigger: { on: 'manual' }, user_confirmed: true }, fixture.flow],
  [
    'update_soar_flow',
    { flow_id: ID, expected_version: 3, name: 'Contain host', definition: fixture.flow_definition, trigger: { on: 'alert', match: 'severity = high' }, status: 'draft', user_confirmed: true },
    fixture.flow,
  ],
  ['remove_soar_flow', { flow_id: ID, user_confirmed: true }, fixture.deleted],
  ['run_soar_flow', { flow_id: ID, inputs: { hostname: 'ws-eng-001' }, dry_run: true }, fixture.run],
  ['list_soar_runs', { limit: 10, offset: 20 }, fixture.runs],
  ['get_soar_run', { run_id: ID, steps_limit: 5, approvals_offset: 0 }, fixture.run_detail],
  ['cancel_soar_run', { run_id: ID, user_confirmed: true }, fixture.run],
  ['list_soar_approvals', { status: 'pending', limit: 5 }, fixture.approvals],
  ['get_soar_approval', { approval_id: ID }, fixture.approval],
];

/** Operations deliberately not exposed: they require an interactive human session. */
const HUMAN_ONLY = ['PUT /api/soar/settings', 'POST /api/soar/approvals/{id}/approve', 'POST /api/soar/approvals/{id}/reject'];

const client = new NanosiemClient({ apiUrl: 'https://us.nano.rs/t/fixture', apiKey: 'fixture-key' });
afterEach(() => vi.unstubAllGlobals());

async function capture(name: string, args: Json, response: unknown) {
  const sent: Array<{ method: string; path: string; query: URLSearchParams; body: unknown }> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      const parsed = new URL(url);
      sent.push({
        method: String(init.method),
        path: parsed.pathname.replace('/t/fixture', ''),
        query: parsed.searchParams,
        body: init.body ? JSON.parse(String(init.body)) : undefined,
      });
      // list_soar_actions also reads connections.
      const body = parsed.pathname.endsWith('/connections') ? fixture.connections : response;
      return new Response(JSON.stringify(body), { status: init.method === 'POST' && parsed.pathname.endsWith('/run') ? 202 : 200 });
    }),
  );
  const result = await handleSoarTool(name, args, client);
  return { sent, result };
}

describe('SOAR tools vs the tenant OpenAPI contract', () => {
  it('vendors the tenant SOAR surface and nothing from platform admin', () => {
    expect(Object.keys(spec.paths).every((path) => path.startsWith('/api/soar/'))).toBe(true);
    expect(OPERATIONS.length).toBe(28);
  });

  it.each(CALLS.map(([name, args, response], index) => [`${index}:${name}`, name, args, response] as const))(
    '%s sends a documented request and parses a schema-valid response',
    async (_label, name, args, response) => {
      const { sent, result } = await capture(name, args, response);
      expect(result.isError, result.content[0].text).not.toBe(true);
      expect(sent.length).toBeGreaterThan(0);
      for (const request of sent) {
        const operation = operationFor(request.method, request.path);
        expect(operation, `${request.method} ${request.path} is not in the spec`).toBeDefined();
        const allowedQuery = queryParameterNames(operation!);
        for (const key of request.query.keys()) expect(allowedQuery, `${operation!.template} ?${key}`).toContain(key);
        const bodySpec = operation!.op.requestBody as Json | undefined;
        if (bodySpec) {
          const schema = (bodySpec.content as Record<string, Json>)['application/json'].schema as Json;
          if (bodySpec.required) expect(request.body, `${operation!.template} requires a body`).toBeDefined();
          if (request.body !== undefined) expect(violations(schema, request.body)).toEqual([]);
        } else {
          expect(request.body, `${operation!.template} takes no body`).toBeUndefined();
        }
      }
      const operation = operationFor(sent[0].method, sent[0].path)!;
      expect(violations(successSchema(operation)!, response)).toEqual([]);
    },
  );

  it('covers every tenant operation except the human-session-only ones', async () => {
    const covered = new Set<string>();
    for (const [name, args, response] of CALLS) {
      const { sent } = await capture(name, args, response);
      for (const request of sent) {
        const operation = operationFor(request.method, request.path);
        if (operation) covered.add(`${operation.method} ${operation.template}`);
      }
    }
    const all = OPERATIONS.map((operation) => `${operation.method} ${operation.template}`);
    expect(all.filter((key) => !covered.has(key)).sort()).toEqual([...HUMAN_ONLY].sort());
    expect(TOOLS.map((tool) => tool.name).every((name) => CALLS.some(([called]) => called === name) || name === 'list_soar_actions')).toBe(true);
  });

  it('documents credentials as write-only and returns them from no operation', () => {
    expect(schemas.SoarCreateConnection.properties).toMatchObject({ credentials: { writeOnly: true } });
    expect(schemas.SoarUpdateConnection.properties).toMatchObject({ credentials: { writeOnly: true } });
    for (const operation of OPERATIONS) {
      const schema = successSchema(operation);
      if (schema) expect(JSON.stringify(resolveDeep(schema)), operation.template).not.toContain('"credentials"');
    }
  });

  it('matches the human-session and scope notes the tools rely on', () => {
    expect(spec.paths['/api/soar/settings'].put.description).toMatch(/Human tenant admin only/);
    expect(spec.paths['/api/soar/approvals/{id}/approve'].post.description).toMatch(/automation keys/);
    expect(schemas.SoarRunRequest.properties).toHaveProperty('dry_run');
    expect(schemas.RunFlow.properties).toHaveProperty('dry_run');
  });

  it.each([
    'getSoarSettings', 'listSoarPacks', 'getSoarPack', 'installSoarPack', 'upgradeSoarPack', 'removeSoarPack',
    'listSoarConnections', 'getSoarConnection', 'createSoarConnection', 'updateSoarConnection', 'removeSoarConnection',
    'testSoarConnection', 'queueSoarAction', 'listSoarRuns', 'getSoarRun', 'cancelSoarRun', 'listSoarFlows',
    'getSoarFlow', 'validateSoarFlow', 'createSoarFlow', 'updateSoarFlow', 'removeSoarFlow', 'queueSoarFlow',
    'listSoarApprovals', 'getSoarApproval',
  ])('NanosiemClient implements %s', (method) => {
    expect(typeof (NanosiemClient.prototype as unknown as Record<string, unknown>)[method]).toBe('function');
  });
});

function resolveDeep(schema: unknown, seen = new Set<string>()): unknown {
  if (Array.isArray(schema)) return schema.map((item) => resolveDeep(item, seen));
  if (!schema || typeof schema !== 'object') return schema;
  const record = schema as Json;
  if (typeof record.$ref === 'string') {
    const name = record.$ref.split('/').pop()!;
    if (seen.has(name)) return {};
    return resolveDeep(schemas[name], new Set([...seen, name]));
  }
  return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, resolveDeep(value, seen)]));
}

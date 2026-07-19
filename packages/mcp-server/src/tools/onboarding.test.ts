import { afterAll, beforeAll, describe, it, expect, vi } from 'vitest';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { NanosiemClient } from '@nano-rs/investigator-core';
import {
  handleOnboardingTool,
  resolveSafeCredentialPath,
  parseCredentialFile,
  TRANSPORT_REQUIREMENTS,
  TOOLS,
} from './onboarding.js';

function makeMockClient(overrides: Partial<NanosiemClient> = {}): NanosiemClient {
  return overrides as unknown as NanosiemClient;
}

const HOME = '/home/analyst';
const CWD = '/home/analyst/work';

// A minimal but valid GCP service-account key.
const GCP_KEY = JSON.stringify({
  type: 'service_account',
  project_id: 'acme-prod',
  private_key_id: 'abc',
  private_key: '-----BEGIN PRIVATE KEY-----\nMIIfake\n-----END PRIVATE KEY-----\n',
  client_email: 'ingest@acme-prod.iam.gserviceaccount.com',
});

describe('onboarding TOOLS registration', () => {
  const names = TOOLS.map((t) => t.name);

  it('registers the four onboarding tools', () => {
    for (const n of ['onboarding_requirements', 'import_credential_from_file', 'create_credential', 'create_source_config']) {
      expect(names).toContain(n);
    }
  });

  it('import_credential_from_file requires path + provider and only offers file-importable providers', () => {
    const tool = TOOLS.find((t) => t.name === 'import_credential_from_file')!;
    expect(tool.inputSchema.required).toEqual(['path', 'provider']);
    const providerEnum = (tool.inputSchema.properties.provider as { enum: string[] }).enum;
    expect(providerEnum).toEqual(['gcp_pubsub', 'aws_s3']);
  });

  it('create_source_config does NOT offer http/otlp (they need no transport)', () => {
    const tool = TOOLS.find((t) => t.name === 'create_source_config')!;
    const enumVals = (tool.inputSchema.properties.config_type as { enum: string[] }).enum;
    expect(enumVals).not.toContain('http');
    expect(enumVals).not.toContain('otlp');
  });

  it('every tool has a non-empty description and an object schema', () => {
    for (const t of TOOLS) {
      expect(t.description.length).toBeGreaterThan(0);
      expect(t.inputSchema.type).toBe('object');
    }
  });
});

describe('resolveSafeCredentialPath (sandbox)', () => {
  it('expands ~ to the home dir', () => {
    expect(resolveSafeCredentialPath('~/Documents/key.json', HOME, CWD)).toBe('/home/analyst/Documents/key.json');
  });

  it('accepts an absolute path inside home', () => {
    expect(resolveSafeCredentialPath('/home/analyst/Downloads/sa.json', HOME, CWD)).toBe('/home/analyst/Downloads/sa.json');
  });

  it('accepts a relative path (resolved under cwd)', () => {
    expect(resolveSafeCredentialPath('creds/aws.json', HOME, CWD)).toBe('/home/analyst/work/creds/aws.json');
  });

  it('rejects an absolute path outside the sandbox', () => {
    expect(() => resolveSafeCredentialPath('/etc/passwd', HOME, CWD)).toThrow(/must be inside/i);
  });

  it('rejects the prefix trap (/home/analyst-evil is not inside /home/analyst)', () => {
    expect(() => resolveSafeCredentialPath('/home/analyst-evil/key.json', HOME, CWD)).toThrow(/must be inside/i);
  });

  it('does NOT reject a directory merely named with a ".." prefix', () => {
    expect(resolveSafeCredentialPath('~/..config/key.json', HOME, CWD)).toBe('/home/analyst/..config/key.json');
  });

  it('rejects a ~-relative traversal that escapes home', () => {
    expect(() => resolveSafeCredentialPath('~/../../etc/shadow', HOME, CWD)).toThrow(/must be inside/i);
  });

  it('rejects an empty path', () => {
    expect(() => resolveSafeCredentialPath('   ', HOME, CWD)).toThrow(/required/i);
  });
});

describe('parseCredentialFile (shape validation)', () => {
  it('accepts a valid GCP service-account key and returns the raw JSON', () => {
    const secret = parseCredentialFile('gcp_pubsub', GCP_KEY) as { credentials_json: string };
    expect(secret.credentials_json).toBe(GCP_KEY);
  });

  it('rejects a non-service-account JSON for gcp_pubsub', () => {
    expect(() => parseCredentialFile('gcp_pubsub', JSON.stringify({ hello: 'world' }))).toThrow(/service-account/i);
  });

  it('rejects a private SSH key masquerading as a credential', () => {
    expect(() => parseCredentialFile('gcp_pubsub', '-----BEGIN OPENSSH PRIVATE KEY-----\n…')).toThrow(/not valid JSON/i);
  });

  it('accepts AWS keys and carries the optional session_token', () => {
    const secret = parseCredentialFile(
      'aws_s3',
      JSON.stringify({ access_key_id: 'AKIA...', secret_access_key: 'shh', session_token: 'tok' }),
    ) as { access_key_id: string; session_token?: string };
    expect(secret.access_key_id).toBe('AKIA...');
    expect(secret.session_token).toBe('tok');
  });

  it('rejects an AWS file missing the secret key', () => {
    expect(() => parseCredentialFile('aws_s3', JSON.stringify({ access_key_id: 'AKIA...' }))).toThrow(/AWS key file/i);
  });
});

describe('handleOnboardingTool dispatch', () => {
  it('onboarding_requirements(config_type) returns that transport with its fields', async () => {
    const result = await handleOnboardingTool('onboarding_requirements', { config_type: 'gcp_pubsub' }, makeMockClient());
    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed.config_type).toBe('gcp_pubsub');
    expect(parsed.requires_credential).toBe(true);
    expect(parsed.connection_config.map((f: { field: string }) => f.field)).toContain('subscription');
  });

  it('onboarding_requirements() lists every transport', async () => {
    const result = await handleOnboardingTool('onboarding_requirements', {}, makeMockClient());
    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed.map((r: { config_type: string }) => r.config_type)).toEqual(Object.keys(TRANSPORT_REQUIREMENTS));
  });

  it('create_source_config rejects a missing required field WITHOUT calling the API', async () => {
    const createSourceConfig = vi.fn();
    const client = makeMockClient({ createSourceConfig });
    const result = await handleOnboardingTool(
      'create_source_config',
      { name: 'gcp feed', config_type: 'gcp_pubsub', connection_config: { project: 'acme-prod' } }, // missing subscription
      client,
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/subscription/);
    expect(createSourceConfig).not.toHaveBeenCalled();
  });

  it('create_source_config treats an empty required array (kafka topics: []) as missing', async () => {
    const createSourceConfig = vi.fn();
    const client = makeMockClient({ createSourceConfig });
    const result = await handleOnboardingTool(
      'create_source_config',
      { name: 'k', config_type: 'kafka', connection_config: { bootstrap_servers: 'b:9092', topics: [] } },
      client,
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/topics/);
    expect(createSourceConfig).not.toHaveBeenCalled();
  });

  it('create_source_config builds the request (credential + routing) and advises deploy', async () => {
    const createSourceConfig = vi.fn().mockResolvedValue({
      success: true,
      data: { id: 'srcfg_1', name: 'gcp feed', config_type: 'gcp_pubsub', deployed: false },
    });
    const client = makeMockClient({ createSourceConfig });
    const result = await handleOnboardingTool(
      'create_source_config',
      {
        name: 'gcp feed',
        config_type: 'gcp_pubsub',
        connection_config: { project: 'acme-prod', subscription: 'logs-sub' },
        credential_id: 'cred_1',
        routing_rules: [{ match_field: 'subscription', match_type: 'exact', match_value: 'logs-sub', target_source_type: 'acme_pubsub' }],
      },
      client,
    );
    expect(createSourceConfig).toHaveBeenCalledWith({
      name: 'gcp feed',
      config_type: 'gcp_pubsub',
      connection_config: { project: 'acme-prod', subscription: 'logs-sub' },
      credential_id: 'cred_1',
      routing_rules: [{ match_field: 'subscription', match_type: 'exact', match_value: 'logs-sub', target_source_type: 'acme_pubsub' }],
    });
    expect(JSON.parse(result.content[0].text as string).note).toMatch(/deploy_source_config/);
  });

  it('create_source_config refuses http (no transport needed)', async () => {
    const result = await handleOnboardingTool('create_source_config', { name: 'x', config_type: 'http', connection_config: {} }, makeMockClient());
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/routed/i);
  });

  it('create_credential stores the secret and returns only metadata + id', async () => {
    const createCredential = vi.fn().mockResolvedValue({
      success: true,
      data: { id: 'cred_9', name: 'prod-aws', provider: 'aws_s3' },
    });
    const client = makeMockClient({ createCredential });
    const result = await handleOnboardingTool(
      'create_credential',
      { name: 'prod-aws', provider: 'aws_s3', credentials: { access_key_id: 'AKIA', secret_access_key: 'shh' } },
      client,
    );
    const parsed = JSON.parse(result.content[0].text as string);
    expect(parsed.credential_id).toBe('cred_9');
    // The secret must never be echoed back.
    expect(result.content[0].text).not.toContain('shh');
  });

  it('import_credential_from_file rejects an out-of-sandbox path without touching the API', async () => {
    const createCredential = vi.fn();
    const client = makeMockClient({ createCredential });
    const result = await handleOnboardingTool(
      'import_credential_from_file',
      { path: '/etc/passwd', provider: 'gcp_pubsub' },
      client,
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/must be inside/i);
    expect(createCredential).not.toHaveBeenCalled();
  });

  it('surfaces the API error message on failure', async () => {
    const createCredential = vi.fn().mockResolvedValue({
      success: false,
      error: { code: 'HTTP_403', message: 'Missing permission: credentials:create' },
    });
    const client = makeMockClient({ createCredential });
    const result = await handleOnboardingTool(
      'create_credential',
      { name: 'x', provider: 'kafka', credentials: { sasl_username: 'u' } },
      client,
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Missing permission');
  });

  it('returns an error for an unknown tool name', async () => {
    const result = await handleOnboardingTool('nope', {}, makeMockClient());
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Unknown onboarding tool');
  });
});

// Exercises the real fs path — the realpath/symlink defense that the pure
// resolveSafeCredentialPath unit tests can't reach. Fixtures live UNDER the test
// process's cwd (an allowed sandbox root); the escape target lives in the OS temp
// dir (outside home + cwd).
describe('import_credential_from_file (filesystem)', () => {
  let sandbox: string; // under cwd → inside the sandbox
  let outside: string; // in tmpdir → outside the sandbox

  beforeAll(() => {
    sandbox = mkdtempSync(join(process.cwd(), 'onbtest-'));
    outside = mkdtempSync(join(tmpdir(), 'onbtest-escape-'));
  });
  afterAll(() => {
    rmSync(sandbox, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });

  it('reads a real key inside the sandbox, submits the secret, and never echoes it', async () => {
    const keyPath = join(sandbox, 'sa.json');
    writeFileSync(keyPath, GCP_KEY);
    const createCredential = vi.fn().mockResolvedValue({
      success: true,
      data: { id: 'cred_fs', name: 'gcp_pubsub-sa', provider: 'gcp_pubsub' },
    });
    const client = makeMockClient({ createCredential });

    const result = await handleOnboardingTool('import_credential_from_file', { path: keyPath, provider: 'gcp_pubsub' }, client);

    // The raw key reached the API...
    expect(createCredential).toHaveBeenCalledTimes(1);
    const submitted = createCredential.mock.calls[0][0] as { credentials: { credentials_json: string } };
    expect(submitted.credentials.credentials_json).toBe(GCP_KEY);
    // ...but the tool output carries only the id/metadata, never the secret.
    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text as string).credential_id).toBe('cred_fs');
    expect(result.content[0].text).not.toContain('private_key');
  });

  it('refuses a symlink whose target escapes the sandbox, without calling the API', async () => {
    const target = join(outside, 'stolen.json');
    writeFileSync(target, GCP_KEY);
    const link = join(sandbox, 'evil.json');
    symlinkSync(target, link);
    const createCredential = vi.fn();
    const client = makeMockClient({ createCredential });

    const result = await handleOnboardingTool('import_credential_from_file', { path: link, provider: 'gcp_pubsub' }, client);

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/symlink/i);
    expect(createCredential).not.toHaveBeenCalled();
  });

  it('reports a clear error for a path that does not exist', async () => {
    const result = await handleOnboardingTool(
      'import_credential_from_file',
      { path: join(sandbox, 'nope.json'), provider: 'gcp_pubsub' },
      makeMockClient({ createCredential: vi.fn() }),
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/not found/i);
  });
});

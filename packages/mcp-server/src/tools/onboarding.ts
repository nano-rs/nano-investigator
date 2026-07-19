/**
 * Source-onboarding tools — the "walk me through it" half of standing up a new
 * log feed. pivt runs the interview (which transport? what params? where's the
 * key?), and these tools do the privileged work: mint the credential, create the
 * ingress transport, and (via the parser tools) wire + deploy the parser.
 *
 * SECURITY — `import_credential_from_file` is the ONE tool here that touches the
 * local disk, so it is written to be safe in pivt's Locked (injection-exposed)
 * mode:
 *   1. The path is resolved (~ expanded, then canonicalized via realpath) and
 *      REQUIRED to sit inside the user's home directory or the working directory.
 *      A path escaping those (…/../../etc/…, an absolute /etc/…, or a symlink
 *      pointing out) is rejected before the file is stored.
 *   2. The file is size-capped and must PARSE as the declared provider's expected
 *      shape (a GCP key must be a service_account JSON with a private_key). A file
 *      that isn't a credential of that provider simply fails — you can't smuggle
 *      /etc/passwd or an SSH key in as a "credential".
 *   3. The secret goes straight from disk to POST /api/credentials — the tool
 *      returns ONLY the resulting credential_id/metadata, never the secret. It
 *      never enters the model's context.
 * Everything else (create_source_config, create_credential) is an authenticated
 * API write gated by the minted key's scope + audit, exactly like the parser
 * tools. Creating credentials / source configs requires admin-level scope.
 */

import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, relative, resolve, sep } from 'node:path';

import type {
  NanosiemClient,
  NewCredential,
  NewSourceConfiguration,
  NewRoutingRule,
  CredentialSecret,
  AwsS3CredentialSecret,
} from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

/** Providers that carry a stored secret (HTTP / HEC / Vector / OTLP don't). */
const CREDENTIAL_PROVIDERS = ['gcp_pubsub', 'aws_s3', 'kafka'] as const;
type CredentialProvider = (typeof CREDENTIAL_PROVIDERS)[number];

/** Providers whose secret can be imported from a single file on disk. */
const FILE_IMPORT_PROVIDERS = ['gcp_pubsub', 'aws_s3'] as const;

const CONFIG_TYPES = ['http', 'kafka', 'aws_s3', 'gcp_pubsub', 'splunk_hec', 'vector', 'otlp'] as const;

/** SA keys are ~2 KB; 1 MiB is a generous ceiling that still refuses giant files. */
const MAX_CREDENTIAL_FILE_BYTES = 1024 * 1024;

interface TransportRequirement {
  label: string;
  requires_credential: boolean;
  credential_provider?: CredentialProvider;
  connection_config: { field: string; required: boolean; description: string }[];
  /** The routing match_field convention for this transport (NAN-1084). */
  match_field: string;
  notes: string;
}

/**
 * Per-transport onboarding requirements: the connection_config fields to ask for
 * (and which are required), whether a stored credential is needed, and the
 * routing match_field convention. This is what lets pivt ask exactly the right
 * questions per transport instead of guessing.
 */
export const TRANSPORT_REQUIREMENTS: Record<string, TransportRequirement> = {
  gcp_pubsub: {
    label: 'GCP Pub/Sub',
    requires_credential: true,
    credential_provider: 'gcp_pubsub',
    connection_config: [
      { field: 'project', required: true, description: 'GCP project id.' },
      { field: 'subscription', required: true, description: 'Pub/Sub subscription id (the id, not the full projects/…/subscriptions/… path).' },
      { field: 'ack_deadline_secs', required: false, description: 'Ack deadline seconds (default 600).' },
    ],
    match_field: 'subscription',
    notes: 'Credential = a service-account JSON key. Point import_credential_from_file at the key file (provider "gcp_pubsub").',
  },
  kafka: {
    label: 'Kafka',
    // SASL/TLS is optional — Kafka can be reached unauthenticated.
    requires_credential: false,
    credential_provider: 'kafka',
    connection_config: [
      { field: 'bootstrap_servers', required: true, description: 'Comma-separated brokers, e.g. "b1:9092,b2:9092".' },
      { field: 'topics', required: true, description: 'Array of topic names to consume.' },
      { field: 'group_id', required: false, description: 'Consumer group id (auto-generated if unset).' },
      { field: 'auto_offset_reset', required: false, description: '"latest" (default) or "earliest".' },
    ],
    match_field: 'topic',
    notes: 'Add a credential only if the brokers use SASL/TLS — create_credential with provider "kafka".',
  },
  aws_s3: {
    label: 'AWS S3 (via SQS)',
    requires_credential: true,
    credential_provider: 'aws_s3',
    connection_config: [
      { field: 'sqs_queue_url', required: true, description: 'SQS queue URL receiving the S3 object-created notifications.' },
      { field: 'region', required: false, description: 'AWS region (default us-east-1).' },
      { field: 'compression', required: false, description: '"auto" (default), "gzip", "zstd", or "none".' },
      { field: 'endpoint', required: false, description: 'Custom S3-compatible endpoint (MinIO etc.).' },
    ],
    match_field: 'bucket',
    notes: 'Credential = AWS access keys. Use import_credential_from_file with a JSON key file (provider "aws_s3"), or create_credential.',
  },
  splunk_hec: {
    label: 'Splunk HEC',
    requires_credential: false,
    connection_config: [],
    match_field: 'sourcetype',
    notes: 'No connection_config and NO credential — served by the shared :8088 listener with VECTOR_AUTH_TOKEN. Single-instance (one HEC config per deployment).',
  },
  http: {
    label: 'HTTP (routed)',
    requires_credential: false,
    connection_config: [],
    match_field: 'source_type',
    notes: 'The default. No transport to create — routed feeds arrive on the shared HTTP endpoint keyed by the X-Source-Type header. Just create + deploy the parser (source_type "routed") with match_values.',
  },
  vector: {
    label: 'Vector',
    requires_credential: false,
    connection_config: [
      { field: 'address', required: false, description: 'Listen address (default 0.0.0.0:6000).' },
      { field: 'version', required: false, description: 'Vector protocol version "2" (default) or "1".' },
    ],
    match_field: 'source_type',
    notes: 'Vector-to-Vector forwarding; secured with mTLS, not a stored credential.',
  },
  otlp: {
    label: 'OTLP',
    requires_credential: false,
    connection_config: [],
    match_field: 'source_type',
    notes: 'Single shared OTLP listener — already present, no transport to create.',
  },
};

export const TOOLS = [
  {
    name: 'onboarding_requirements',
    description:
      'What a transport needs to be onboarded: the connection_config fields to collect (and which are required), whether a stored credential is needed, and the routing match_field convention. Call this FIRST when a user wants to onboard a feed, so you ask exactly the right questions for their transport. Omit config_type to list all transports.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        config_type: {
          type: 'string',
          enum: [...CONFIG_TYPES],
          description: 'Transport to describe (e.g. "gcp_pubsub"). Omit for all.',
        },
      },
    },
  },
  {
    name: 'import_credential_from_file',
    description:
      "Read a credential file off the LOCAL disk (e.g. a GCP service-account JSON key the user points you at, like ~/Documents/key.json) and store it as an encrypted credential — WITHOUT the secret ever passing through this conversation. The file must sit inside the user's home directory or the working directory, and must parse as the declared provider's shape (gcp_pubsub → a service_account JSON with a private_key; aws_s3 → JSON with access_key_id + secret_access_key). Returns only a credential_id to reference from create_source_config. Requires credentials:create (admin).",
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: "Local filesystem path to the credential file (a leading ~ expands to home). Must resolve inside the user's home directory or the working directory.",
        },
        provider: {
          type: 'string',
          enum: [...FILE_IMPORT_PROVIDERS],
          description: 'Which transport the credential is for. gcp_pubsub = a service-account JSON key; aws_s3 = a JSON file with access_key_id + secret_access_key.',
        },
        name: { type: 'string', description: 'A name for the stored credential (defaults from the provider + file name).' },
      },
      required: ['path', 'provider'],
    },
  },
  {
    name: 'create_credential',
    description:
      'Store a cloud credential from values the user gives you in chat (NOT from a file — use import_credential_from_file for a GCP key on disk). Use for AWS keys or Kafka SASL typed directly. The secret is encrypted server-side; only metadata is returned. Requires credentials:create (admin).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'A name for the stored credential.' },
        provider: { type: 'string', enum: [...CREDENTIAL_PROVIDERS], description: 'Credential provider.' },
        credentials: {
          type: 'object',
          description:
            'Provider secret. aws_s3 → {access_key_id, secret_access_key, session_token?, assume_role_arn?}; gcp_pubsub → {credentials_json}; kafka → {sasl_mechanism?, sasl_username?, sasl_password?, tls_enabled?, tls_ca_cert?}.',
        },
        description: { type: 'string' },
        region: { type: 'string', description: 'AWS region, for aws_s3.' },
      },
      required: ['name', 'provider', 'credentials'],
    },
  },
  {
    name: 'create_source_config',
    description:
      'Create an ingress transport (source configuration) — the connection a pull source (Kafka / S3 / Pub-Sub) or HEC arrives on. Pass connection_config per onboarding_requirements, a credential_id (from import_credential_from_file / create_credential) for credentialed transports, and optionally routing_rules to map incoming events to a parser source_type in the same call. NOT deployed — call deploy_source_config after. HTTP/routed needs no source config; just create + deploy the parser.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'A name for the transport.' },
        config_type: {
          type: 'string',
          enum: ['kafka', 'aws_s3', 'gcp_pubsub', 'splunk_hec', 'vector'],
          description: 'Transport driver.',
        },
        connection_config: {
          type: 'object',
          description: 'Transport-specific settings (see onboarding_requirements). {} for splunk_hec.',
        },
        credential_id: { type: 'string', description: 'Stored credential id, for kafka / aws_s3 / gcp_pubsub.' },
        default_source_type: {
          type: 'string',
          description: 'Fallback source_type for pull-source events matching no routing rule.',
        },
        routing_rules: {
          type: 'array',
          description: 'Optional routing rules to create with the transport. Each maps matching events to a parser source_type.',
          items: {
            type: 'object',
            properties: {
              match_field: { type: 'string' },
              match_type: { type: 'string', enum: ['exact', 'prefix', 'suffix', 'regex', 'contains', 'default'] },
              match_value: { type: 'string' },
              target_source_type: { type: 'string' },
              priority: { type: 'number' },
            },
            required: ['match_field', 'match_type', 'target_source_type'],
          },
        },
      },
      required: ['name', 'config_type', 'connection_config'],
    },
  },
];

// ── Security helpers (exported for unit testing) ─────────────────────────────

/** Is `abs` (an absolute path) contained within one of the allowed roots? */
function isInsideRoots(abs: string, home: string, cwd: string): boolean {
  return [home, cwd].some((root) => {
    const rel = relative(root, abs);
    // rel === '' → abs IS the root. A real '..' segment (exactly '..' or a
    // leading '../') means abs escapes the root; guard on the separator so a
    // directory merely NAMED '..config' isn't wrongly rejected.
    return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel));
  });
}

/**
 * Expand `~`, resolve to an absolute path, and REFUSE anything outside the home
 * dir or cwd. Throws with a user-facing reason. Pure (no fs) so the sandbox rule
 * is unit-testable; the caller additionally realpath-checks to defeat symlinks.
 */
export function resolveSafeCredentialPath(rawPath: string, home = homedir(), cwd = process.cwd()): string {
  const input = String(rawPath ?? '').trim();
  if (!input) throw new Error('A file `path` is required.');
  const expanded = input === '~' ? home : input.startsWith('~/') ? resolve(home, input.slice(2)) : input;
  const abs = resolve(cwd, expanded);
  if (!isInsideRoots(abs, home, cwd)) {
    throw new Error(
      `Refusing to read \`${abs}\` — credential files must be inside your home directory or the working directory.`,
    );
  }
  return abs;
}

/**
 * Parse + shape-validate a credential file's contents for a provider. Throws
 * (with a user-facing reason) if it isn't a credential of that provider — this
 * is what stops a random file (an SSH key, /etc/passwd) being stored as a
 * "credential".
 */
export function parseCredentialFile(provider: string, contents: string): CredentialSecret {
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(contents) as Record<string, unknown>;
  } catch {
    throw new Error('File is not valid JSON — expected a JSON credential file.');
  }

  if (provider === 'gcp_pubsub') {
    if (json.type !== 'service_account' || typeof json.private_key !== 'string' || typeof json.project_id !== 'string') {
      throw new Error('Not a GCP service-account key (expected JSON with type "service_account", a private_key, and a project_id).');
    }
    return { credentials_json: contents };
  }

  if (provider === 'aws_s3') {
    const accessKeyId = json.access_key_id ?? json.AccessKeyId ?? json.aws_access_key_id;
    const secretAccessKey = json.secret_access_key ?? json.SecretAccessKey ?? json.aws_secret_access_key;
    if (typeof accessKeyId !== 'string' || typeof secretAccessKey !== 'string') {
      throw new Error('Not an AWS key file (expected JSON with access_key_id and secret_access_key).');
    }
    const secret: AwsS3CredentialSecret = { access_key_id: accessKeyId, secret_access_key: secretAccessKey };
    if (typeof json.session_token === 'string') secret.session_token = json.session_token;
    if (typeof json.assume_role_arn === 'string') secret.assume_role_arn = json.assume_role_arn;
    return secret;
  }

  throw new Error(`import_credential_from_file supports provider "gcp_pubsub" or "aws_s3"; got "${provider}".`);
}

function defaultCredentialName(provider: string, filePath: string): string {
  return `${provider}-${basename(filePath).replace(/\.[^.]+$/, '')}`;
}

export async function handleOnboardingTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient,
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'onboarding_requirements': {
        const configType = args.config_type as string | undefined;
        if (configType) {
          const req = TRANSPORT_REQUIREMENTS[configType];
          if (!req) {
            return err(`Unknown transport "${configType}". Known: ${Object.keys(TRANSPORT_REQUIREMENTS).join(', ')}.`);
          }
          return ok({ config_type: configType, ...req });
        }
        return ok(Object.entries(TRANSPORT_REQUIREMENTS).map(([config_type, r]) => ({ config_type, ...r })));
      }

      case 'import_credential_from_file': {
        const provider = String(args.provider ?? '');
        if (provider !== 'gcp_pubsub' && provider !== 'aws_s3') {
          return err('`provider` must be "gcp_pubsub" or "aws_s3" for a file import.');
        }

        let safePath: string;
        try {
          safePath = resolveSafeCredentialPath(args.path as string);
        } catch (e) {
          return err(e instanceof Error ? e.message : String(e));
        }

        // realpath defeats a symlink whose target escapes the sandbox.
        let realPath: string;
        try {
          realPath = await fs.realpath(safePath);
        } catch {
          return err(`File not found: ${safePath}`);
        }
        // Compare the canonical target against CANONICAL roots — on macOS the
        // home/cwd may themselves contain a symlinked segment (/tmp→/private/tmp),
        // which would otherwise false-reject a legitimate in-home file.
        const realHome = await fs.realpath(homedir()).catch(() => homedir());
        const realCwd = await fs.realpath(process.cwd()).catch(() => process.cwd());
        if (!isInsideRoots(realPath, realHome, realCwd)) {
          return err('Refusing to follow a symlink that escapes your home/working directory.');
        }

        const stat = await fs.stat(realPath);
        if (!stat.isFile()) return err(`Not a file: ${realPath}`);
        if (stat.size > MAX_CREDENTIAL_FILE_BYTES) {
          return err(`Credential file is too large (${stat.size} bytes; max ${MAX_CREDENTIAL_FILE_BYTES}).`);
        }

        const contents = await fs.readFile(realPath, 'utf8');
        let secret: CredentialSecret;
        try {
          secret = parseCredentialFile(provider, contents);
        } catch (e) {
          return err(e instanceof Error ? e.message : String(e));
        }

        const req: NewCredential = {
          name: (args.name as string) || defaultCredentialName(provider, realPath),
          provider,
          credentials: secret,
        };
        const res = await client.createCredential(req);
        if (!res.success) return err(res.error?.message ?? 'Failed to store credential');
        // Metadata only — the secret never leaves this function.
        return ok({
          credential_id: res.data?.id,
          name: res.data?.name,
          provider: res.data?.provider,
          note: `Stored the ${provider} credential from ${basename(realPath)} (encrypted server-side; the secret was not exposed). Reference it as credential_id in create_source_config.`,
        });
      }

      case 'create_credential': {
        const provider = String(args.provider ?? '');
        if (!CREDENTIAL_PROVIDERS.includes(provider as CredentialProvider)) {
          return err(`\`provider\` must be one of: ${CREDENTIAL_PROVIDERS.join(', ')}.`);
        }
        const credentials = args.credentials;
        if (!credentials || typeof credentials !== 'object') {
          return err('`credentials` must be an object with the provider secret fields.');
        }
        const req: NewCredential = {
          name: args.name as string,
          provider,
          credentials: credentials as CredentialSecret,
        };
        if (args.description !== undefined) req.description = args.description as string;
        if (args.region !== undefined) req.region = args.region as string;
        const res = await client.createCredential(req);
        if (!res.success) return err(res.error?.message ?? 'Failed to store credential');
        return ok({
          credential_id: res.data?.id,
          name: res.data?.name,
          provider: res.data?.provider,
          note: 'Credential stored (encrypted). Reference it as credential_id in create_source_config.',
        });
      }

      case 'create_source_config': {
        const configType = String(args.config_type ?? '');
        if (configType === 'http' || configType === 'otlp') {
          return err(
            configType === 'http'
              ? '"http" needs no transport — routed feeds arrive on the shared HTTP endpoint. Just create + deploy the parser (source_type "routed") with match_values.'
              : '"otlp" is a single shared listener that already exists — no transport to create.',
          );
        }
        const requirements = TRANSPORT_REQUIREMENTS[configType];
        if (!requirements) {
          return err(`Unknown config_type "${configType}". Call onboarding_requirements to see the transports.`);
        }
        const connectionConfig = (args.connection_config as Record<string, unknown>) ?? {};
        // Fail HERE with a clear message on a missing required field, rather than
        // at deploy time inside Vector.
        const missing = requirements.connection_config
          .filter((f) => {
            if (!f.required) return false;
            const v = connectionConfig[f.field];
            return v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0);
          })
          .map((f) => f.field);
        if (missing.length) {
          return err(
            `Missing required ${requirements.label} field(s): ${missing.join(', ')}. Call onboarding_requirements("${configType}") for the full list.`,
          );
        }

        const req: NewSourceConfiguration = {
          name: args.name as string,
          config_type: configType,
          connection_config: connectionConfig,
        };
        if (args.credential_id !== undefined) req.credential_id = args.credential_id as string;
        if (args.default_source_type !== undefined) req.default_source_type = args.default_source_type as string;
        if (Array.isArray(args.routing_rules)) {
          req.routing_rules = (args.routing_rules as Record<string, unknown>[]).map((r) => {
            const rule: NewRoutingRule = {
              match_field: r.match_field as string,
              match_type: r.match_type as string,
              target_source_type: r.target_source_type as string,
            };
            if (r.match_value !== undefined) rule.match_value = r.match_value as string;
            if (r.priority !== undefined) rule.priority = r.priority as number;
            return rule;
          });
        }

        const res = await client.createSourceConfig(req);
        if (!res.success) return err(res.error?.message ?? 'Failed to create source config');
        return ok({
          ...res.data,
          note: 'Transport created but NOT deployed. Call deploy_source_config with the returned id, then create + deploy the routed parser (create_log_source / import_parser with dispatch_source_config_id + match_values, then deploy_log_source), and confirm with get_log_source_health.',
        });
      }

      default:
        return err(`Unknown onboarding tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

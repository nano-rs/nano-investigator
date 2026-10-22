/**
 * SOAR tools (NAN-4375) — build and run tenant automation without the UI.
 *
 * One tool per tenant `/api/soar/*` route (contract:
 * packages/core/src/fixtures/soar-openapi.json), plus `list_soar_actions`,
 * which flattens the action catalog the packs response already carries.
 *
 * Safety model:
 * - Reads are safe. Writes and external side effects refuse without
 *   `user_confirmed: true` (see TOOL_CONFIRMATIONS in tool-permissions.ts).
 *   Action and flow runs accept `dry_run: true` instead: the executor renders
 *   every request but sends nothing.
 * - Connection credentials are write-only. The API never returns them; these
 *   tools additionally drop credential-shaped keys from every output, scrub
 *   the values supplied in this call from any text (including errors), and
 *   never log arguments.
 * - Not exposed: enabling SOAR (`PUT /api/soar/settings`) and deciding
 *   approvals (`/approve`, `/reject`). The API accepts those from interactive
 *   human sessions only; an agent API key is refused by design.
 */

import type { NanosiemClient, ApiResponse, SoarPack } from '@nano-rs/investigator-core';
import type { ToolResult } from './utils.js';
import { redact } from './redaction.js';
import { missingConfirmation } from '../tool-permissions.js';

type Schema = Record<string, unknown>;
type Properties = Record<string, Schema>;

const UUID_PATTERN = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
const uuid = (description: string): Schema => ({ type: 'string', pattern: UUID_PATTERN, description });
const packName: Schema = {
  type: 'string',
  pattern: '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$',
  description: 'Pack name from list_soar_packs (e.g. "crowdstrike_falcon")',
};
const version: Schema = { type: 'string', minLength: 1, maxLength: 64, description: 'Catalog version from list_soar_packs / get_soar_pack' };
const confirmed: Schema = {
  type: 'boolean',
  const: true,
  description: 'Set to true ONLY after the user explicitly approved this exact change in the conversation.',
};
const object = (description: string, maxBytes: number): Schema => ({ type: 'object', description, 'x-max-bytes': maxBytes });
const page = (max: number, description: string): Schema => ({ type: 'integer', minimum: 1, maximum: max, description });
const offset: Schema = { type: 'integer', minimum: 0, maximum: 100000, description: 'Rows to skip (default 0)' };
const caseId = uuid('Optional case to link. The run posts its result to that case wall; needs cases:view and cases:comment.');
const flowStatus: Schema = {
  type: 'string',
  enum: ['draft', 'live', 'archived'],
  description: 'draft = editable, runnable only as a dry run; live = ARMED: alert/case/schedule triggers start runs automatically; archived = retired',
};
const trigger: Schema = {
  type: 'object',
  description:
    'When the flow runs: {"on":"manual"} | {"on":"alert","match":"<when clause>"} | {"on":"case","match":"<when clause>"} | {"on":"schedule","cron":"<cron>"}',
  properties: {
    on: { type: 'string', enum: ['manual', 'alert', 'case', 'schedule'] },
    match: { type: 'string', maxLength: 4096 },
    cron: { type: 'string', maxLength: 256 },
  },
  required: ['on'],
  additionalProperties: false,
};
const definition = object(
  'Flow document: {"summary": str, "description"?: str, "value": {"modules": [...]}}. Module value types: action {pack, action, connection (connection id), input_transforms {name: {"type":"static","value":…}|{"type":"expr","expr":"flow_input.x"}}, approval default|required|auto}, branchone, branchall, forloopflow, approval, identity. Max 64 modules, depth 4, 1 MiB. Read the soar_workflow prompt for examples.',
  1024 * 1024,
);
const actionInputs = object('Action inputs as named by list_soar_actions (inputs[].name). Static values only; no secrets.', 64 * 1024);

interface Definition {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Properties; required: string[]; additionalProperties: false };
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
}

function tool(
  name: string,
  description: string,
  properties: Properties,
  required: string[],
  kind: 'read' | 'write' | 'destructive' | 'external' = 'read',
): Definition {
  return {
    name,
    description,
    inputSchema: { type: 'object', properties, required, additionalProperties: false },
    annotations: {
      readOnlyHint: kind === 'read',
      destructiveHint: kind === 'destructive' || kind === 'external',
      idempotentHint: kind === 'read',
      openWorldHint: kind === 'external' || name === 'test_soar_connection',
    },
  };
}

export const TOOLS: Definition[] = [
  // ---------- Settings ----------
  tool(
    'get_soar_settings',
    'Read whether SOAR is enabled for this workspace (and its settings revision). Call first: while disabled, packs, connections, actions and flows return "not enabled" but run and approval history stay readable. Enabling is a human tenant-admin action in nano Settings; API keys cannot enable SOAR.',
    {},
    [],
  ),

  // ---------- Catalog / packs ----------
  tool(
    'list_soar_packs',
    'Browse the signed SOAR catalog visible to this workspace: integration packs with vendor, categories, catalog version, installed/enabled state, upgrade availability and action counts. Use get_soar_pack for config fields, credential fields and actions.',
    {
      installed_only: { type: 'boolean', description: 'Only installed packs (default false)' },
      search: { type: 'string', maxLength: 128, description: 'Case-insensitive match on name, display name, vendor, category or description' },
      include_withdrawn: { type: 'boolean', description: 'Include packs withdrawn from the catalog (default false; installed packs are always shown)' },
    },
    [],
  ),
  tool(
    'get_soar_pack',
    'Read one pack in full: config_fields, credential_fields (names and whether each is configured — never values), actions with inputs/effect/approval policy, test_action, rate limits and signed provenance.',
    { name: packName },
    ['name'],
  ),
  tool(
    'install_soar_pack',
    'WRITE: install a catalog pack version into this workspace so connections can be created for it. Requires explicit user confirmation (user_confirmed=true).',
    { name: packName, version, user_confirmed: confirmed },
    ['name', 'version', 'user_confirmed'],
    'write',
  ),
  tool(
    'upgrade_soar_pack',
    'WRITE: move an installed pack to a newer catalog version. Read the pack change_summary and tell the user what changes (actions, inputs, approval policy) before asking. Requires user_confirmed=true.',
    { name: packName, version, user_confirmed: confirmed },
    ['name', 'version', 'user_confirmed'],
    'write',
  ),
  tool(
    'remove_soar_pack',
    'DESTRUCTIVE WRITE: uninstall a pack. Refused while connections or flows still depend on it. Requires user_confirmed=true.',
    { name: packName, user_confirmed: confirmed },
    ['name', 'user_confirmed'],
    'destructive',
  ),

  // ---------- Actions ----------
  tool(
    'list_soar_actions',
    'List runnable actions: for each (installed) pack, its actions with inputs, effect, approval policy and idempotency, plus the connections that can run them (id, label, ready). Use this to pick connection_id + action for run_soar_action, or pack/action/connection for a flow module.',
    {
      pack_name: { ...packName, description: 'Only this pack' },
      installed_only: { type: 'boolean', description: 'Only installed packs (default true)' },
    },
    [],
  ),

  // ---------- Connections ----------
  tool(
    'list_soar_connections',
    'List configured connections: pack, label, readiness, which credential fields are configured (never values), last test status and active run count. While SOAR is off, soar:manage holders see sanitized cleanup metadata only.',
    { pack_name: { ...packName, description: 'Only connections for this pack' } },
    [],
  ),
  tool(
    'get_soar_connection',
    'Read one connection: config, credential field status (configured or not — values are write-only and never returned), readiness, last test and active runs.',
    { connection_id: uuid('Connection id from list_soar_connections') },
    ['connection_id'],
  ),
  tool(
    'create_soar_connection',
    'WRITE: create a connection for an installed pack. config holds non-secret settings named by the pack config_fields; credentials holds the secrets named by credential_fields. Credentials are write-only: they are sent once, stored encrypted, and never returned or repeated by this tool. Ask the user to provide them; never invent, echo or summarize credential values. Requires user_confirmed=true.',
    {
      pack_name: packName,
      label: { type: 'string', minLength: 1, maxLength: 256, description: 'Human label, e.g. "Okta prod"' },
      config: object('Non-secret settings keyed by config_fields[].name', 64 * 1024),
      credentials: {
        type: 'object',
        writeOnly: true,
        additionalProperties: { type: 'string', maxLength: 16384 },
        description: 'WRITE-ONLY secrets keyed by credential_fields[].name',
      },
      user_confirmed: confirmed,
    },
    ['pack_name', 'label', 'config', 'credentials', 'user_confirmed'],
    'write',
  ),
  tool(
    'update_soar_connection',
    'WRITE: change a connection label, config or credentials (rotation). Omitted credential fields keep their stored values; an empty string removes an optional credential. Credential values are write-only and never returned. Requires user_confirmed=true.',
    {
      connection_id: uuid('Connection id'),
      label: { type: 'string', minLength: 1, maxLength: 256 },
      config: object('Replacement non-secret settings keyed by config_fields[].name', 64 * 1024),
      credentials: {
        type: 'object',
        writeOnly: true,
        additionalProperties: { type: 'string', maxLength: 16384 },
        description: 'WRITE-ONLY secrets to set or rotate, keyed by credential_fields[].name',
      },
      user_confirmed: confirmed,
    },
    ['connection_id', 'user_confirmed'],
    'write',
  ),
  tool(
    'test_soar_connection',
    "WRITE: run the pack's read-only test action against the vendor with the stored credentials (bounded at 20 s) and record the result on the connection. Contacts the external system. Requires user_confirmed=true.",
    {
      connection_id: uuid('Connection id'),
      inputs: object('Optional inputs for the pack test_action', 64 * 1024),
      user_confirmed: confirmed,
    },
    ['connection_id', 'user_confirmed'],
    'write',
  ),
  tool(
    'remove_soar_connection',
    'DESTRUCTIVE WRITE: delete a connection and its stored credentials. Refused while runs are queued or active on it (see can_delete/active_runs). Requires user_confirmed=true.',
    { connection_id: uuid('Connection id'), user_confirmed: confirmed },
    ['connection_id', 'user_confirmed'],
    'destructive',
  ),

  // ---------- Action runs ----------
  tool(
    'run_soar_action',
    'MUTATING / EXTERNAL SIDE EFFECT: queue one pack action on a connection (e.g. contain a host, disable a user). Always do a dry run first (dry_run=true: requests are rendered, approvals skipped, nothing is sent) and show the user the rendered result from get_soar_run. A live run requires user_confirmed=true after the user approves the exact action, connection and inputs. Actions whose policy requires approval wait for a human approver in nano; this tool cannot approve. Returns the queued run; poll get_soar_run for steps and outputs.',
    {
      connection_id: uuid('Connection id from list_soar_actions'),
      action: { type: 'string', minLength: 1, maxLength: 128, description: 'Action name from list_soar_actions' },
      inputs: actionInputs,
      case_id: caseId,
      dry_run: { type: 'boolean', description: 'Render without sending (default false). No confirmation needed.' },
      user_confirmed: confirmed,
    },
    ['connection_id', 'action', 'inputs'],
    'external',
  ),

  // ---------- Flows (playbooks) ----------
  tool(
    'list_soar_flows',
    'List automation flows (playbooks): name, version, status (draft/live/archived), trigger and next scheduled run, plus event overflow and admission backpressure.',
    {},
    [],
  ),
  tool(
    'get_soar_flow',
    'Read one flow with its full definition and trigger. Use version as expected_version when updating.',
    { flow_id: uuid('Flow id from list_soar_flows') },
    ['flow_id'],
  ),
  tool(
    'validate_soar_flow',
    'Validate a flow definition against the bounded flow grammar and current packs/connections without saving it. Returns valid, module count and a summary. Safe: persists nothing. Validate before create_soar_flow / update_soar_flow.',
    { definition },
    ['definition'],
  ),
  tool(
    'create_soar_flow',
    'WRITE: save a new flow. Default status is draft (no trigger fires; only dry runs). status=live ARMS the trigger: alert, case and schedule triggers then start real runs with external side effects without further confirmation, so say so when asking. Requires user_confirmed=true.',
    {
      name: { type: 'string', minLength: 1, maxLength: 256 },
      definition,
      trigger,
      status: flowStatus,
      user_confirmed: confirmed,
    },
    ['name', 'definition', 'trigger', 'user_confirmed'],
    'write',
  ),
  tool(
    'update_soar_flow',
    'WRITE: replace a flow (name, definition, trigger, status) guarded by expected_version from get_soar_flow; a conflict means it changed — reload. Moving to live ARMS automatic triggers. Requires user_confirmed=true.',
    {
      flow_id: uuid('Flow id'),
      expected_version: { type: 'integer', minimum: 1, description: 'Current version from get_soar_flow' },
      name: { type: 'string', minLength: 1, maxLength: 256 },
      definition,
      trigger,
      status: flowStatus,
      user_confirmed: confirmed,
    },
    ['flow_id', 'expected_version', 'name', 'definition', 'trigger', 'status', 'user_confirmed'],
    'write',
  ),
  tool(
    'remove_soar_flow',
    'DESTRUCTIVE WRITE: delete a flow. Refused while it has active runs. Requires user_confirmed=true.',
    { flow_id: uuid('Flow id'), user_confirmed: confirmed },
    ['flow_id', 'user_confirmed'],
    'destructive',
  ),
  tool(
    'run_soar_flow',
    'MUTATING / EXTERNAL SIDE EFFECT: start a flow manually. Draft flows run only with dry_run=true. Dry-run first (approvals skipped, nothing sent) and review get_soar_run with the user; a live run requires user_confirmed=true. Approval modules pause for a human approver in nano. Returns the queued run.',
    {
      flow_id: uuid('Flow id'),
      inputs: object('Flow input, available to expressions as flow_input.*', 64 * 1024),
      case_id: caseId,
      dry_run: { type: 'boolean', description: 'Render without sending (default false). No confirmation needed.' },
      user_confirmed: confirmed,
    },
    ['flow_id', 'inputs'],
    'external',
  ),

  // ---------- Run history / audit ----------
  tool(
    'list_soar_runs',
    'Run history, newest first: action or flow, trigger (manual/alert/case/schedule/ai), status, dry_run, approval requirement, requester, case link, timing and error class. Case-linked runs appear only with cases:view.',
    { limit: page(100, 'Rows (1-100, default 50)'), offset },
    [],
  ),
  tool(
    'get_soar_run',
    'One run in detail: inputs, outputs, every step execution (attempt, status, sanitized request summary, outputs, error class) and its approvals, paged. This is the per-run audit record; workspace-wide SOAR audit events are in get_audit_trail with resource_type "soar".',
    {
      run_id: uuid('Run id'),
      steps_limit: page(100, 'Step rows (default 50)'),
      steps_offset: offset,
      approvals_limit: page(100, 'Approval rows (default 50)'),
      approvals_offset: offset,
    },
    ['run_id'],
  ),
  tool(
    'cancel_soar_run',
    'WRITE: cancel a queued, waiting or running run. Steps already sent to a vendor cannot be recalled and are marked ambiguous. Requires user_confirmed=true.',
    { run_id: uuid('Run id'), user_confirmed: confirmed },
    ['run_id', 'user_confirmed'],
    'write',
  ),
  tool(
    'list_soar_approvals',
    'List approval requests (default pending): requested action, run, requester, expiry and decision. Decisions are made by a human approver in nano; agents cannot approve or reject.',
    {
      status: { type: 'string', enum: ['pending', 'approved', 'rejected', 'expired', 'canceled'] },
      limit: page(100, 'Rows (1-100, default 50)'),
      offset,
    },
    [],
  ),
  tool(
    'get_soar_approval',
    'Read one approval request and its decision.',
    { approval_id: uuid('Approval id') },
    ['approval_id'],
  ),
];

/** Read tools only — for clients that pre-approve this server's tools wholesale. */
export const SOAR_READ_TOOLS = TOOLS.filter((entry) => entry.annotations.readOnlyHint).map((entry) => entry.name);

// ==================== Validation ====================

function invalidArgument(definition: Definition, args: Record<string, unknown>): string | undefined {
  const { properties, required } = definition.inputSchema;
  for (const key of Object.keys(args)) if (!Object.hasOwn(properties, key)) return `Unsupported argument: ${key}`;
  // A missing user_confirmed is answered by missingConfirmation(), which tells the agent what to do.
  for (const key of required) if (key !== 'user_confirmed' && args[key] === undefined) return `Missing ${key}`;
  for (const [key, value] of Object.entries(args)) {
    if (value === undefined) continue;
    const problem = invalidValue(properties[key], value);
    if (problem) return `Invalid ${key}: ${problem}`;
  }
  return undefined;
}

function invalidValue(schema: Schema, value: unknown): string | undefined {
  switch (schema.type) {
    case 'string': {
      if (typeof value !== 'string') return 'expected a string';
      if (typeof schema.minLength === 'number' && value.length < schema.minLength) return 'too short';
      if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) return 'too long';
      if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern).test(value)) return 'unexpected format';
      if (Array.isArray(schema.enum) && !schema.enum.includes(value)) return `expected one of ${schema.enum.join(', ')}`;
      return undefined;
    }
    case 'boolean':
      if (typeof value !== 'boolean') return 'expected a boolean';
      if (schema.const !== undefined && value !== schema.const) return `must be ${String(schema.const)}`;
      return undefined;
    case 'integer':
      if (!Number.isSafeInteger(value)) return 'expected an integer';
      if (typeof schema.minimum === 'number' && (value as number) < schema.minimum) return `minimum ${schema.minimum}`;
      if (typeof schema.maximum === 'number' && (value as number) > schema.maximum) return `maximum ${schema.maximum}`;
      return undefined;
    case 'object': {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return 'expected an object';
      const max = schema['x-max-bytes'];
      if (typeof max === 'number' && Buffer.byteLength(JSON.stringify(value)) > max) return `exceeds ${max} bytes`;
      const record = value as Record<string, unknown>;
      if (schema.properties) {
        const nested: Definition = {
          name: '',
          description: '',
          inputSchema: {
            type: 'object',
            properties: schema.properties as Properties,
            required: (schema.required as string[]) ?? [],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        };
        return invalidArgument(nested, record);
      }
      const values = schema.additionalProperties as Schema | undefined;
      if (values) {
        const entries = Object.entries(record);
        if (entries.length > 32) return 'too many fields';
        for (const [name, item] of entries) {
          if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name)) return 'unexpected field name';
          if (invalidValue(values, item)) return `field ${name} must be a string within limits`;
        }
      }
      return undefined;
    }
    default:
      return undefined;
  }
}

// ==================== Output ====================

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

/** Values supplied in this call that must never appear in any output. */
function secretValues(args: Record<string, unknown>): string[] {
  const credentials = args.credentials;
  if (!credentials || typeof credentials !== 'object') return [];
  return Object.values(credentials as Record<string, unknown>).filter(
    (value): value is string => typeof value === 'string' && value.length >= 4,
  );
}

function scrub(text: string, secrets: string[]): string {
  let out = text;
  for (const secret of secrets) out = out.split(secret).join('[REDACTED]');
  return out;
}

/**
 * Documents an agent reads and may write back: a flow's definition/trigger and
 * a connection's non-secret config (secrets live in credentials, which no
 * response carries). Their keys are kept intact; strings are still scrubbed.
 */
const ROUND_TRIP_KEYS: ReadonlySet<string> = new Set(['definition', 'trigger', 'config']);

function respond(value: unknown, secrets: string[]): ToolResult {
  const text = scrub(JSON.stringify(redact(value, 0, ROUND_TRIP_KEYS), null, 2), secrets);
  if (Buffer.byteLength(text, 'utf8') > MAX_OUTPUT_BYTES) {
    return failure('SOAR result exceeds 2 MiB. Narrow it (filters, a single pack, smaller pages).', secrets);
  }
  return { content: [{ type: 'text', text }] };
}

function failure(message: string, secrets: string[]): ToolResult {
  return { content: [{ type: 'text', text: `Error: ${scrub(message, secrets)}` }], isError: true };
}

function hint(error: ApiResponse<unknown>['error']): string {
  const message = error?.message ?? 'SOAR request failed';
  if (/feature not enabled/i.test(message)) {
    return `${message}. SOAR is disabled for this workspace; a human tenant admin enables it in nano Settings (get_soar_settings shows the state).`;
  }
  if (/entitlement required/i.test(message)) return `${message}. This workspace's plan does not include SOAR.`;
  if (/human session/i.test(message)) return `${message}. Only an interactive human user can do this in nano.`;
  return message;
}

class SoarCallError extends Error {}

async function unwrap<T>(call: Promise<ApiResponse<T>>): Promise<T> {
  const res = await call;
  if (!res.success) throw new SoarCallError(hint(res.error));
  return res.data as T;
}

function packSummary(pack: SoarPack) {
  return {
    name: pack.name,
    display_name: pack.display_name,
    vendor: pack.vendor,
    categories: pack.categories,
    description: pack.description.length > 300 ? `${pack.description.slice(0, 297)}...` : pack.description,
    version: pack.version,
    installed: pack.installed,
    installed_version: pack.installed_version ?? null,
    upgrade_available: Boolean(pack.installed && pack.installed_version && pack.installed_version !== pack.version),
    enabled: pack.enabled,
    withdrawn: pack.withdrawn,
    availability: pack.availability,
    origin: pack.origin,
    action_count: pack.actions.length,
    test_action: pack.test_action ?? null,
  };
}

function matches(pack: SoarPack, search: string): boolean {
  const needle = search.toLowerCase();
  return [pack.name, pack.display_name, pack.vendor, pack.description, ...pack.categories].some((field) =>
    field.toLowerCase().includes(needle),
  );
}

const QUEUED_NOTE = 'Queued. Poll get_soar_run for steps and outputs.';

// ==================== Handler ====================

export async function handleSoarTool(
  name: string,
  rawArgs: Record<string, unknown>,
  client: NanosiemClient,
): Promise<ToolResult> {
  const args = rawArgs ?? {};
  const secrets = secretValues(args);
  const definition = TOOLS.find((entry) => entry.name === name);
  if (!definition) return failure(`Unknown SOAR tool: ${name}`, secrets);
  const invalid = invalidArgument(definition, args);
  if (invalid) return failure(invalid, secrets);
  const unconfirmed = missingConfirmation(name, args);
  if (unconfirmed) return failure(unconfirmed, secrets);

  const str = (key: string) => args[key] as string;
  const num = (key: string) => args[key] as number | undefined;
  const obj = (key: string) => args[key] as Record<string, unknown>;

  try {
    switch (name) {
      case 'get_soar_settings': {
        const settings = await unwrap(client.getSoarSettings());
        return respond(
          settings.soar_enabled
            ? settings
            : {
                ...settings,
                note: 'SOAR is disabled. A human tenant admin enables it in nano Settings (settings:system plus the SOAR entitlement); API keys cannot. Run and approval history stay readable.',
              },
          secrets,
        );
      }

      case 'list_soar_packs': {
        const catalog = await unwrap(client.listSoarPacks());
        const packs = catalog.packs
          .filter((pack) => (args.installed_only === true ? pack.installed : true))
          .filter((pack) => (args.include_withdrawn === true || pack.installed ? true : !pack.withdrawn))
          .filter((pack) => (typeof args.search === 'string' && args.search ? matches(pack, args.search) : true))
          .map(packSummary);
        return respond(
          {
            catalog_status: catalog.catalog_status,
            catalog_expires_at: catalog.catalog_expires_at ?? null,
            total: catalog.packs.length,
            returned: packs.length,
            packs,
          },
          secrets,
        );
      }

      case 'get_soar_pack': {
        const result = await unwrap(client.getSoarPack(str('name')));
        const pack = result.packs.find((entry) => entry.name === str('name')) ?? result.packs[0];
        if (!pack) return failure('Pack not found', secrets);
        return respond({ catalog_status: result.catalog_status, pack }, secrets);
      }

      case 'install_soar_pack':
      case 'upgrade_soar_pack': {
        const call = name === 'install_soar_pack' ? client.installSoarPack : client.upgradeSoarPack;
        const result = await unwrap(call.call(client, str('name'), str('version')));
        const pack = result.packs.find((entry) => entry.name === str('name'));
        return respond(
          {
            pack: pack ? packSummary(pack) : null,
            next: 'Create a connection with create_soar_connection (see get_soar_pack config_fields/credential_fields), then test_soar_connection.',
          },
          secrets,
        );
      }

      case 'remove_soar_pack':
        return respond(await unwrap(client.removeSoarPack(str('name'))), secrets);

      case 'list_soar_actions': {
        const installedOnly = args.installed_only !== false;
        const packName = typeof args.pack_name === 'string' ? args.pack_name : undefined;
        const [catalog, connections] = await Promise.all([
          unwrap(packName ? client.getSoarPack(packName) : client.listSoarPacks()),
          client.listSoarConnections(),
        ]);
        const available = connections.success ? connections.data?.connections ?? [] : undefined;
        const packs = catalog.packs
          .filter((pack) => (packName ? pack.name === packName : true))
          .filter((pack) => (installedOnly ? pack.installed : true))
          .map((pack) => ({
            pack_name: pack.name,
            pack_version: pack.installed_version ?? pack.version,
            installed: pack.installed,
            enabled: pack.enabled,
            test_action: pack.test_action ?? null,
            rate_limit: { per_minute: pack.per_minute, per_day: pack.per_day },
            connections: available
              ? available
                  .filter((connection) => connection.pack_name === pack.name)
                  .map((connection) => ({ id: connection.id, label: connection.label, ready: connection.ready }))
              : 'unavailable (needs soar:view on connections)',
            actions: pack.actions,
          }));
        return respond({ packs }, secrets);
      }

      case 'list_soar_connections': {
        const result = await unwrap(client.listSoarConnections());
        const connections =
          typeof args.pack_name === 'string'
            ? result.connections.filter((connection) => connection.pack_name === args.pack_name)
            : result.connections;
        return respond({ connections }, secrets);
      }

      case 'get_soar_connection':
        return respond(await unwrap(client.getSoarConnection(str('connection_id'))), secrets);

      case 'create_soar_connection': {
        const connection = await unwrap(
          client.createSoarConnection({
            pack_name: str('pack_name'),
            label: str('label'),
            config: obj('config'),
            credentials: obj('credentials') as Record<string, string>,
          }),
        );
        return respond(
          { connection, next: connection.ready ? 'Run test_soar_connection (with user confirmation) to verify vendor access.' : 'Not ready: required config or credential fields are missing (see credential_fields[].configured).' },
          secrets,
        );
      }

      case 'update_soar_connection': {
        if (args.label === undefined && args.config === undefined && args.credentials === undefined) {
          return failure('Provide at least one of label, config or credentials', secrets);
        }
        return respond(
          await unwrap(
            client.updateSoarConnection(str('connection_id'), {
              ...(args.label !== undefined ? { label: str('label') } : {}),
              ...(args.config !== undefined ? { config: obj('config') } : {}),
              ...(args.credentials !== undefined ? { credentials: obj('credentials') as Record<string, string> } : {}),
            }),
          ),
          secrets,
        );
      }

      case 'test_soar_connection':
        return respond(
          await unwrap(client.testSoarConnection(str('connection_id'), (args.inputs as Record<string, unknown>) ?? {})),
          secrets,
        );

      case 'remove_soar_connection':
        return respond(await unwrap(client.removeSoarConnection(str('connection_id'))), secrets);

      case 'run_soar_action': {
        const run = await unwrap(
          client.queueSoarAction({
            connection_id: str('connection_id'),
            action: str('action'),
            inputs: obj('inputs'),
            ...(args.case_id !== undefined ? { case_id: str('case_id') } : {}),
            dry_run: args.dry_run === true,
          }),
        );
        return respond({ run, note: runNote(run.dry_run, run.approval_required) }, secrets);
      }

      case 'list_soar_flows':
        return respond(await unwrap(client.listSoarFlows()), secrets);

      case 'get_soar_flow':
        return respond(await unwrap(client.getSoarFlow(str('flow_id'))), secrets);

      case 'validate_soar_flow':
        return respond(await unwrap(client.validateSoarFlow(obj('definition'))), secrets);

      case 'create_soar_flow':
        return respond(
          await unwrap(
            client.createSoarFlow({
              name: str('name'),
              definition: obj('definition'),
              trigger: obj('trigger') as never,
              ...(args.status !== undefined ? { status: str('status') as never } : {}),
            }),
          ),
          secrets,
        );

      case 'update_soar_flow':
        return respond(
          await unwrap(
            client.updateSoarFlow(str('flow_id'), {
              expected_version: num('expected_version') as number,
              name: str('name'),
              definition: obj('definition'),
              trigger: obj('trigger') as never,
              status: str('status') as never,
            }),
          ),
          secrets,
        );

      case 'remove_soar_flow':
        return respond(await unwrap(client.removeSoarFlow(str('flow_id'))), secrets);

      case 'run_soar_flow': {
        const run = await unwrap(
          client.queueSoarFlow(str('flow_id'), {
            inputs: obj('inputs'),
            ...(args.case_id !== undefined ? { case_id: str('case_id') } : {}),
            dry_run: args.dry_run === true,
          }),
        );
        return respond({ run, note: runNote(run.dry_run, run.approval_required) }, secrets);
      }

      case 'list_soar_runs':
        return respond(await unwrap(client.listSoarRuns({ limit: num('limit'), offset: num('offset') })), secrets);

      case 'get_soar_run':
        return respond(
          await unwrap(
            client.getSoarRun(str('run_id'), {
              steps_limit: num('steps_limit'),
              steps_offset: num('steps_offset'),
              approvals_limit: num('approvals_limit'),
              approvals_offset: num('approvals_offset'),
            }),
          ),
          secrets,
        );

      case 'cancel_soar_run':
        return respond(await unwrap(client.cancelSoarRun(str('run_id'))), secrets);

      case 'list_soar_approvals':
        return respond(
          await unwrap(
            client.listSoarApprovals({
              status: args.status as never,
              limit: num('limit'),
              offset: num('offset'),
            }),
          ),
          secrets,
        );

      case 'get_soar_approval':
        return respond(await unwrap(client.getSoarApproval(str('approval_id'))), secrets);

      default:
        return failure(`Unknown SOAR tool: ${name}`, secrets);
    }
  } catch (error) {
    // Never echo arguments; the message is the API's (or ours), scrubbed.
    return failure(error instanceof SoarCallError ? error.message : 'SOAR request failed', secrets);
  }
}

function runNote(dryRun: boolean, approvalRequired: boolean): string {
  if (dryRun) return `Dry run: requests are rendered, approvals skipped, nothing is sent. ${QUEUED_NOTE} Show the user the rendered steps before any live run.`;
  if (approvalRequired) return `${QUEUED_NOTE} This run waits for a human approver in nano (list_soar_approvals); agents cannot approve.`;
  return QUEUED_NOTE;
}

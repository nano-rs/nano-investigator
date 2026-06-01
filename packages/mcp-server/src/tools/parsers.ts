/**
 * Parser authoring tools — build, validate, test, save, and deploy log-source
 * parsers (Vector VRL) without the web UI.
 *
 * These are the open-edition equivalent of the meloD parser wizard: Claude
 * writes the VRL itself (steered by the `nanosiem://reference/vrl-parsers`
 * resource), then validates → tests → saves → deploys → confirms flow through
 * these tools. No Enterprise / AI-credit dependency.
 *
 * The canonical authoring loop (see the `build_parser` prompt):
 *   1. get_source_types / list_log_sources — see what already exists
 *   2. write VRL (read the vrl-parsers reference first)
 *   3. validate_vrl — compile-check
 *   4. test_parse_sample — run against a real sample line, inspect UDM output
 *   5. create_log_source — save as a draft (NOT deployed)
 *   6. deploy_log_source — push to Vector
 *   7. get_log_source_health — confirm events are actually flowing
 */

import type {
  NanosiemClient,
  NewLogSource,
  UpdateLogSource,
  TestVrlRequest,
  TestVrlLiveRequest,
  NewRoutingRule,
  CheckReachabilityRequest,
  ImportParserRequest,
} from '@nano-investigator/core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  // ---- Discover ---------------------------------------------------------
  {
    name: 'list_log_sources',
    description:
      'List all log-source parsers. Returns a summary (id, name, source_type, deployed/validated/enabled, kind). Optionally filter. Use get_log_source for the full parser_vrl and metadata.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        source_type: { type: 'string', description: 'Filter to one source_type (case-insensitive).' },
        deployed: { type: 'boolean', description: 'Filter by deployed status.' },
        enabled: { type: 'boolean', description: 'Filter by enabled status.' },
        kind: { type: 'string', enum: ['log', 'enrichment'], description: 'Filter by parser kind.' },
      },
    },
  },
  {
    name: 'get_log_source',
    description:
      'Get one log source in full — including parser_vrl, source_config, match criteria, validated/deployed flags, and timestamps. Use before update_log_source so you edit against the current VRL.',
    inputSchema: {
      type: 'object' as const,
      properties: { id: { type: 'string', description: 'Log source id (typeid, e.g. "logsource_...").' } },
      required: ['id'],
    },
  },
  // ---- Author / validate / test ----------------------------------------
  {
    name: 'validate_vrl',
    description:
      'Compile-check VRL without saving. Returns { valid, errors, diagnostics } where diagnostics carry line/col + a code (e.g. E651, E203). ALWAYS run this until valid before saving. Read the nanosiem://reference/vrl-parsers resource first to avoid the common compiler errors.',
    inputSchema: {
      type: 'object' as const,
      properties: { vrl_code: { type: 'string', description: 'The complete VRL parser source.' } },
      required: ['vrl_code'],
    },
  },
  {
    name: 'test_parse_sample',
    description:
      'Run VRL against ONE sample log line and return the parsed output { success, output, extracted_field_count, error }. Inspect `output.udm.*` to confirm fields mapped correctly. Iterate validate_vrl + test_parse_sample until the UDM mapping is right, THEN save.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vrl_code: { type: 'string', description: 'The VRL parser source.' },
        sample_log: { type: 'string', description: 'A single raw log line to parse (goes in .message).' },
        extension_vrl: { type: 'string', description: 'Optional parser-extension VRL chained after vrl_code.' },
      },
      required: ['vrl_code', 'sample_log'],
    },
  },
  {
    name: 'test_parse_live',
    description:
      'Test VRL against real recent events for an already-ingested source_type (pulled from ClickHouse), comparing the new parse against the currently deployed one. Use this when refining a parser for a source_type that is already flowing. Capped at 20 events.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vrl_code: { type: 'string', description: 'The new/edited VRL to test.' },
        source_type: { type: 'string', description: 'Source type whose live events to pull.' },
        current_vrl: { type: 'string', description: 'Currently deployed VRL, for side-by-side comparison.' },
        limit: { type: 'number', description: 'Events to test (default 10, max 20).' },
      },
      required: ['vrl_code', 'source_type'],
    },
  },
  // ---- Persist ----------------------------------------------------------
  {
    name: 'create_log_source',
    description:
      'Save a new parser as a DRAFT (validated server-side, NOT deployed — call deploy_log_source after). Only `name`, `source_type`, and `parser_vrl` are required. For a routed/HTTP source you can omit source_config (defaults to {}).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Human-readable parser name.' },
        source_type: {
          type: 'string',
          description: 'The source_type this parser claims (e.g. "apache_http_server"). Routing delivers matching events here.',
        },
        parser_vrl: { type: 'string', description: 'The complete, validated VRL parser source.' },
        description: { type: 'string' },
        namespace: { type: 'string', description: 'Identity-resolution namespace. Defaults to "default".' },
        timezone: { type: 'string', description: 'IANA timezone for offset-less timestamps. Defaults to "UTC".' },
        category: {
          type: 'string',
          enum: ['network', 'endpoint', 'cloud', 'application', 'security', 'system', 'identity', 'other'],
        },
        vendor: { type: 'string' },
        product: { type: 'string' },
        source_config: { type: 'object', description: 'Transport-specific config. Omit for routed/HTTP (defaults to {}).' },
      },
      required: ['name', 'source_type', 'parser_vrl'],
    },
  },
  {
    name: 'update_log_source',
    description:
      'Update an existing parser. Only the fields you pass change; everything else is left alone. Editing parser_vrl does NOT auto-deploy — call deploy_log_source after. Fetch get_log_source first to edit against current state.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'string', description: 'Log source id (typeid).' },
        name: { type: 'string' },
        description: { type: 'string' },
        parser_vrl: { type: 'string' },
        source_type: { type: 'string' },
        namespace: { type: 'string' },
        timezone: { type: 'string' },
        category: { type: 'string' },
        vendor: { type: 'string' },
        product: { type: 'string' },
        enabled: { type: 'boolean' },
      },
      required: ['id'],
    },
  },
  // ---- Deploy / lifecycle ----------------------------------------------
  {
    name: 'deploy_log_source',
    description:
      'Deploy a saved parser to Vector (writes config + triggers reload). IMPORTANT: this is best-effort — it can report success even if Vector did not reload. After deploying, wait ~1 minute then call get_log_source_health to confirm events are actually flowing before telling the user it is live.',
    inputSchema: {
      type: 'object' as const,
      properties: { id: { type: 'string', description: 'Log source id (typeid).' } },
      required: ['id'],
    },
  },
  {
    name: 'undeploy_log_source',
    description: 'Take a deployed parser offline (removes it from the running Vector config).',
    inputSchema: {
      type: 'object' as const,
      properties: { id: { type: 'string', description: 'Log source id (typeid).' } },
      required: ['id'],
    },
  },
  {
    name: 'get_log_source_health',
    description:
      'Health metrics for a parser: total/24h/last-hour event counts, last_event_at, freshness, parse_errors_24h, and a health_status (healthy | stale | no_data | disabled | error). The honest way to confirm a deploy actually worked.',
    inputSchema: {
      type: 'object' as const,
      properties: { id: { type: 'string', description: 'Log source id (typeid).' } },
      required: ['id'],
    },
  },
  {
    name: 'get_log_source_deployments',
    description: 'Deployment history for a parser (deploy/undeploy actions, status, error_message). Use to diagnose a failed or silent deploy.',
    inputSchema: {
      type: 'object' as const,
      properties: { id: { type: 'string', description: 'Log source id (typeid).' } },
      required: ['id'],
    },
  },
  // ---- Ingress wiring (source configs + routing rules) ------------------
  {
    name: 'list_source_config_types',
    description:
      'List the available ingress transport drivers (HTTP, Kafka, AWS S3, GCP Pub/Sub, Splunk HEC, Vector) with their match_field presets and whether they need credentials. Use to understand how events reach a parser before adding routing rules.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'list_source_configs',
    description: 'List configured ingress transports (the connections events arrive on). Each carries routing rules that map events to a parser source_type.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        config_type: { type: 'string', description: 'Filter by driver (http, kafka, aws_s3, gcp_pubsub, splunk_hec, vector).' },
        enabled: { type: 'boolean' },
      },
    },
  },
  {
    name: 'create_routing_rule',
    description:
      'Add a routing rule to a source configuration so matching events activate a parser. The rule maps a match_field/match_type/match_value to a target_source_type (which must equal a parser\'s source_type). Tip: run check_rule_reachability first.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        source_config_id: { type: 'string', description: 'Source configuration id (typeid).' },
        match_field: { type: 'string', description: 'Field to match on (e.g. "source_type", "topic", "sourcetype"). See list_source_config_types for presets.' },
        match_type: { type: 'string', enum: ['exact', 'prefix', 'suffix', 'regex', 'contains', 'default'] },
        match_value: { type: 'string', description: 'Value to match (omit for match_type "default").' },
        target_source_type: { type: 'string', description: 'Parser source_type to route matching events to.' },
        priority: { type: 'number', description: 'Lower = evaluated first. Optional.' },
      },
      required: ['source_config_id', 'match_field', 'match_type', 'target_source_type'],
    },
  },
  {
    name: 'check_rule_reachability',
    description:
      'Verify a candidate routing rule can actually deliver events to a parser before you create it: checks the source config is enabled + deployed, a parser exists for target_source_type, and (for Kafka) that a broker is reachable. Returns warnings explaining any gap.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        source_config_id: { type: 'string', description: 'Source configuration id (typeid).' },
        target_source_type: { type: 'string' },
        match_field: { type: 'string' },
        match_type: { type: 'string', enum: ['exact', 'prefix', 'suffix', 'regex', 'contains', 'default'] },
        match_value: { type: 'string' },
      },
      required: ['source_config_id', 'target_source_type', 'match_field', 'match_type', 'match_value'],
    },
  },
  // ---- Parser library (upstream repos) ----------------------------------
  {
    name: 'list_parser_repositories',
    description: 'List connected parser repositories (upstream libraries of prebuilt parsers, e.g. nano-rs/parsers). Returns sync status and parser_count per repo.',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'sync_parser_repository',
    description: 'Pull the latest parsers from an upstream repository into the local cache (async — returns immediately). Run before list_repository_parsers if the cache is stale.',
    inputSchema: {
      type: 'object' as const,
      properties: { repository_id: { type: 'string', description: 'Parser repository id (typeid).' } },
      required: ['repository_id'],
    },
  },
  {
    name: 'list_repository_parsers',
    description: 'Browse the prebuilt parsers available in a repository. Returns a summary per parser (path, name, category, vendor/product, whether already imported). Import one with import_parser.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repository_id: { type: 'string', description: 'Parser repository id (typeid).' },
        category: { type: 'string', description: 'Filter by category.' },
        search: { type: 'string', description: 'Filter by name/description substring.' },
      },
      required: ['repository_id'],
    },
  },
  {
    name: 'import_parser',
    description:
      'Import a prebuilt parser from a repository as a DRAFT log source (not deployed). "linked" (default) tracks upstream updates; "forked" detaches a private copy. After import, deploy_log_source to activate it.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repository_id: { type: 'string', description: 'Parser repository id (typeid).' },
        path: { type: 'string', description: 'File path of the parser within the repo (from list_repository_parsers).' },
        source_type: { type: 'string', description: 'Override the source_type the parser claims (e.g. "apache"). Optional.' },
        import_type: { type: 'string', enum: ['linked', 'forked'], description: 'Defaults to "linked".' },
        ingestion_method: { type: 'string', enum: ['routed', 'kafka', 'aws_s3', 'gcp_pubsub', 'splunk_hec', 'vector'] },
      },
      required: ['repository_id', 'path'],
    },
  },
];

/** Build a NewLogSource from loosely-typed tool args. */
function buildNewLogSource(args: Record<string, unknown>): NewLogSource {
  const req: NewLogSource = {
    name: args.name as string,
    source_type: args.source_type as string,
    parser_vrl: args.parser_vrl as string,
  };
  if (args.description !== undefined) req.description = args.description as string;
  if (args.namespace !== undefined) req.namespace = args.namespace as string;
  if (args.timezone !== undefined) req.timezone = args.timezone as string;
  if (args.category !== undefined) req.category = args.category as string;
  if (args.vendor !== undefined) req.vendor = args.vendor as string;
  if (args.product !== undefined) req.product = args.product as string;
  if (args.source_config !== undefined) req.source_config = args.source_config as Record<string, unknown>;
  return req;
}

/** Build an UpdateLogSource from loosely-typed tool args (id excluded). */
function buildUpdateLogSource(args: Record<string, unknown>): UpdateLogSource {
  const req: UpdateLogSource = {};
  const fields = ['name', 'description', 'parser_vrl', 'source_type', 'namespace', 'timezone', 'category', 'vendor', 'product'] as const;
  for (const f of fields) {
    if (args[f] !== undefined) (req as Record<string, unknown>)[f] = args[f];
  }
  if (args.enabled !== undefined) req.enabled = args.enabled as boolean;
  return req;
}

export async function handleParsersTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'list_log_sources': {
        const res = await client.listLogSources();
        if (!res.success) return err(res.error?.message ?? 'Failed to list log sources');
        let sources = res.data ?? [];
        if (args.source_type) {
          const want = (args.source_type as string).toLowerCase();
          sources = sources.filter((s) => s.source_type.toLowerCase() === want);
        }
        if (args.deployed !== undefined) sources = sources.filter((s) => s.deployed === args.deployed);
        if (args.enabled !== undefined) sources = sources.filter((s) => s.enabled === args.enabled);
        if (args.kind) sources = sources.filter((s) => s.kind === args.kind);
        const summary = sources.map((s) => ({
          id: s.id,
          name: s.name,
          source_type: s.source_type,
          kind: s.kind,
          deployed: s.deployed,
          validated: s.validated,
          enabled: s.enabled,
          description: s.description,
        }));
        return ok(summary);
      }

      case 'get_log_source': {
        const res = await client.getLogSource(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to get log source');
        return ok(res.data);
      }

      case 'validate_vrl': {
        const res = await client.validateVrl(args.vrl_code as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to validate VRL');
        return ok(res.data);
      }

      case 'test_parse_sample': {
        const req: TestVrlRequest = {
          vrl_code: args.vrl_code as string,
          sample_log: args.sample_log as string,
        };
        if (args.extension_vrl !== undefined) req.extension_vrl = args.extension_vrl as string;
        const res = await client.testVrl(req);
        if (!res.success) return err(res.error?.message ?? 'Failed to test VRL');
        return ok(res.data);
      }

      case 'test_parse_live': {
        const req: TestVrlLiveRequest = {
          vrl_code: args.vrl_code as string,
          source_type: args.source_type as string,
        };
        if (args.current_vrl !== undefined) req.current_vrl = args.current_vrl as string;
        if (args.limit !== undefined) req.limit = args.limit as number;
        const res = await client.testVrlLive(req);
        if (!res.success) return err(res.error?.message ?? 'Failed to run live VRL test');
        return ok(res.data);
      }

      case 'create_log_source': {
        const res = await client.createLogSource(buildNewLogSource(args));
        if (!res.success) return err(res.error?.message ?? 'Failed to create log source');
        return ok({
          ...res.data,
          note: 'Saved as a draft. It is NOT deployed yet — call deploy_log_source to push it to Vector.',
        });
      }

      case 'update_log_source': {
        const res = await client.updateLogSource(args.id as string, buildUpdateLogSource(args));
        if (!res.success) return err(res.error?.message ?? 'Failed to update log source');
        return ok({
          ...res.data,
          note: 'Updated. If you changed parser_vrl, call deploy_log_source to push the change to Vector.',
        });
      }

      case 'deploy_log_source': {
        const res = await client.deployLogSource(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to deploy log source');
        return ok({
          ...res.data,
          note: 'Deploy is best-effort: Vector reload may lag or fail silently. Wait ~1 minute, then call get_log_source_health to confirm events are actually flowing before reporting this as live.',
        });
      }

      case 'undeploy_log_source': {
        const res = await client.undeployLogSource(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to undeploy log source');
        return ok(res.data);
      }

      case 'get_log_source_health': {
        const res = await client.getLogSourceHealth(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to get log source health');
        return ok(res.data);
      }

      case 'get_log_source_deployments': {
        const res = await client.getLogSourceDeployments(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to get deployment history');
        return ok(res.data);
      }

      case 'list_source_config_types': {
        const res = await client.listSourceConfigTypes();
        if (!res.success) return err(res.error?.message ?? 'Failed to list source config types');
        return ok(res.data);
      }

      case 'list_source_configs': {
        const res = await client.listSourceConfigs({
          config_type: args.config_type as string | undefined,
          enabled: args.enabled as boolean | undefined,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to list source configs');
        return ok(res.data);
      }

      case 'create_routing_rule': {
        const req: NewRoutingRule = {
          match_field: args.match_field as string,
          match_type: args.match_type as string,
          target_source_type: args.target_source_type as string,
        };
        if (args.match_value !== undefined) req.match_value = args.match_value as string;
        if (args.priority !== undefined) req.priority = args.priority as number;
        const res = await client.createRoutingRule(args.source_config_id as string, req);
        if (!res.success) return err(res.error?.message ?? 'Failed to create routing rule');
        return ok(res.data);
      }

      case 'check_rule_reachability': {
        const req: CheckReachabilityRequest = {
          target_source_type: args.target_source_type as string,
          match_field: args.match_field as string,
          match_type: args.match_type as string,
          match_value: args.match_value as string,
        };
        const res = await client.checkRoutingRuleReachability(args.source_config_id as string, req);
        if (!res.success) return err(res.error?.message ?? 'Failed to check rule reachability');
        return ok(res.data);
      }

      case 'list_parser_repositories': {
        const res = await client.listParserRepositories();
        if (!res.success) return err(res.error?.message ?? 'Failed to list parser repositories');
        return ok(res.data?.repositories ?? []);
      }

      case 'sync_parser_repository': {
        const res = await client.syncParserRepository(args.repository_id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to sync parser repository');
        return ok(res.data);
      }

      case 'list_repository_parsers': {
        const res = await client.listRepositoryParsers(args.repository_id as string, {
          category: args.category as string | undefined,
          search: args.search as string | undefined,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to list repository parsers');
        const summary = (res.data ?? []).map((p) => ({
          path: p.file_path,
          name: p.display_name ?? p.name,
          description: p.description,
          category: p.category,
          vendor: p.vendor,
          product: p.product,
          version: p.version,
          kind: p.kind,
          is_imported: p.is_imported,
          linked_log_source_id: p.linked_log_source_id,
        }));
        return ok(summary);
      }

      case 'import_parser': {
        const req: ImportParserRequest = {};
        if (args.source_type !== undefined) req.source_type = args.source_type as string;
        if (args.import_type !== undefined) req.import_type = args.import_type as string;
        if (args.ingestion_method !== undefined) req.ingestion_method = args.ingestion_method as string;
        const res = await client.importParser(args.repository_id as string, args.path as string, req);
        if (!res.success) return err(res.error?.message ?? 'Failed to import parser');
        return ok({
          ...res.data,
          note: 'Imported as a draft log source. Call deploy_log_source with the returned log_source_id to activate it.',
        });
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

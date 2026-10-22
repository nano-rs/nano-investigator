/**
 * Permission requirements published with each MCP tool.
 *
 * Keep this registry aligned with the authorization checks in nanosiem-api.
 * Desktop and other MCP clients can consume the metadata instead of guessing a
 * scope from the tool name. Alternatives are useful where the backend selects a
 * permission path from the request (for example nPL vs SQL dashboard panels).
 */

export const PERMISSION_REQUIREMENTS_META_KEY = 'io.nano/permission-requirements';

export interface PermissionAlternative {
  /** Every scope in this list is required for this authorization path. */
  allOf: string[];
  /** Explains when a conditional authorization path applies. */
  when?: string;
}

export interface ToolPermissionRequirements {
  version: 1;
  /**
   * A call is authorized when the applicable alternative's complete `allOf`
   * list is granted. An empty `allOf` explicitly declares a permissionless,
   * local, or public operation.
   */
  alternatives: PermissionAlternative[];
}

const allOf = (...permissions: string[]): ToolPermissionRequirements => ({
  version: 1,
  alternatives: [{ allOf: permissions }],
});

const alternatives = (
  ...paths: PermissionAlternative[]
): ToolPermissionRequirements => ({
  version: 1,
  alternatives: paths,
});

const permissionless = allOf();

/** Either recon write scope admits; see the Recon block below. */
const reconWrite = (
  tools: string[],
): Record<string, ToolPermissionRequirements> =>
  Object.fromEntries(
    tools.map((tool) => [
      tool,
      alternatives(
        { allOf: ['hunts:profile_write'], when: 'the narrow recon write scope' },
        {
          allOf: ['hunts:manage'],
          when: 'sessions provisioned before hunts:profile_write existed',
        },
      ),
    ]),
  );

/**
 * The authoritative permission contract for every tool exposed by this server.
 *
 * Conditional alternatives describe request- or resource-dependent checks.
 * They are intentionally not flattened into one oversized scope list: doing so
 * would incorrectly claim that every call needs every possible permission.
 */
export const TOOL_PERMISSION_REQUIREMENTS: Record<
  string,
  ToolPermissionRequirements
> = {
  // Agent lane (same authorization as the existing API endpoints).
  lake_sql: allOf('search:execute'),
  prevalence: allOf('prevalence:view'),
  risk_scores: allOf('risk:view', 'detections:view'),
  resolve_identity: allOf('enrichments:view'),
  lookup: alternatives({ allOf: ['lookup:view'], when: 'lookup table mode' }, { allOf: ['enrichments:view', 'search:execute'], when: 'ioc snapshot mode' }),

  // Search
  search: allOf('search:execute'),
  search_sql: allOf('search:sql'),
  get_schema: alternatives(
    { allOf: ['search:view'], when: 'include_ext is false' },
    {
      allOf: ['search:view', 'search:execute'],
      when: 'include_ext is true or omitted (the default)',
    },
  ),
  explain_query: allOf('search:execute'),
  get_field_values: allOf('search:execute'),
  list_saved_searches: allOf('search:view'),
  get_saved_search: allOf('search:view'),
  save_search: allOf('search:save'),
  create_shared_search: allOf('search:share'),

  // Alerts
  list_alerts: allOf('alerts:view'),
  get_alert: allOf('alerts:view'),
  get_alert_counts: allOf('alerts:view'),

  // Cases
  list_cases: allOf('cases:view'),
  get_case: allOf('cases:view'),
  review_case: allOf('cases:view', 'notebooks:view'),
  get_case_stats: allOf('cases:view'),
  get_related_cases: allOf('cases:view'),
  create_case: allOf('cases:create'),
  update_case: allOf('cases:edit'),
  change_case_status: alternatives(
    {
      allOf: ['cases:edit'],
      when: 'moving to a non-closed status',
    },
    {
      allOf: ['cases:close'],
      when: 'closing or reopening a case',
    },
  ),
  assign_case: allOf('cases:assign'),
  add_alert_to_case: allOf('cases:edit', 'alerts:view'),
  add_case_wall_entry: allOf('cases:comment'),
  merge_cases: allOf('cases:edit'),
  // Reads the case's notebook to pick the merge-vs-link path, then takes the
  // composite both case-side notebook mutations require.
  merge_notebook_into_case: allOf('cases:view', 'cases:edit', 'notebooks:edit'),

  // Notebooks
  list_notebooks: allOf('notebooks:view'),
  get_notebook: allOf('notebooks:view'),
  get_notebook_entries: allOf('notebooks:view'),
  find_notebooks_by_reference: allOf('notebooks:view'),
  create_notebook: allOf('notebooks:create'),
  add_notebook_entry: alternatives(
    {
      allOf: ['notebooks:edit'],
      when: 'a regular notebook or an explicitly shared case notebook',
    },
    {
      allOf: ['cases:edit'],
      when: 'a case notebook authorized through its case',
    },
  ),
  add_notebook_reference: allOf('notebooks:edit'),
  update_notebook: allOf('notebooks:edit'),
  share_notebook: allOf('notebooks:share'),

  // Dashboards
  get_dashboard_schema: permissionless,
  validate_dashboard: permissionless,
  dashboard_panel_query: alternatives(
    {
      allOf: ['dashboards:view', 'search:execute'],
      when: 'query_mode is piped (nPL)',
    },
    {
      allOf: ['dashboards:view', 'search:sql'],
      when: 'query_mode is sql',
    },
  ),
  list_dashboards: allOf('dashboards:view'),
  get_dashboard: allOf('dashboards:view'),
  create_dashboard: allOf('dashboards:create'),
  update_dashboard: allOf('dashboards:edit'),

  // Detections
  list_detections: allOf('detections:view'),
  get_detection: allOf('detections:view'),
  get_detection_matches: allOf('detections:view'),

  // Prevalence
  get_prevalence: allOf('prevalence:view'),
  get_rare_artifacts: allOf('prevalence:view'),
  get_new_artifacts: allOf('prevalence:view'),

  // Risk
  get_risky_entities: allOf('risk:view'),
  get_risk_overview: allOf('risk:view'),
  get_entity_risk_timeline: allOf('risk:view', 'detections:view'),
  get_entity_risk_activity: allOf('risk:view'),
  reset_entity_risk: allOf('risk:clear'),

  // Enrichment
  get_entity_context: allOf('risk:view', 'alerts:view', 'cases:view', 'detections:view'),
  lookup_ip: allOf('enrichments:view'),
  lookup_ioc: allOf('enrichments:view'),

  // MITRE ATT&CK
  get_mitre_technique: allOf('mitre:view'),
  get_mitre_coverage: allOf('mitre:view', 'detections:view'),

  // System context
  get_source_types: alternatives(
    { allOf: ['search:execute'] },
    { allOf: ['log_sources:create'] },
    { allOf: ['detections:view'] },
    { allOf: ['source_scopes:view'] },
  ),
  get_org_context: alternatives(
    { allOf: ['settings:view'], when: 'read-only settings authority' },
    { allOf: ['settings:ai'], when: 'legacy AI settings authority' },
  ),
  health_check: permissionless,
  get_audit_trail: allOf('audit:view'),

  // Ingestion lifecycle and diagnostics (aligned with nanodac).
  create_pipeline: allOf('log_sources:create'),
  update_pipeline_draft: allOf('log_sources:edit'),
  preview_pipeline: allOf('log_sources:view'),
  review_pipeline_release: allOf('log_sources:view'),
  publish_pipeline_release: allOf('log_sources:view', 'log_sources:deploy'),
  rollback_pipeline_release: allOf('log_sources:deploy'),
  list_pipelines: allOf('log_sources:view'),
  get_pipeline: allOf('log_sources:view'),
  explain_pipeline: allOf('log_sources:view'),
  list_log_sources: allOf('log_sources:view'),
  get_log_source: allOf('log_sources:view'),
  list_parser_repositories: allOf('parser_repositories:view'),
  get_parser_repository_sync_status: allOf('parser_repositories:view'),
  browse_parser_repository: allOf('parser_repositories:view'),
  get_repository_parser: allOf('parser_repositories:view'),
  list_data_sources: allOf('log_sources:view'),
  get_connector_status: allOf('enrichments:view', 'log_sources:view'),
  get_onboarding_status: allOf('log_sources:view'),
  get_add_data_guidance: allOf(),
  get_log_source_health: allOf('log_sources:view'),
  get_pipeline_releases: allOf('log_sources:view'),
  get_pipeline_inputs: allOf('log_sources:view'),
  get_add_data_status: allOf('log_sources:view'),
  get_ingest_credential_activity: allOf('log_sources:view'),

  // Recon (NAN-2238)
  //
  // All four take a recon WRITE scope. `hunts:view` is authority to READ a
  // stored profile, while recon reads across the whole log estate and ends by
  // writing a profile and creating hunt definitions. `hunts:run` is
  // deliberately NOT required: nothing in this flow schedules or starts
  // anything.
  //
  // Two alternatives, and the ORDER matters — a client rendering "what this
  // tool needs" should show the narrow scope first. `hunts:profile_write`
  // (nanosiem migration 9000060) authorizes exactly these five endpoints;
  // `hunts:manage` also archives and edits hunts and is accepted only so that
  // sessions provisioned before that migration keep working. Declaring only
  // `hunts:manage` would tell an operator who already holds the narrow scope
  // that they need the broad one — which is how a deliberately narrowed agent
  // key gets widened back.
  //
  // Flattening these into one `allOf` would be wrong in the other direction: it
  // would claim a call needs BOTH.
  ...reconWrite([
    'hunt_build_census',
    'hunt_huntable_surface',
    'hunt_save_profile',
    'hunt_propose_drafts',
  ]),

  // SOAR (NAN-4375) — aligned with nanosiem-enterprise handlers/soar.rs
  // `fence()` and each handler's `admit*` scope. Every route also needs the
  // tenant's SOAR entitlement and SOAR enabled (except settings, run/approval
  // history and cleanup), which are tenant state, not caller scopes.
  get_soar_settings: allOf('soar:view'),
  list_soar_packs: allOf('soar:view'),
  get_soar_pack: allOf('soar:view'),
  list_soar_actions: allOf('soar:view'),
  install_soar_pack: allOf('soar:manage'),
  upgrade_soar_pack: allOf('soar:manage'),
  remove_soar_pack: allOf('soar:manage'),
  list_soar_connections: alternatives(
    { allOf: ['soar:view'], when: 'SOAR enabled and entitled: full connection metadata' },
    {
      allOf: ['soar:manage'],
      when: 'SOAR off or entitlement lapsed: sanitized cleanup metadata only',
    },
  ),
  get_soar_connection: allOf('soar:view'),
  create_soar_connection: allOf('soar:manage'),
  update_soar_connection: allOf('soar:manage'),
  test_soar_connection: allOf('soar:manage'),
  remove_soar_connection: allOf('soar:manage'),
  run_soar_action: alternatives(
    { allOf: ['soar:run'], when: 'no case_id' },
    {
      allOf: ['soar:run', 'cases:view', 'cases:comment'],
      when: 'case_id links the run to a case (results post to its wall)',
    },
  ),
  list_soar_flows: allOf('soar:view'),
  get_soar_flow: allOf('soar:view'),
  validate_soar_flow: allOf('soar:manage'),
  create_soar_flow: allOf('soar:manage'),
  update_soar_flow: allOf('soar:manage'),
  remove_soar_flow: allOf('soar:manage'),
  run_soar_flow: alternatives(
    { allOf: ['soar:run'], when: 'no case_id' },
    {
      allOf: ['soar:run', 'cases:view', 'cases:comment'],
      when: 'case_id links the run to a case (results post to its wall)',
    },
  ),
  // Case-linked runs and approvals are visible only with cases:view.
  list_soar_runs: allOf('soar:view'),
  get_soar_run: allOf('soar:view'),
  cancel_soar_run: allOf('soar:run'),
  list_soar_approvals: allOf('soar:view'),
  get_soar_approval: allOf('soar:view'),
};

// ==================== Confirmation ====================

export const CONFIRMATION_META_KEY = 'io.nano/confirmation';

/**
 * - `write`: changes tenant state (install a pack, store a connection, save a
 *   flow, cancel a run). Ask the user first.
 * - `external_side_effect`: MUTATING — sends requests to a third-party system
 *   (contain a host, disable a user). Ask the user first; a dry run, where the
 *   API offers one, renders the requests without sending and needs no
 *   confirmation.
 */
export type ToolEffect = 'write' | 'external_side_effect';

export interface ToolConfirmation {
  version: 1;
  effect: ToolEffect;
  /** The tool refuses unless this argument is literally `true`. */
  argument: 'user_confirmed';
  /** Removes tenant state that is not recoverable through the tool. */
  destructive?: boolean;
  /** When this argument is `true`, nothing external is sent and confirmation is not required. */
  dryRunArgument?: 'dry_run';
}

const confirm = (
  effect: ToolEffect,
  extra: Partial<Pick<ToolConfirmation, 'destructive' | 'dryRunArgument'>> = {},
): ToolConfirmation => ({ version: 1, effect, argument: 'user_confirmed', ...extra });

/**
 * Tools that refuse to run without explicit user confirmation. Every tool NOT
 * listed here is either a read (safe) or a pre-existing write governed by its
 * own description. Desktop and other clients can render the confirmation from
 * this metadata; the handler enforces it regardless of client.
 */
export const TOOL_CONFIRMATIONS: Record<string, ToolConfirmation> = {
  // Ingestion (pre-existing user_confirmed gates)
  publish_pipeline_release: confirm('write'),
  rollback_pipeline_release: confirm('write'),

  // SOAR
  install_soar_pack: confirm('write'),
  upgrade_soar_pack: confirm('write'),
  remove_soar_pack: confirm('write', { destructive: true }),
  create_soar_connection: confirm('write'),
  update_soar_connection: confirm('write'),
  // Calls the vendor with the stored credentials (the pack's read-only test action).
  test_soar_connection: confirm('write'),
  remove_soar_connection: confirm('write', { destructive: true }),
  create_soar_flow: confirm('write'),
  update_soar_flow: confirm('write'),
  remove_soar_flow: confirm('write', { destructive: true }),
  cancel_soar_run: confirm('write'),
  run_soar_action: confirm('external_side_effect', { dryRunArgument: 'dry_run' }),
  run_soar_flow: confirm('external_side_effect', { dryRunArgument: 'dry_run' }),
};

/** The refusal message when a confirmation-gated call lacks confirmation, else undefined. */
export function missingConfirmation(
  tool: string,
  args: Record<string, unknown>,
): string | undefined {
  const rule = TOOL_CONFIRMATIONS[tool];
  if (!rule) return undefined;
  if (rule.dryRunArgument && args[rule.dryRunArgument] === true) return undefined;
  if (args[rule.argument] === true) return undefined;
  const what =
    rule.effect === 'external_side_effect'
      ? 'This sends real requests to an external system.'
      : 'This changes workspace state.';
  const dry = rule.dryRunArgument
    ? ` Run with ${rule.dryRunArgument}=true first to preview without sending.`
    : '';
  return `${what} Describe exactly what will happen, ask the user, and retry with ${rule.argument}=true only after they explicitly approve.${dry}`;
}

type ToolDefinition = {
  name: string;
  _meta?: Record<string, unknown>;
};

/** Attach the versioned permission contract to MCP `tools/list` definitions. */
export function withPermissionRequirements<T extends ToolDefinition>(
  tools: readonly T[],
): Array<T & { _meta: Record<string, unknown> }> {
  return tools.map((tool) => {
    const requirements = TOOL_PERMISSION_REQUIREMENTS[tool.name];
    if (!requirements) {
      throw new Error(`Missing permission requirements for MCP tool "${tool.name}"`);
    }

    const confirmation = TOOL_CONFIRMATIONS[tool.name];
    return {
      ...tool,
      _meta: {
        ...tool._meta,
        [PERMISSION_REQUIREMENTS_META_KEY]: requirements,
        ...(confirmation ? { [CONFIRMATION_META_KEY]: confirmation } : {}),
      },
    };
  });
}

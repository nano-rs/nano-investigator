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
  get_entity_risk_timeline: allOf('risk:view'),
  get_entity_risk_activity: allOf('risk:view'),
  reset_entity_risk: allOf('risk:clear'),

  // Enrichment
  get_entity_context: allOf('risk:view'),
  lookup_ip: allOf('enrichments:view'),

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
  get_org_context: allOf('settings:ai'),
  health_check: permissionless,
  get_audit_trail: allOf('audit:view'),

  // Parser authoring
  list_log_sources: allOf('log_sources:view'),
  get_log_source: allOf('log_sources:view'),
  validate_vrl: allOf('log_sources:view'),
  test_parse_sample: allOf('log_sources:view'),
  test_parse_live: allOf('log_sources:view', 'search:execute'),
  create_log_source: allOf('log_sources:create'),
  update_log_source: allOf('log_sources:edit'),
  deploy_log_source: allOf('log_sources:deploy'),
  undeploy_log_source: allOf('log_sources:deploy'),
  get_log_source_health: allOf('log_sources:view'),
  get_log_source_deployments: allOf('log_sources:view'),
  list_source_config_types: allOf('source_configs:view'),
  list_source_configs: allOf('source_configs:view'),
  create_routing_rule: allOf('source_configs:edit'),
  check_rule_reachability: allOf('source_configs:view'),
  deploy_source_config: alternatives(
    {
      allOf: ['source_configs:deploy'],
      when: 'the saved source configuration has no credential',
    },
    {
      allOf: ['source_configs:deploy', 'credentials:use'],
      when: 'the saved source configuration references a credential',
    },
  ),
  undeploy_source_config: allOf('source_configs:deploy'),
  list_parser_repositories: allOf('parser_repositories:view'),
  sync_parser_repository: allOf('parser_repositories:sync'),
  list_repository_parsers: allOf('parser_repositories:view'),
  import_parser: alternatives(
    {
      allOf: ['parser_repositories:import', 'log_sources:create'],
      when: 'importing a log or enrichment parser',
    },
    {
      allOf: ['parser_repositories:import', 'source_configs:edit'],
      when: 'importing an identity parser',
    },
  ),

  // Guided onboarding
  onboarding_requirements: permissionless,
  import_credential_from_file: allOf('credentials:create'),
  create_credential: allOf('credentials:create'),
  create_source_config: alternatives(
    {
      allOf: ['source_configs:create'],
      when: 'credential_id is omitted',
    },
    {
      allOf: ['source_configs:create', 'credentials:use'],
      when: 'credential_id is provided',
    },
  ),
};

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

    return {
      ...tool,
      _meta: {
        ...tool._meta,
        [PERMISSION_REQUIREMENTS_META_KEY]: requirements,
      },
    };
  });
}

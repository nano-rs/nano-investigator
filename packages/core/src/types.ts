// ============================================================================
// Common Types
// ============================================================================

export interface TimeRange {
  start: string;
  end: string;
}

// ============================================================================
// Search Types
// ============================================================================

export interface SearchRequest {
  query: string;
  time_range: TimeRange;
  limit?: number;
  offset?: number;
  skip_field_stats?: boolean;
  table_view?: boolean;
  source_type?: string;
}

export interface SearchResponse {
  results: Record<string, unknown>[];
  total_count: number;
  execution_time_ms: number;
  fields: FieldInfo[];
  generated_sql?: string;
  histogram?: HistogramBucket[];
  warnings?: QueryWarning[];
  display_type?: string;
  column_order?: string[];
}

export interface FieldInfo {
  name: string;
  field_type: string;
  count: number;
  top_values: [string, number][];
  cardinality?: number;
}

export interface HistogramBucket {
  time: string;
  count: number;
}

export interface QueryWarning {
  severity: 'info' | 'warning' | 'error';
  code: string;
  message: string;
  suggestion?: string;
}

export interface RawSqlRequest {
  sql: string;
  time_range: TimeRange;
  limit?: number;
}

export interface FieldStatsRequest {
  query: string;
  start: string;
  end: string;
}

export interface FieldStatsResponse {
  fields: FieldInfo[];
  total_events: number;
}

export interface FieldValuesRequest {
  field: string;
  query: string;
  start: string;
  end: string;
  limit?: number;
}

export interface FieldValueInfo {
  value: string;
  count: number;
  percentage: number;
}

export interface FieldValuesResponse {
  field: string;
  values: FieldValueInfo[];
  total_count: number;
}

// ============================================================================
// UDM Schema Types
// ============================================================================

export interface UdmFieldInfo {
  name: string;
  column_name: string;
  data_type: string;
  category: string;
  description: string;
}

export interface UdmFieldsResponse {
  fields: UdmFieldInfo[];
}

// ============================================================================
// Saved Search Types
// ============================================================================

export interface SavedSearch {
  id: string;
  name: string;
  query: string;
  query_mode: 'piped' | 'sql';
  time_range?: TimeRange;
  created_at: string;
  updated_at: string;
  user_id?: string;
  visibility?: 'private' | 'public' | 'group';
}

export interface CreateSavedSearchRequest {
  name: string;
  query: string;
  query_mode: 'piped' | 'sql';
  time_range?: TimeRange;
  visibility?: 'private' | 'public' | 'group';
}

export interface CreateSharedSearchRequest {
  query: string;
  query_mode: string;
  time_range_type: string;
  time_range_preset?: string;
  time_range_start?: string;
  time_range_end?: string;
}

export interface CreateSharedSearchResponse {
  id: string;
  short_url: string;
}

// ============================================================================
// Alert Types
// ============================================================================

export interface Alert {
  id: string;
  rule_id: string;
  rule_name?: string;
  rule_query?: string;
  severity: Severity;
  status: 'new' | 'acknowledged' | 'closed';
  disposition?: Disposition;
  matched_events: Record<string, unknown>[];
  matched_event_count?: number;
  risk_score?: number;
  assigned_to?: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  closed_by?: string;
  closed_at?: string;
  triage_status?: string;
  triage_verdict?: string;
  created_at: string;
}

export interface AlertCounts {
  total: number;
  new: number;
  acknowledged: number;
  closed: number;
  by_severity: Record<string, number>;
}

export interface AlertsListParams {
  status?: string;
  severity?: string;
  rule_id?: string;
  assigned_to?: string;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Case Types
// ============================================================================

export type CaseStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed';
export type CaseDisposition = 'true_positive' | 'false_positive' | 'benign' | 'inconclusive' | 'merged';
export type CaseEntityType = 'user' | 'host' | 'ip' | 'domain' | 'hash' | 'url' | 'file' | 'process' | 'email';
export type CaseWallEntryType = 'comment' | 'status_change' | 'assignment_change' | 'alert_added' | 'alert_removed' | 'ai_analysis' | 'action_taken';

export interface Case {
  id: string;
  case_number: number;
  title: string;
  description?: string;
  severity: Severity;
  status: CaseStatus;
  disposition?: CaseDisposition;
  priority: number;
  assigned_to?: string;
  ai_summary?: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
  first_activity_at?: string;
  last_activity_at?: string;
  resolved_at?: string;
  closed_at?: string;
}

export interface CaseWithDetails extends Case {
  alert_count: number;
  entity_count: number;
  assignee_name?: string;
  creator_name?: string;
}

export interface CaseListResponse {
  cases: CaseWithDetails[];
  total_count: number;
  limit: number;
  offset: number;
}

export interface CaseEntity {
  id: string;
  case_id: string;
  entity_type: CaseEntityType;
  entity_value: string;
  occurrence_count: number;
  risk_score?: number;
  is_primary: boolean;
  enrichment_data?: Record<string, unknown>;
  created_at: string;
}

export interface EntityTypeSummary {
  entity_type: string;
  count: number;
  entities: CaseEntity[];
}

export interface CaseWallEntry {
  id: string;
  case_id: string;
  entry_type: CaseWallEntryType;
  content?: string;
  metadata: Record<string, unknown>;
  is_internal: boolean;
  created_by?: string;
  creator_name?: string;
  created_at: string;
}

export interface CaseAlertDetail {
  id: string;
  alert_id: string;
  rule_name?: string;
  severity: Severity;
  status: string;
  disposition?: string;
  matched_event_count?: number;
  created_at: string;
  added_at: string;
  is_primary: boolean;
  triage_verdict?: string;
}

export interface RelatedCaseSummary {
  case_id: string;
  case_number: number;
  title: string;
  severity: Severity;
  status: CaseStatus;
  relation_type: string;
  confidence?: number;
  shared_entity_count: number;
}

export interface CaseStats {
  total: number;
  open: number;
  in_progress: number;
  pending: number;
  resolved: number;
  closed: number;
  by_severity: Record<string, number>;
  avg_resolution_time_hours?: number;
}

export interface CaseFullResponse {
  case: CaseWithDetails;
  alerts: CaseAlertDetail[];
  entities: EntityTypeSummary[];
  related_cases: RelatedCaseSummary[];
  stats: {
    alert_count: number;
    entity_count: number;
    comment_count: number;
    time_open_hours?: number;
  };
}

export interface CreateCaseRequest {
  title: string;
  description?: string;
  severity: Severity;
  priority?: number;
  assigned_to?: string;
  tags?: string[];
}

export interface UpdateCaseRequest {
  title?: string;
  description?: string;
  severity?: Severity;
  priority?: number;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  tags?: string[];
}

export interface CaseFilter {
  status?: CaseStatus[];
  severity?: string[];
  assigned_to?: string;
  search?: string;
  tags?: string[];
  created_after?: string;
  created_before?: string;
  limit?: number;
  offset?: number;
}

export interface AddAlertToCaseRequest {
  alert_id: string;
  is_primary?: boolean;
}

export interface AddWallEntryRequest {
  entry_type: CaseWallEntryType;
  content?: string;
  metadata?: Record<string, unknown>;
  is_internal?: boolean;
}

export interface ChangeCaseStatusRequest {
  status: CaseStatus;
  disposition?: CaseDisposition;
}

export interface MergeCasesRequest {
  source_case_ids: string[];
}

export interface LinkNotebookRequest {
  notebook_id: string;
}

// ============================================================================
// Notebook Types
// ============================================================================

export type NotebookVisibility = 'private' | 'shared' | 'public';
export type NotebookStatus = 'active' | 'paused' | 'closed' | 'merged';
export type NotebookEntryType =
  | 'manual_note'
  | 'search_executed'
  | 'search_refined'
  | 'alert_viewed'
  | 'alert_actioned'
  | 'detection_viewed'
  | 'detection_modified'
  | 'ai_suggestion'
  | 'ai_summary'
  | 'entity_reference'
  | 'ioc_marker'
  | 'timeline_marker'
  | 'linked_alert'
  | 'linked_detection'
  | 'ai_query'
  | 'pivot_suggestions'
  | 'case_event'
  | 'investigation_timeline';

export type ReferenceType = 'alert' | 'detection' | 'saved_search' | 'case';

export interface Notebook {
  id: string;
  title: string;
  owner_id: string;
  case_id?: string;
  visibility: NotebookVisibility;
  status: NotebookStatus;
  summary?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

export interface NotebookWithOwner extends Notebook {
  owner_name?: string;
  entry_count?: number;
}

export interface NotebookEntry {
  id: string;
  notebook_id: string;
  entry_type: NotebookEntryType;
  content: Record<string, unknown>;
  source_url?: string;
  created_by: string;
  created_at: string;
  source?: string;
  creator_name?: string;
}

export interface NotebookReference {
  id: string;
  notebook_id: string;
  reference_type: ReferenceType;
  reference_id: string;
  reference_name?: string;
  created_at: string;
}

export interface CreateNotebookRequest {
  title: string;
  visibility?: NotebookVisibility;
}

export interface UpdateNotebookRequest {
  title?: string;
  visibility?: NotebookVisibility;
  status?: NotebookStatus;
  summary?: string;
}

export interface AddEntryRequest {
  entry_type: NotebookEntryType;
  content: Record<string, unknown>;
  source_url?: string;
}

export interface AddReferenceRequest {
  reference_type: ReferenceType;
  reference_id: string;
  reference_name?: string;
}

export interface ShareNotebookRequest {
  visibility: NotebookVisibility;
  group_ids?: string[];
}

export interface NotebookListParams {
  case_id?: string;
  status?: NotebookStatus;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Detection Types
// ============================================================================

export interface AiTriageHints {
  ignore_when: string[];
  suspicious_when: string[];
  context?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  query: string;
  severity: Severity;
  mode: 'staging' | 'live' | 'alerting';
  detection_mode?: 'real-time' | 'scheduled';
  enabled: boolean;
  schedule_cron?: string;
  lookback_minutes?: number;
  mitre_tactics: string[];
  mitre_techniques: string[];
  narrative?: string;
  reference_url?: string;
  author?: string;
  tags: string[];
  ai_triage_hints?: AiTriageHints;
  folder?: string;
  created_at: string;
  updated_at: string;
  last_run_at?: string;
  last_match_at?: string;
  match_count: number;
  live_match_count?: number;
  alert_mode?: 'grouped' | 'per_event';
}

export interface DetectionMatch {
  id: string;
  detected_at: string;
  severity: string;
  status: string;
  event_count: number;
  events: Record<string, unknown>[];
}

export interface DetectionMatchesResponse {
  total: number;
  matches: DetectionMatch[];
}

// ============================================================================
// Prevalence Types
// ============================================================================

export type PrevalenceArtifactType = 'hash_md5' | 'hash_sha256' | 'hash_unknown' | 'domain' | 'subdomain' | 'ip_address' | 'ip_address_private';

export interface PrevalenceData {
  artifact: string;
  artifact_type: PrevalenceArtifactType;
  host_count: number;
  total_occurrences: number;
  first_seen: string;
  last_seen: string;
  is_rare: boolean;
  prevalence_score: number;
}

export interface BulkPrevalenceRequest {
  artifacts: string[];
  window?: string;
}

export interface BulkPrevalenceResponse {
  data: PrevalenceData[];
  total: number;
}

export interface ArtifactListResponse {
  artifacts: PrevalenceData[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface RareArtifactsQuery {
  window?: string;
  type?: string;
  limit?: number;
  offset?: number;
}

export interface NewArtifactsQuery {
  since?: string;
  type?: string;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Risk Types
// ============================================================================

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface EntityRiskSummary {
  entity: string;
  entity_type: string;
  risk_score: number;
  finding_count: number;
  last_finding_at?: string;
  last_rule_name?: string;
  last_severity?: string;
  risk_level: RiskLevel;
}

export interface RiskAnalyticsOverview {
  total_entities: number;
  critical_entities: number;
  high_entities: number;
  medium_entities: number;
  low_entities: number;
  total_findings: number;
  avg_risk_score: number;
}

export interface EntityTypeCount {
  entity_type: string;
  count: number;
}

export interface RiskOverviewResponse {
  overview_24h: RiskAnalyticsOverview;
  overview_7d: RiskAnalyticsOverview;
  entity_types: EntityTypeCount[];
}

export interface RiskEntitiesResponse {
  entities: EntityRiskSummary[];
  total: number;
}

export interface RiskEntitiesQuery {
  window?: '24h' | '7d' | 'all';
  entity_type?: string;
  min_score?: number;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Enrichment Types
// ============================================================================

export interface IpLookupResult {
  ip: string;
  found: boolean;
  country?: string;
  country_code?: string;
  continent?: string;
  asn?: string;
  as_name?: string;
  as_domain?: string;
}

// ============================================================================
// MITRE Types
// ============================================================================

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description?: string;
  detection_count?: number;
}

export interface MitreCoverage {
  techniques: MitreTechnique[];
  total_techniques: number;
  covered_techniques: number;
  coverage_percentage: number;
}

// ============================================================================
// Audit Types
// ============================================================================

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_id?: string;
  user_name?: string;
  api_key_id?: string;
  api_key_name?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  success: boolean;
}

export interface AuditLogResponse {
  logs: AuditLogEntry[];
  total: number;
}

export interface AuditLogQuery {
  user_id?: string;
  action?: string;
  resource_type?: string;
  start_time?: string;
  end_time?: string;
  success?: boolean;
  limit?: number;
  offset?: number;
}

// ============================================================================
// System Types
// ============================================================================

export interface HealthStatus {
  status: string;
  version?: string;
  clickhouse?: { status: string };
  postgres?: { status: string };
}

export interface OrgContext {
  company_name?: string;
  industry?: string;
  compliance_frameworks?: string[];
  internal_ip_ranges?: string[];
  critical_assets?: string[];
  business_hours?: { start: string; end: string; timezone: string };
}

// ============================================================================
// Shared Types
// ============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Disposition = 'true_positive' | 'false_positive' | 'benign';

// ============================================================================
// Parsers / Log Sources
// ============================================================================
// A "log source" is a Vector VRL parser bound to a source_type. All IDs are
// typeids serialized as strings (e.g. "logsource_...", "sourceconfig_...").
// Mirrors nanosiem-core::log_sources / source_configs / parser_repository.

export interface LogSource {
  id: string;
  name: string;
  description?: string | null;
  /** Identity-resolution namespace, e.g. "default", "aws:123:vpc-abc". */
  namespace: string;
  /** IANA timezone applied to timestamps without offset info. */
  timezone: string;
  source_type: string;
  source_config: Record<string, unknown>;
  parser_vrl: string;
  output_fields?: Record<string, unknown> | null;
  extension_vrl?: string | null;
  extension_enabled?: boolean;
  category?: string | null;
  vendor?: string | null;
  product?: string | null;
  match_field?: string | null;
  match_pattern?: string | null;
  match_values?: string[] | null;
  validated: boolean;
  validation_error?: string | null;
  deployed: boolean;
  deployed_at?: string | null;
  enabled: boolean;
  parser_only?: boolean;
  /** "log" (default) or "enrichment". */
  kind: string;
  source_parser_repository_id?: string | null;
  source_parser_path?: string | null;
  source_parser_linked?: boolean;
  created_at: string;
  updated_at: string;
}

export interface NewLogSource {
  name: string;
  source_type: string;
  parser_vrl: string;
  /** Required by the API. Pass {} for a routed/HTTP source (the common case). */
  source_config?: Record<string, unknown>;
  description?: string;
  /** Defaults server-side to "default". */
  namespace?: string;
  /** Defaults server-side to "UTC". */
  timezone?: string;
  output_fields?: Record<string, unknown>;
  category?: string;
  vendor?: string;
  product?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  dispatch_source_config_id?: string;
}

export interface UpdateLogSource {
  name?: string;
  description?: string;
  namespace?: string;
  timezone?: string;
  source_type?: string;
  source_config?: Record<string, unknown>;
  parser_vrl?: string;
  output_fields?: Record<string, unknown>;
  category?: string;
  vendor?: string;
  product?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  enabled?: boolean;
  extension_vrl?: string;
  extension_enabled?: boolean;
}

export interface VrlDiagnostic {
  /** "error" | "warn" | "info" */
  severity: string;
  line?: number | null;
  col?: number | null;
  code?: string | null;
  message: string;
  hint?: string | null;
}

export interface VrlValidationResult {
  valid: boolean;
  /** Free-form error strings (legacy). Prefer `diagnostics`. */
  errors: string[];
  diagnostics: VrlDiagnostic[];
}

export interface ParserTestResult {
  input: string;
  success: boolean;
  output?: Record<string, unknown> | null;
  error?: string | null;
  /** Number of top-level fields in `output` (0 when output is null). */
  extracted_field_count: number;
}

export interface TestVrlRequest {
  vrl_code: string;
  sample_log: string;
  /** Optional parser-extension VRL chained after vrl_code. */
  extension_vrl?: string;
}

export interface TestVrlLiveRequest {
  vrl_code: string;
  source_type: string;
  /** Deployed VRL to compare against. */
  current_vrl?: string;
  /** Events to test (default 10, max 20). */
  limit?: number;
}

export interface LiveTestResult {
  input: string;
  new_parse: ParserTestResult;
  current_parse?: ParserTestResult | null;
}

export interface DeploymentResult {
  success: boolean;
  log_source_id: string;
  action: string;
  message: string;
  validation_result?: VrlValidationResult | null;
  deployment_id?: string | null;
}

export interface LogSourceDeployment {
  id: string;
  log_source_id: string;
  action: string;
  status: string;
  error_message?: string | null;
  config_snapshot?: string | null;
  deployed_at: string;
}

export interface LogSourceHealth {
  log_source_id: string;
  log_source_name: string;
  total_events: number;
  events_last_24h: number;
  events_last_hour: number;
  avg_events_per_hour: number;
  last_event_at?: string | null;
  first_event_at?: string | null;
  data_freshness_hours?: number | null;
  /** "increasing" | "stable" | "decreasing" | "unknown" */
  ingestion_rate_trend: string;
  /** "healthy" | "stale" | "no_data" | "disabled" | "error" */
  health_status: string;
  total_size_bytes: number;
  avg_event_size_bytes: number;
  error_rate_24h: number;
  parse_errors_24h: number;
}

// --- Source configurations (ingress transports + routing) ---

export interface MatchFieldPreset {
  label: string;
  /** VRL path stored as match_field (no leading dot). */
  path: string;
  description: string;
}

export interface SourceConfigTypeInfo {
  config_type: string;
  label: string;
  description: string;
  requires_credentials: boolean;
  is_pull_source: boolean;
  default_match_field: string;
  match_field_presets: MatchFieldPreset[];
}

export interface SourceConfiguration {
  id: string;
  name: string;
  description?: string | null;
  config_type: string;
  connection_config: Record<string, unknown>;
  credential_id?: string | null;
  enabled: boolean;
  deployed: boolean;
  deployed_at?: string | null;
  created_at: string;
  updated_at: string;
  events_24h?: number | null;
  bytes_per_day_24h?: number | null;
  last_event_at?: string | null;
}

export interface ListSourceConfigsParams {
  config_type?: string;
  enabled?: boolean;
  deployed?: boolean;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface RoutingRule {
  id: string;
  source_configuration_id: string;
  /** Lower = higher priority. */
  priority: number;
  match_field: string;
  /** "exact" | "prefix" | "suffix" | "regex" | "contains" | "default" */
  match_type: string;
  match_value?: string | null;
  target_source_type: string;
  created_at: string;
  fires_24h?: number | null;
  last_fired_at?: string | null;
}

export interface NewRoutingRule {
  priority?: number;
  match_field: string;
  match_type: string;
  match_value?: string;
  target_source_type: string;
}

export interface CheckReachabilityRequest {
  target_source_type: string;
  match_field: string;
  match_type: string;
  match_value: string;
}

export interface ReachabilityResult {
  reachable: boolean;
  source_config_enabled: boolean;
  source_config_deployed: boolean;
  target_log_source_exists: boolean;
  broker_reachable?: boolean | null;
  broker_reachable_details?: string[];
  warnings: string[];
}

// --- Parser repositories (importable parser library, e.g. nano-rs/parsers) ---

export interface ParserRepository {
  id: string;
  name: string;
  slug: string;
  description?: string | null;
  url: string;
  branch: string;
  parsers_path?: string | null;
  auto_sync_enabled: boolean;
  sync_interval_hours: number;
  last_synced_at?: string | null;
  last_sync_commit?: string | null;
  last_sync_status?: string | null;
  last_sync_error?: string | null;
  parser_count: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ListParserRepositoriesResponse {
  repositories: ParserRepository[];
}

/** A parser cached from an upstream repo. List responses flatten import status. */
export interface RepositoryParser {
  id: string;
  repository_id: string;
  file_path: string;
  name?: string | null;
  display_name?: string | null;
  description?: string | null;
  version?: string | null;
  category?: string | null;
  vendor?: string | null;
  product?: string | null;
  parser_vrl?: string | null;
  /** "parser" (log) or "enrichment". */
  kind: string;
  is_imported?: boolean;
  linked_log_source_id?: string | null;
}

export interface ListRepositoryParsersParams {
  category?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface ImportParserRequest {
  /** "linked" (default) or "forked". */
  import_type?: string;
  /** Match value that activates this parser via routing rules (e.g. "apache"). */
  source_type?: string;
  /** routed | kafka | aws_s3 | gcp_pubsub | splunk_hec | vector */
  ingestion_method?: string;
  dispatch_source_config_id?: string;
}

export interface ImportParserResponse {
  log_source_id: string;
  import_type: string;
}

export interface ParserSyncStartResponse {
  repository_id: string;
  status: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Dashboards
//
// `panels` and `layout` are opaque `serde_json::Value` columns server-side —
// NOTHING validates their shape on write. A malformed panel saves happily and
// then breaks at every render. These types ARE the schema, and they mirror
// nanosiem-web/src/lib/api/types.ts, which owns it.
//
// Note the casing split, which is not a mistake: dashboard-level fields are
// snake_case (they're real columns), while everything INSIDE panels/layout is
// camelCase (the frontend owns those blobs end to end).
// ---------------------------------------------------------------------------

export type DashboardVisibility = 'public' | 'group' | 'private';

/**
 * The visualization types that can actually be authored.
 *
 * `tree` and `flow` exist in the web app's enum but the backend REJECTS the
 * commands they need (HTTP 400), and `obs_metric` is fetched from the metrics
 * endpoint rather than the panel-query path. All three are omitted here so an
 * agent cannot author a panel that is broken by construction.
 */
export type VisualizationType =
  | 'bar'
  | 'line'
  | 'area'
  | 'pie'
  | 'table'
  | 'single_value'
  | 'timeline'
  | 'ranked_bar'
  | 'transaction';

export interface ThresholdConfig {
  value: number;
  color: string;
  label?: string;
}

export interface TableColumnConfig {
  field: string;
  label: string;
  sortable: boolean;
  width?: number;
}

/** One flat bag of options for every viz type — not a per-type union. */
export interface VisualizationConfig {
  orientation?: 'horizontal' | 'vertical';
  stacked?: boolean;
  showPoints?: boolean;
  smooth?: boolean;
  fillOpacity?: number;
  showLabels?: boolean;
  columns?: TableColumnConfig[];
  pageSize?: number;
  unit?: string;
  thresholds?: ThresholdConfig[];
  showTrend?: boolean;
  maxEventsShown?: number;
}

export interface PanelConfig {
  id: string;
  title: string;
  query: string;
  queryMode: 'piped' | 'sql';
  visualizationType: VisualizationType;
  visualizationConfig: VisualizationConfig;
  timeRangeMode: 'dashboard' | 'custom';
  customTimeRange?: { start: string; end: string };
  drilldownEnabled: boolean;
  drilldownTemplate?: string;
}

/** react-grid-layout's item shape, 1:1. `i` MUST equal a PanelConfig.id. */
export interface LayoutItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
}

export type DashboardVariableType = 'dropdown' | 'text' | 'query';

export interface DashboardVariable {
  /** Referenced in a panel query as `$name`. */
  name: string;
  label: string;
  type: DashboardVariableType;
  defaultValue?: string;
  /** `dropdown`: the fixed choices. */
  options?: string[];
  /** `query`: an nPL query whose results supply the choices. */
  query?: string;
  queryField?: string;
}

export interface DashboardLayout {
  columns: number;
  rowHeight: number;
  items: LayoutItem[];
  /** Variables live inside `layout` purely for persistence. It's a wart; it's the contract. */
  variables?: DashboardVariable[];
  defaultTimeRange?:
    | { type: 'preset'; preset: string }
    | { type: 'custom'; start: string; end: string };
  /** When true, panels run on open. Otherwise the dashboard waits for a click. */
  autoRun?: boolean;
}

export interface Dashboard {
  id: string;
  name: string;
  description?: string;
  layout: DashboardLayout;
  panels: PanelConfig[];
  refresh_interval?: number;
  owner_id?: string;
  owner_name?: string;
  visibility: DashboardVisibility;
  is_owner?: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * What `GET /api/dashboards` actually returns — a SUMMARY, not a Dashboard.
 * It carries `panel_count` and has no `panels`/`layout` at all, so treating the
 * list response as `Dashboard[]` reports every dashboard as having zero panels.
 */
export interface DashboardSummary {
  id: string;
  name: string;
  description?: string;
  panel_count: number;
  owner_id?: string;
  owner_name?: string;
  visibility: DashboardVisibility;
  shared_groups?: unknown[];
  created_at: string;
  updated_at: string;
}

export interface CreateDashboardRequest {
  name: string;
  description?: string;
  layout: DashboardLayout;
  panels: PanelConfig[];
  refresh_interval?: number;
  visibility?: DashboardVisibility;
}

export interface UpdateDashboardRequest {
  name?: string;
  description?: string | null;
  layout?: DashboardLayout;
  panels?: PanelConfig[];
  refresh_interval?: number | null;
  /**
   * Optimistic concurrency. Send the `updated_at` you read, and the server
   * returns 409 if someone changed it since — rather than letting this write
   * silently clobber theirs.
   */
  expected_updated_at?: string;
}

export interface PanelQueryRequest {
  query: string;
  query_mode: 'piped' | 'sql';
  time_range: { start: string; end: string };
  variables?: Record<string, string>;
  bypass_cache?: boolean;
}

export interface PanelQueryResponse {
  results: Record<string, unknown>[];
  total_count: number;
  execution_time_ms: number;
  /**
   * Group-by columns first, aggregates last. LOAD-BEARING for rendering: without
   * it a renderer cannot tell a numeric group-by (`dest_port`) from a numeric
   * aggregate (`count`), and will plot the port number as the bar height.
   */
  column_order?: string[];
  /** The result hit the 10,000-row panel cap. */
  truncated?: boolean;
  cached?: boolean;
  cache_age_secs?: number;
}

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

export interface IocLookupResult {
  ioc_value: string;
  found: boolean;
  ioc_type?: string;
  confidence_level?: number;
  threat_type?: string;
  malware?: string;
  tags?: string[];
  first_seen_at?: string;
  last_seen_at?: string;
  reference_url?: string;
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

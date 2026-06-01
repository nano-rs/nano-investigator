/**
 * nano API client for SOC operations
 *
 * Handles communication with both the main API (port 3000) and search service (port 3002)
 */

import type {
  // Search
  SearchRequest,
  SearchResponse,
  RawSqlRequest,
  FieldStatsRequest,
  FieldStatsResponse,
  FieldValuesRequest,
  FieldValuesResponse,
  UdmFieldsResponse,
  SavedSearch,
  CreateSavedSearchRequest,
  CreateSharedSearchRequest,
  CreateSharedSearchResponse,
  // Alerts
  Alert,
  AlertCounts,
  AlertsListParams,
  // Cases
  CaseFullResponse,
  CaseListResponse,
  CaseWallEntry,
  CaseStats,
  RelatedCaseSummary,
  CreateCaseRequest,
  UpdateCaseRequest,
  CaseFilter,
  AddAlertToCaseRequest,
  AddWallEntryRequest,
  ChangeCaseStatusRequest,
  MergeCasesRequest,
  LinkNotebookRequest,
  CaseWithDetails,
  // Notebooks
  NotebookWithOwner,
  NotebookEntry,
  NotebookReference,
  CreateNotebookRequest,
  UpdateNotebookRequest,
  AddEntryRequest,
  AddReferenceRequest,
  ShareNotebookRequest,
  NotebookListParams,
  // Detections
  DetectionRule,
  DetectionMatchesResponse,
  // Prevalence
  PrevalenceData,
  BulkPrevalenceRequest,
  BulkPrevalenceResponse,
  ArtifactListResponse,
  RareArtifactsQuery,
  NewArtifactsQuery,
  // Risk
  RiskOverviewResponse,
  RiskEntitiesResponse,
  RiskEntitiesQuery,
  // Enrichment
  IpLookupResult,
  // MITRE
  MitreCoverage,
  // Audit
  AuditLogResponse,
  AuditLogQuery,
  // System
  HealthStatus,
  OrgContext,
  // Parsers / Log Sources
  LogSource,
  NewLogSource,
  UpdateLogSource,
  VrlValidationResult,
  ParserTestResult,
  TestVrlRequest,
  TestVrlLiveRequest,
  LiveTestResult,
  DeploymentResult,
  LogSourceDeployment,
  LogSourceHealth,
  SourceConfiguration,
  SourceConfigTypeInfo,
  ListSourceConfigsParams,
  RoutingRule,
  NewRoutingRule,
  CheckReachabilityRequest,
  ReachabilityResult,
  ListParserRepositoriesResponse,
  RepositoryParser,
  ListRepositoryParsersParams,
  ImportParserRequest,
  ImportParserResponse,
  ParserSyncStartResponse,
} from './types.js';

export interface NanosiemClientConfig {
  apiUrl: string;
  searchUrl?: string;
  apiKey: string;
  timeout?: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

export class NanosiemClient {
  private apiUrl: string;
  private searchUrl: string;
  private apiKey: string;
  private timeout: number;

  constructor(config: NanosiemClientConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, '');
    this.searchUrl = config.searchUrl?.replace(/\/$/, '') || this.apiUrl;
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 60000;
  }

  /** Encode a path segment to prevent path traversal */
  private encodeId(id: string): string {
    return encodeURIComponent(id);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts?: { useSearchUrl?: boolean; query?: Record<string, string | number | boolean | undefined> }
  ): Promise<ApiResponse<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const baseUrl = opts?.useSearchUrl ? this.searchUrl : this.apiUrl;

    let url = `${baseUrl}${path}`;
    if (opts?.query) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(opts.query)) {
        if (value !== undefined) {
          params.set(key, String(value));
        }
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    try {
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        return {
          success: false,
          error: {
            code: `HTTP_${response.status}`,
            message:
              (errorBody as { error?: { message?: string } }).error?.message ||
              (errorBody as { message?: string }).message ||
              response.statusText,
            details: errorBody as Record<string, unknown>,
          },
        };
      }

      // Handle 204 No Content
      if (response.status === 204) {
        return { success: true, data: undefined as T };
      }

      const data = (await response.json()) as T;
      return { success: true, data };
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        return {
          success: false,
          error: {
            code: 'TIMEOUT',
            message: `Request timed out after ${this.timeout}ms`,
          },
        };
      }

      return {
        success: false,
        error: {
          code: 'NETWORK_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
        },
      };
    }
  }

  // ==================== Search (→ search service) ====================

  async search(req: SearchRequest): Promise<ApiResponse<SearchResponse>> {
    return this.request<SearchResponse>('POST', '/api/search', {
      ...req,
      table_view: req.table_view ?? true,
      skip_field_stats: req.skip_field_stats ?? true,
    }, { useSearchUrl: true });
  }

  async searchSql(req: RawSqlRequest): Promise<ApiResponse<SearchResponse>> {
    return this.request<SearchResponse>('POST', '/api/search/sql', req, { useSearchUrl: true });
  }

  async explainQuery(query: string, timeRange: { start: string; end: string }): Promise<ApiResponse<{ sql: string; explanation?: string }>> {
    return this.request<{ sql: string; explanation?: string }>('POST', '/api/search/explain', {
      query,
      time_range: timeRange,
    }, { useSearchUrl: true });
  }

  async getFieldValues(req: FieldValuesRequest): Promise<ApiResponse<FieldValuesResponse>> {
    return this.request<FieldValuesResponse>('POST', '/api/search/field-values', req, { useSearchUrl: true });
  }

  async getFieldStats(req: FieldStatsRequest): Promise<ApiResponse<FieldStatsResponse>> {
    return this.request<FieldStatsResponse>('POST', '/api/search/field-stats', req, { useSearchUrl: true });
  }

  // ==================== Saved Searches (→ search service) ====================

  async listSavedSearches(): Promise<ApiResponse<SavedSearch[]>> {
    return this.request<SavedSearch[]>('GET', '/api/search/saved', undefined, { useSearchUrl: true });
  }

  async getSavedSearch(id: string): Promise<ApiResponse<SavedSearch>> {
    return this.request<SavedSearch>('GET', `/api/search/saved/${this.encodeId(id)}`, undefined, { useSearchUrl: true });
  }

  async createSavedSearch(req: CreateSavedSearchRequest): Promise<ApiResponse<SavedSearch>> {
    return this.request<SavedSearch>('POST', '/api/search/saved', req, { useSearchUrl: true });
  }

  async createSharedSearch(req: CreateSharedSearchRequest): Promise<ApiResponse<CreateSharedSearchResponse>> {
    return this.request<CreateSharedSearchResponse>('POST', '/api/search/share', req);
  }

  // ==================== Alerts (→ api) ====================

  async listAlerts(params?: AlertsListParams): Promise<ApiResponse<Alert[]>> {
    return this.request<Alert[]>('GET', '/api/alerts', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  async getAlert(id: string): Promise<ApiResponse<Alert>> {
    return this.request<Alert>('GET', `/api/alerts/${this.encodeId(id)}`);
  }

  async getAlertCounts(): Promise<ApiResponse<AlertCounts>> {
    return this.request<AlertCounts>('GET', '/api/alerts/counts');
  }

  // ==================== Cases (→ api) ====================

  async listCases(params?: CaseFilter): Promise<ApiResponse<CaseListResponse>> {
    const query: Record<string, string | number | boolean | undefined> = {};
    if (params) {
      if (params.status) query.status = params.status.join(',');
      if (params.severity) query.severity = params.severity.join(',');
      if (params.assigned_to) query.assigned_to = params.assigned_to;
      if (params.search) query.search = params.search;
      if (params.tags) query.tags = params.tags.join(',');
      if (params.created_after) query.created_after = params.created_after;
      if (params.created_before) query.created_before = params.created_before;
      if (params.limit) query.limit = params.limit;
      if (params.offset) query.offset = params.offset;
    }
    return this.request<CaseListResponse>('GET', '/api/cases', undefined, { query });
  }

  async getCase(id: string): Promise<ApiResponse<CaseFullResponse>> {
    return this.request<CaseFullResponse>('GET', `/api/cases/${this.encodeId(id)}`);
  }

  async getCaseStats(): Promise<ApiResponse<CaseStats>> {
    return this.request<CaseStats>('GET', '/api/cases/stats');
  }

  async createCase(req: CreateCaseRequest): Promise<ApiResponse<CaseWithDetails>> {
    return this.request<CaseWithDetails>('POST', '/api/cases', req);
  }

  async updateCase(id: string, req: UpdateCaseRequest): Promise<ApiResponse<CaseWithDetails>> {
    return this.request<CaseWithDetails>('PUT', `/api/cases/${this.encodeId(id)}`, req);
  }

  async changeCaseStatus(id: string, req: ChangeCaseStatusRequest): Promise<ApiResponse<void>> {
    return this.request<void>('POST', `/api/cases/${id}/status`, req);
  }

  async assignCase(id: string, userId: string): Promise<ApiResponse<void>> {
    return this.request<void>('POST', `/api/cases/${id}/assign`, { assigned_to: userId });
  }

  async addAlertToCase(caseId: string, req: AddAlertToCaseRequest): Promise<ApiResponse<void>> {
    return this.request<void>('POST', `/api/cases/${this.encodeId(caseId)}/alerts`, req);
  }

  async getCaseWall(id: string): Promise<ApiResponse<CaseWallEntry[]>> {
    return this.request<CaseWallEntry[]>('GET', `/api/cases/${id}/wall`);
  }

  async addCaseWallEntry(caseId: string, req: AddWallEntryRequest): Promise<ApiResponse<CaseWallEntry>> {
    return this.request<CaseWallEntry>('POST', `/api/cases/${this.encodeId(caseId)}/wall`, req);
  }

  async getRelatedCases(id: string): Promise<ApiResponse<RelatedCaseSummary[]>> {
    return this.request<RelatedCaseSummary[]>('GET', `/api/cases/${id}/related`);
  }

  async mergeCases(id: string, req: MergeCasesRequest): Promise<ApiResponse<void>> {
    return this.request<void>('POST', `/api/cases/${id}/merge`, req);
  }

  async linkNotebookToCase(caseId: string, req: LinkNotebookRequest): Promise<ApiResponse<void>> {
    return this.request<void>('POST', `/api/cases/${this.encodeId(caseId)}/notebook`, req);
  }

  // ==================== Notebooks (→ api) ====================

  async listNotebooks(params?: NotebookListParams): Promise<ApiResponse<NotebookWithOwner[]>> {
    return this.request<NotebookWithOwner[]>('GET', '/api/notebooks', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  async getNotebook(id: string): Promise<ApiResponse<NotebookWithOwner>> {
    return this.request<NotebookWithOwner>('GET', `/api/notebooks/${this.encodeId(id)}`);
  }

  async getNotebookEntries(id: string): Promise<ApiResponse<NotebookEntry[]>> {
    return this.request<NotebookEntry[]>('GET', `/api/notebooks/${id}/entries`);
  }

  async createNotebook(req: CreateNotebookRequest): Promise<ApiResponse<NotebookWithOwner>> {
    return this.request<NotebookWithOwner>('POST', '/api/notebooks', req);
  }

  async addNotebookEntry(id: string, req: AddEntryRequest): Promise<ApiResponse<NotebookEntry>> {
    return this.request<NotebookEntry>('POST', `/api/notebooks/${id}/entries`, req);
  }

  async getNotebookReferences(id: string): Promise<ApiResponse<NotebookReference[]>> {
    return this.request<NotebookReference[]>('GET', `/api/notebooks/${id}/references`);
  }

  async addNotebookReference(id: string, req: AddReferenceRequest): Promise<ApiResponse<NotebookReference>> {
    return this.request<NotebookReference>('POST', `/api/notebooks/${id}/references`, req);
  }

  async findNotebooksByReference(referenceType: string, referenceId: string): Promise<ApiResponse<NotebookWithOwner[]>> {
    return this.request<NotebookWithOwner[]>('GET', '/api/notebooks/by-reference', undefined, {
      query: { reference_type: referenceType, reference_id: referenceId },
    });
  }

  async updateNotebook(id: string, req: UpdateNotebookRequest): Promise<ApiResponse<NotebookWithOwner>> {
    return this.request<NotebookWithOwner>('PUT', `/api/notebooks/${this.encodeId(id)}`, req);
  }

  async shareNotebook(id: string, req: ShareNotebookRequest): Promise<ApiResponse<void>> {
    return this.request<void>('POST', `/api/notebooks/${id}/share`, req);
  }

  // ==================== Detections (→ api, routes use /api/rules) ====================

  async listDetections(): Promise<ApiResponse<DetectionRule[]>> {
    return this.request<DetectionRule[]>('GET', '/api/rules');
  }

  async getDetection(id: string): Promise<ApiResponse<DetectionRule>> {
    return this.request<DetectionRule>('GET', `/api/rules/${this.encodeId(id)}`);
  }

  async getDetectionMatches(id: string): Promise<ApiResponse<DetectionMatchesResponse>> {
    return this.request<DetectionMatchesResponse>('GET', `/api/rules/${id}/matches`);
  }

  // ==================== Prevalence (→ api) ====================

  async getHashPrevalence(hash: string): Promise<ApiResponse<{ data: PrevalenceData }>> {
    return this.request<{ data: PrevalenceData }>('GET', `/api/prevalence/hash/${this.encodeId(hash)}`);
  }

  async getDomainPrevalence(domain: string): Promise<ApiResponse<{ data: PrevalenceData }>> {
    return this.request<{ data: PrevalenceData }>('GET', `/api/prevalence/domain/${this.encodeId(domain)}`);
  }

  async bulkPrevalence(req: BulkPrevalenceRequest): Promise<ApiResponse<BulkPrevalenceResponse>> {
    return this.request<BulkPrevalenceResponse>('POST', '/api/prevalence/bulk', req);
  }

  async getRareArtifacts(params?: RareArtifactsQuery): Promise<ApiResponse<ArtifactListResponse>> {
    return this.request<ArtifactListResponse>('GET', '/api/prevalence/rare', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  async getNewArtifacts(params?: NewArtifactsQuery): Promise<ApiResponse<ArtifactListResponse>> {
    return this.request<ArtifactListResponse>('GET', '/api/prevalence/new', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  // ==================== Risk (→ api) ====================

  async getRiskyEntities(params?: RiskEntitiesQuery): Promise<ApiResponse<RiskEntitiesResponse>> {
    return this.request<RiskEntitiesResponse>('GET', '/api/risk/entities', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  async getRiskOverview(): Promise<ApiResponse<RiskOverviewResponse>> {
    return this.request<RiskOverviewResponse>('GET', '/api/risk/overview');
  }

  async getEntityRiskTimeline(entity: string, entityType?: string): Promise<ApiResponse<RiskEntitiesResponse>> {
    return this.request<RiskEntitiesResponse>('GET', '/api/risk/time-windowed', undefined, {
      query: { entity, entity_type: entityType },
    });
  }

  // ==================== Enrichment (→ api) ====================

  async lookupIp(ip: string): Promise<ApiResponse<IpLookupResult>> {
    return this.request<IpLookupResult>('GET', `/api/enrichment/lookup/${this.encodeId(ip)}`);
  }


  // ==================== MITRE (→ api) ====================

  async getMitreData(): Promise<ApiResponse<Record<string, unknown>>> {
    return this.request<Record<string, unknown>>('GET', '/api/mitre');
  }

  async getMitreCoverage(): Promise<ApiResponse<MitreCoverage>> {
    return this.request<MitreCoverage>('GET', '/api/mitre/coverage');
  }

  // ==================== System (→ api) ====================

  async getSourceTypes(): Promise<ApiResponse<string[]>> {
    return this.request<string[]>('GET', '/api/source-types');
  }

  async getUdmFields(): Promise<ApiResponse<UdmFieldsResponse>> {
    return this.request<UdmFieldsResponse>('GET', '/api/udm/fields');
  }

  async getExtFields(): Promise<ApiResponse<string[]>> {
    return this.request<string[]>('GET', '/api/fields/ext');
  }

  async getOrgContext(): Promise<ApiResponse<OrgContext>> {
    return this.request<OrgContext>('GET', '/api/settings/organizational-context');
  }

  async healthCheck(): Promise<ApiResponse<HealthStatus>> {
    return this.request<HealthStatus>('GET', '/health');
  }

  async getAuditTrail(params?: AuditLogQuery): Promise<ApiResponse<AuditLogResponse>> {
    return this.request<AuditLogResponse>('GET', '/api/audit', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  // ==================== Parsers / Log Sources (→ api) ====================
  // A log source is a Vector VRL parser bound to a source_type. The authoring
  // flow is: validate VRL → test against a sample → create (draft) → deploy →
  // confirm health. Save and deploy are distinct, mirroring the UI.

  async listLogSources(): Promise<ApiResponse<LogSource[]>> {
    return this.request<LogSource[]>('GET', '/api/log-sources');
  }

  async getLogSource(id: string): Promise<ApiResponse<LogSource>> {
    return this.request<LogSource>('GET', `/api/log-sources/${this.encodeId(id)}`);
  }

  async createLogSource(req: NewLogSource): Promise<ApiResponse<LogSource>> {
    return this.request<LogSource>('POST', '/api/log-sources', {
      // source_config is required by the API; default to {} for routed/HTTP.
      source_config: {},
      ...req,
    });
  }

  async updateLogSource(id: string, req: UpdateLogSource): Promise<ApiResponse<LogSource>> {
    return this.request<LogSource>('PUT', `/api/log-sources/${this.encodeId(id)}`, req);
  }

  /** Compile-check arbitrary VRL without saving. */
  async validateVrl(vrlCode: string): Promise<ApiResponse<VrlValidationResult>> {
    return this.request<VrlValidationResult>('POST', '/api/log-sources/validate-vrl', {
      vrl_code: vrlCode,
    });
  }

  /** Run VRL against one sample log line and return the parsed output. */
  async testVrl(req: TestVrlRequest): Promise<ApiResponse<ParserTestResult>> {
    return this.request<ParserTestResult>('POST', '/api/log-sources/test-vrl', req);
  }

  /** Test VRL against real recent events for a source_type (post-deploy). */
  async testVrlLive(req: TestVrlLiveRequest): Promise<ApiResponse<LiveTestResult[]>> {
    return this.request<LiveTestResult[]>('POST', '/api/log-sources/test-live', req);
  }

  /**
   * Deploy a log source to Vector. NOTE: best-effort — the API returns
   * success even if Vector is unreachable (it logs a warning). Always confirm
   * with getLogSourceHealth() before reporting the parser as live.
   */
  async deployLogSource(id: string): Promise<ApiResponse<DeploymentResult>> {
    return this.request<DeploymentResult>('POST', `/api/log-sources/${this.encodeId(id)}/deploy`);
  }

  async undeployLogSource(id: string): Promise<ApiResponse<DeploymentResult>> {
    return this.request<DeploymentResult>('POST', `/api/log-sources/${this.encodeId(id)}/undeploy`);
  }

  async getLogSourceHealth(id: string): Promise<ApiResponse<LogSourceHealth>> {
    return this.request<LogSourceHealth>('GET', `/api/log-sources/${this.encodeId(id)}/health`);
  }

  async getLogSourceDeployments(id: string): Promise<ApiResponse<LogSourceDeployment[]>> {
    return this.request<LogSourceDeployment[]>('GET', `/api/log-sources/${this.encodeId(id)}/deployments`);
  }

  // ==================== Source Configurations (→ api) ====================
  // Ingress transports (HTTP / Kafka / S3 / Pub-Sub / HEC / Vector) plus the
  // routing rules that map an incoming event to a parser's source_type.

  async listSourceConfigTypes(): Promise<ApiResponse<SourceConfigTypeInfo[]>> {
    return this.request<SourceConfigTypeInfo[]>('GET', '/api/source-configurations/types');
  }

  async listSourceConfigs(params?: ListSourceConfigsParams): Promise<ApiResponse<SourceConfiguration[]>> {
    return this.request<SourceConfiguration[]>('GET', '/api/source-configurations', undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  async listRoutingRules(sourceConfigId: string): Promise<ApiResponse<RoutingRule[]>> {
    return this.request<RoutingRule[]>('GET', `/api/source-configurations/${this.encodeId(sourceConfigId)}/rules`);
  }

  async createRoutingRule(sourceConfigId: string, req: NewRoutingRule): Promise<ApiResponse<RoutingRule>> {
    return this.request<RoutingRule>('POST', `/api/source-configurations/${this.encodeId(sourceConfigId)}/rules`, req);
  }

  /** Check whether a candidate routing rule can actually deliver to a parser. */
  async checkRoutingRuleReachability(
    sourceConfigId: string,
    req: CheckReachabilityRequest
  ): Promise<ApiResponse<ReachabilityResult>> {
    return this.request<ReachabilityResult>(
      'POST',
      `/api/source-configurations/${this.encodeId(sourceConfigId)}/rules/check-reachability`,
      req
    );
  }

  // ==================== Parser Repositories (→ api) ====================
  // Browse and import parsers from an upstream library (e.g. nano-rs/parsers).

  async listParserRepositories(): Promise<ApiResponse<ListParserRepositoriesResponse>> {
    return this.request<ListParserRepositoriesResponse>('GET', '/api/parser-repositories');
  }

  async syncParserRepository(id: string): Promise<ApiResponse<ParserSyncStartResponse>> {
    return this.request<ParserSyncStartResponse>('POST', `/api/parser-repositories/${this.encodeId(id)}/sync`);
  }

  async listRepositoryParsers(
    id: string,
    params?: ListRepositoryParsersParams
  ): Promise<ApiResponse<RepositoryParser[]>> {
    return this.request<RepositoryParser[]>('GET', `/api/parser-repositories/${this.encodeId(id)}/parsers`, undefined, {
      query: params as Record<string, string | number | boolean | undefined>,
    });
  }

  /** Import a repo parser as a draft log source. `path` may contain slashes. */
  async importParser(
    id: string,
    path: string,
    req: ImportParserRequest
  ): Promise<ApiResponse<ImportParserResponse>> {
    return this.request<ImportParserResponse>(
      'POST',
      `/api/parser-repositories/${this.encodeId(id)}/parsers/import/${this.encodeId(path)}`,
      req
    );
  }
}

Offline, synthetic recordings of backend wire contracts; no tenant data or live calls.

Source revision: nano-rs/nanosiem cc799503e (origin/main at audit), with routes checked against v1.0.6 too.

- schema: nanosiem-core/src/schema/field_universe.rs, SchemaFieldsResponse / SchemaFieldInfo. Example field paths are canonical OCSF 1.9; field metadata is representative.
- accepted/running/completed/pages: nanosiem-core/src/search/jobs.rs, AsyncSearchResponse, SearchJobStatusResponse, SearchJobResultSummary, SearchJobResultPage; nanosiem-search/src/handlers/search_jobs.rs strips private result_ref and exposes durable_result. has_more is independent of page count.
- inline: SearchResponse via nanosiem-search/src/handlers/search.rs; same result shape can be returned inside a completed job after Nano post-processing.
- closed: nanosiem-api/src/middleware/auth/enterprise_shared_auth.rs, shared_closed_route_response.

operations.json covers the read contracts exercised through MCP tool handlers: alerts.rs Vec<Alert>, enterprise_shared_detection_dashboard.rs / enterprise_shared_detections.rs rule arrays, prevalence/types.rs PrevalenceResponse, enterprise_shared_enrichment_risk.rs EntityContextResponse, enterprise_shared_cases_notebooks.rs TenantCaseListResponse. Values are synthetic; no assertion relies on a live provider being configured or live data being present.

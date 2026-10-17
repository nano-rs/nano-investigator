# NAN-3944 lake tools

Historical NAN-3944 audit. Its ingestion rows describe the earlier tool surface and are superseded by the [NAN-4015 ingestion matrix](docs/ingestion-capability-matrix.md), including removed authoring tools and renamed read arguments.

Contract references: nanosiem origin/main cc799503e (main.rs → routes.rs → enterprise_shared_auth.rs and tenant adapter fences), open core tag v1.0.6. No live tenant requests made. “Mounted” means HTTP 200 is expected from the static route contract with the required permission/entitlement; it records static route availability, not proof of a successful live operation. Permissions, entitlements and configured providers still apply.

| tool | endpoint | hosted | open core | problem | fix |
|---|---|---|---|---|---|
| capabilities | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| hashes | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| strings | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| filetype | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| exiftool | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| yara | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| olevba | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| pdfid | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| pe_info | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| run_all | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| record_lead | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| note_trail | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| record_knowledge | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| record_suppression | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| list_alerts | /api/alerts | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_alert | /api/alerts/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_alert_counts | /api/alerts/counts | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_cases | /api/cases | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| get_case | /api/cases/{id} | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| review_case | /api/cases/{id}; /api/cases/{id}/wall; /api/notebooks; /api/notebooks/{id}/entries; /api/notebooks/{id}/references | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| get_case_stats | /api/cases/stats | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| get_related_cases | /api/cases/{id}/related | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| create_case | /api/cases | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| update_case | /api/cases/{id} | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| change_case_status | /api/cases/{id}/status | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| assign_case | /api/cases/{id}/assign | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| add_alert_to_case | /api/cases/{caseId}/alerts | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| add_case_wall_entry | /api/cases/{caseId}/wall | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| merge_notebook_into_case | /api/cases/{caseId}/notebook; /api/cases/{caseId}/notebook/merge | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| merge_cases | /api/cases/{id}/merge | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| get_dashboard_schema | none (local schema/validation) | local; backend independent | local; backend independent | none | unchanged |
| validate_dashboard | none (local schema/validation) | local; backend independent | local; backend independent | none | unchanged |
| dashboard_panel_query | /api/dashboards/panel/query | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_dashboards | /api/dashboards | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_dashboard | /api/dashboards/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| create_dashboard | /api/dashboards | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| update_dashboard | /api/dashboards/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_detections | /api/rules | mounted; permission/entitlement dependent | mounted; permission dependent | implicit first page | explicit limit/offset; return rules with page metadata |
| get_detection | /api/rules/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_detection_matches | /api/rules/{id}/matches | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| lookup_ioc | /api/threat-intel/lookup | mounted; permission/entitlement dependent | 404 (enterprise only) | missing TI tool | new tool: tenant threat-intel/lookup; explicit open-core gate |
| get_entity_context | /api/entities/{entityType}/{value}/context | mounted; permission/entitlement dependent | 404 (enterprise only) | partial composite silently hid errors | use backend entity context; explicit open-core gate |
| lookup_ip | /api/enrichment/lookup/{ip} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_mitre_technique | /api/mitre | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_mitre_coverage | /api/mitre/coverage | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_notebooks | /api/notebooks | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| get_notebook | /api/notebooks/{id} | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| get_notebook_entries | /api/notebooks/{id}/entries | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| find_notebooks_by_reference | /api/notebooks/by-reference | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| create_notebook | /api/notebooks | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| add_notebook_entry | /api/notebooks/{id}/entries | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| add_notebook_reference | /api/notebooks/{id}/references | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| update_notebook | /api/notebooks/{id} | 403 (interactive session required) | not available in open core | API keys cannot mutate this resource | explicit hosted gate; use nano UI |
| share_notebook | /api/notebooks/{id}/share | mounted; permission/entitlement dependent | not available in open core | enterprise-only surface | NANOSIEM_DEPLOYMENT=open-core gate; use alerts |
| onboarding_requirements | none (local schema/validation) | local; backend independent | local; backend independent | none | unchanged |
| import_credential_from_file | /api/credentials | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| create_credential | /api/credentials | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| create_source_config | /api/source-configurations | 409 platform_managed | mounted; permission dependent | hosted transports managed by platform | explicit hosted gate; use source onboarding |
| list_log_sources | /api/log-sources | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_log_source | /api/log-sources/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| validate_vrl | /api/log-sources/validate-vrl | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| test_parse_sample | /api/log-sources/test-vrl | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| test_parse_live | /api/log-sources/test-live | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| create_log_source | /api/log-sources | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| update_log_source | /api/log-sources/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| publish_log_source | /api/log-sources/{id}/publish | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_log_source_draft_status | /api/log-sources/{id}/draft-status | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| deploy_log_source | /api/log-sources/{id}/deploy | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| undeploy_log_source | /api/log-sources/{id}/undeploy | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_log_source_health | /api/log-sources/{id}/health | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_log_source_deployments | /api/log-sources/{id}/deployments | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_source_config_types | /api/source-configurations/types | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_source_configs | /api/source-configurations | 200 [] (platform managed) | mounted; permission dependent | no tenant-owned transports | document hosted platform ownership |
| create_routing_rule | /api/source-configurations/{sourceConfigId}/rules | 409 platform_managed | mounted; permission dependent | hosted transports managed by platform | explicit hosted gate; use source onboarding |
| check_rule_reachability | /api/source-configurations/{sourceConfigId}/rules/check-reachability | 409 platform_managed | mounted; permission dependent | hosted transports managed by platform | explicit hosted gate; use source onboarding |
| deploy_source_config | /api/source-configurations/{id}/deploy | 409 platform_managed | mounted; permission dependent | hosted transports managed by platform | explicit hosted gate; use source onboarding |
| undeploy_source_config | /api/source-configurations/{id}/undeploy | 409 platform_managed | mounted; permission dependent | hosted transports managed by platform | explicit hosted gate; use source onboarding |
| list_parser_repositories | /api/parser-repositories | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| sync_parser_repository | /api/parser-repositories/{id}/sync | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_repository_parsers | /api/parser-repositories/{id}/parsers | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| import_parser | /api/parser-repositories/{id}/parsers/import/{path} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_prevalence | /api/prevalence/hash/{hash}; /api/prevalence/domain/{domain} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_rare_artifacts | /api/prevalence/rare | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_new_artifacts | /api/prevalence/new | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| hunt_build_census | /api/hunts/profile/census | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| hunt_huntable_surface | /api/hunts/profile/surface | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| hunt_save_profile | /api/hunts/profile | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| hunt_propose_drafts | /api/hunts/drafts | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_risky_entities | /api/risk/entities | mounted; permission/entitlement dependent | 404 (enterprise only) | legacy transport / OCSF guidance | shared transport and updated guidance; stable name; explicit open-core gate |
| get_risk_overview | /api/risk/overview | mounted; permission/entitlement dependent | 404 (enterprise only) | legacy transport / OCSF guidance | shared transport and updated guidance; stable name; explicit open-core gate |
| get_entity_risk_timeline | /api/entities/{entityType}/{entity}/risk-timeline | mounted; permission/entitlement dependent | 404 (enterprise only) | legacy route returned leaderboard rather than timeline | entity risk-timeline route; open-core gate |
| get_entity_risk_activity | /api/risk/entity-activity | mounted; permission/entitlement dependent | 404 (enterprise only) | legacy transport / OCSF guidance | shared transport and updated guidance; stable name; explicit open-core gate |
| reset_entity_risk | /api/risk/clear | mounted; permission/entitlement dependent | 404 (enterprise only) | legacy transport / OCSF guidance | shared transport and updated guidance; stable name; explicit open-core gate |
| search_sql | /api/search/sql | route_not_available | mounted; permission dependent | raw SQL closed on hosted | explicit hosted gate / backend unavailable error |
| get_schema | /api/schema/fields; /api/fields/ext | mounted; permission/entitlement dependent | mounted; permission dependent | legacy schema fields | /api/schema/fields; canonical wire type; legacy output aliases |
| search | /api/search; /api/search/jobs/{id}; /api/search/jobs/{id}/results/{page} | mounted; permission/entitlement dependent | mounted; permission dependent | job envelope mistaken for rows | bounded poll + verified result pages |
| explain_query | /api/search/explain | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_field_values | /api/search/field-values | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| list_saved_searches | /api/search/saved | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_saved_search | /api/search/saved/{id} | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| save_search | /api/search/saved | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| create_shared_search | /api/search/share | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_source_types | /api/source-types | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| get_org_context | /api/settings/organizational-context | route_not_available / 403 | mounted; permission dependent | not a ported tenant surface | explicit hosted unavailable gate |
| health_check | /health | gateway dependent | mounted; permission dependent | public health routing varies | preserve HTTP diagnostics |
| get_audit_trail | /api/audit | mounted; permission/entitlement dependent | mounted; permission dependent | legacy transport / OCSF guidance | shared transport and updated guidance; stable name |
| whois | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| dns_lookup | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| reverse_dns | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |
| asn_lookup | local filesystem / validated local binaries (no lake API) | local; backend independent | local; backend independent | none | unchanged |

No tool renames. Added lookup_ioc. Legacy schema resource URI and SDK type aliases retained.

Smoke: `node scripts/live-smoke.mjs --url https://us.nano.rs/t/b12 --key-file /path/to/b12-key --deployment hosted`; repeat with `--url <CT108 API URL> --key-file /path/to/CT108-key --deployment open-core`. The coordinator supplies endpoints/keys and runs these; no publish or desktop pin change in this lane.


Validation: 210 tests passed in 10 touched suites (`vitest --maxWorkers=2 --minWorkers=1`); all five packages built and typechecked, followed by final core/MCP rebuild and MCP typecheck. `git diff --check` and smoke-script syntax/usage checks passed. No tenant API calls, npm publication, Slack posts, desktop edits, or write-mode formatters.

Release: investigator-core 0.2.0 and investigator-mcp-server 0.2.0. The local hunt/recon/artifacts servers have no lake HTTP contracts and do not need releases. Schema wire types and `list_detections` output changed, so these are minor releases. Rule listings return `{rules, limit, offset, may_have_more, guidance}`; filters apply to each page. Legacy `source_type` search arguments now fail with guidance to scope `metadata.log_source` in the query; previously the backend silently ignored the argument. All tool names and the schema resource URI are retained.

Coordinator: build with `pnpm build`, run the two smoke commands above with appropriately scoped API keys (hosted entity context needs risk:view, alerts:view, cases:view and detections:view), then publish core before MCP and update desktop pins in the separate release lane. A provider-backed TI lookup is available through `lookup_ioc`; it is intentionally not triggered by the smoke script because configured providers may incur usage charges. Hosted browser-only case/notebook writes and platform-owned source transport mutations remain unavailable to this API-key client and return explicit guidance.

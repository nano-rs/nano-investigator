# Changelog

## Ingestion diagnostics (NAN-4015)

Read pipeline drafts, inputs, runtime capabilities, release rollouts, Add data delivery, source onboarding plans and synced parser repositories. Tool names and schemas align with nanodac. Ingestion writes and legacy transport/credential onboarding shortcuts move to nano Desktop or nanodac; see [migration details](docs/ingestion-capability-matrix.md#migration).

## investigator-core 0.2.0 / investigator-mcp-server 0.2.0

- Support lean-lake durable search admission, status polling and verified result pages. Preserve the 1000-row interactive ceiling, fail closed on inconsistent/oversized pages, and report timeout/job failures without returning partial results.
- Preserve tenant path base URLs; send X-API-Key and a curl-compatible User-Agent. Refuse redirects with credentials. Normalize hosted route_not_available responses.
- Reject the legacy separate source_type argument with guidance to use metadata.log_source in the query; the lake backend otherwise silently ignores it.
- Discover canonical OCSF 1.9 fields through /api/schema/fields. Update query examples, parser guidance and investigation prompts; retain legacy schema URI/type/output aliases for compatibility.
- Use full backend entity context and the real entity risk timeline route. Add lookup_ioc for tenant TI providers and correct permission metadata.
- Gate absent open-core enterprise features and hosted mutations requiring an interactive session. Add detection rule pagination (list_detections now returns rules and page metadata).
- Add offline handler-shaped fixtures and coordinator-only live smoke. No tool renames. Other server packages are local tools with no lake endpoints and remain unchanged.

Publication and desktop version pins are deferred to the coordinator after hosted/open-core live smoke.

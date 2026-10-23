export const SQL_GUIDE_URI = 'nano://sql-guide';
export const SQL_GUIDE_RESOURCE = {
  uri: SQL_GUIDE_URI, name: 'Lake query guide',
  description: 'Lake query guide', mimeType: 'text/markdown',
};
export const SQL_GUIDE_CONTENT = `# Lake query guide

Use lake_sql for sealed-hour investigations and search (nPL) for recent unsealed events. Omit sql on lake_sql to discover authorized tables. Use a single authorized table and WHERE {window}; do not add your own time predicate or a subquery.
Read get_schema for canonical OCSF 1.9 fields. Never assume legacy database tables, JSON storage layouts or aggregate functions exist.
Examples:
actor.user.name="admin" | stats count by device.hostname | sort -count | head 20
src_endpoint.ip="192.0.2.1" | table time, dst_endpoint.ip, dst_endpoint.port
Supply start_time and end_time. Results are bounded to 1000 rows. Aggregate before returning data, and sort before head for meaningful top-N results.
Use bounded lake_sql to inspect prevalence and IOC ingest stamps first, labeled prevalence at ingest time (stamp). Heavy cell tools are narrow exceptions: prevalence only for current counts or unstamped (65535) artifacts already found; risk_scores for a specific suspicious entity; resolve_identity at the event timestamp; lookup for a specific current snapshot question. Each requires a one-sentence reason, explicit entities (max 10), default 24 h and cap 7 d unless widen_reason. Echo the effective window. Budgets: 6/API key/rolling hour, 30/tenant/UTC day, one concurrent/tool/tenant; back off on budget without retry.
search_sql remains available for deployments that support it, subject to search:sql permission. Use only the schema and SQL dialect that deployment documents.
`;

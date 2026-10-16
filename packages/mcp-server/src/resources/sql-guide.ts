export const SQL_GUIDE_URI = 'nano://sql-guide';
export const SQL_GUIDE_RESOURCE = {
  uri: SQL_GUIDE_URI, name: 'Lake query guide',
  description: 'Lake query guide', mimeType: 'text/markdown',
};
export const SQL_GUIDE_CONTENT = `# Lake query guide

Use search (nPL) for lake investigations. Hosted tenants do not expose raw SQL.
Read get_schema for canonical OCSF 1.9 fields. Never assume legacy database tables, JSON storage layouts or aggregate functions exist.
Examples:
actor.user.name="admin" | stats count by device.hostname | sort -count | head 20
src_endpoint.ip="192.0.2.1" | table time, dst_endpoint.ip, dst_endpoint.port
Supply start_time and end_time. Results are bounded to 1000 rows. Aggregate before returning data, and sort before head for meaningful top-N results.
Use get_prevalence for artifact prevalence and get_entity_context for identity and risk context.
search_sql remains available for deployments that support it, subject to search:sql permission. Use only the schema and SQL dialect that deployment documents.
`;

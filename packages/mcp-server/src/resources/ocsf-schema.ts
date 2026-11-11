/** OCSF field reference (MCP resource). */
export const OCSF_SCHEMA_URI = 'nanosiem://schema/ocsf';
/**
 * Pre-0.3.1 URI for the same content. Still readable so existing clients and
 * saved prompts keep working, but no longer listed. Deprecated.
 */
export const LEGACY_SCHEMA_URI = 'nanosiem://schema/udm';
export const OCSF_SCHEMA_RESOURCE = {
  uri: OCSF_SCHEMA_URI, name: 'OCSF 1.9 Field Reference',
  description: 'Canonical lake field paths; use get_schema for the deployment field universe.',
  mimeType: 'text/markdown',
};
export const OCSF_SCHEMA_CONTENT = `# OCSF 1.9 investigation fields
Read get_schema before building queries. Use exact canonical paths exposed by that deployment.
- actor.user.name: acting user
- src_endpoint.ip, dst_endpoint.ip: network endpoints
- device.hostname: device identity
- metadata.log_source: log source
- process.file.path, process.cmd_line: executable and command line
- time, class_uid, activity_id, severity_id: event classification
Use nPL search with explicit time bounds and a limit of at most 1000.
Example: actor.user.name="admin" | stats count by device.hostname | sort -count | head 20
Example: src_endpoint.ip="192.0.2.1" | table time, dst_endpoint.ip, dst_endpoint.port
Cross-class questions: OR the class-specific paths, e.g. (actor.user.name="x" OR user.name="x").
Event semantics are OCSF enums, not strings: class_uid/activity_id (3002 + activity_id=1 = logon),
status_id (1 Success, 2 Failure), disposition_id (2 Blocked, 1 Allowed), logon_type_id (2/10 interactive, 3 network).
Never assume a field exists: check get_schema and get_field_values.
`;

/** OCSF field reference (MCP resource). */
export const OCSF_SCHEMA_URI = 'nanosiem://schema/ocsf';
/**
 * Pre-0.3.1 URI for the same content. Still readable so existing clients and
 * saved prompts keep working, but no longer listed. Deprecated.
 */
export const LEGACY_SCHEMA_URI = 'nanosiem://schema/udm';
export const OCSF_SCHEMA_RESOURCE = {
  uri: OCSF_SCHEMA_URI, name: 'OCSF 1.9 Field Reference',
  description: 'Canonical OCSF field paths for nPL; use get_schema for the deployment field universe.',
  mimeType: 'text/markdown',
};
export const OCSF_SCHEMA_CONTENT = `# OCSF 1.9 investigation fields
Read get_schema before building queries. Use exact canonical paths exposed by that deployment.
- actor.user.name: acting user (process, file, registry, network, API activity)
- user.name: the account a logon is for. Authentication (3002) and Authorize Session (3003) put it here; actor.user.name is empty on them
- src_endpoint.ip, dst_endpoint.ip: network endpoints
- device.hostname: the endpoint an event happened on; src_endpoint.hostname, dst_endpoint.hostname: network peers
- metadata.log_source: log source
- process.file.path, process.cmd_line: executable and command line
- time, class_uid, activity_id, severity_id: event classification
Use nPL search with explicit time bounds and a limit of at most 1000.
Example: (actor.user.name="admin" OR user.name="admin") | stats count by device.hostname | sort -count | head 20
Example: src_endpoint.ip="192.0.2.1" | table time, dst_endpoint.ip, dst_endpoint.port
Cross-class questions: OR the class-specific paths. User: (actor.user.name="x" OR user.name="x"). Host: (device.hostname="x" OR src_endpoint.hostname="x" OR dst_endpoint.hostname="x").
Event semantics are OCSF enums, not strings: class_uid/activity_id (3002 + activity_id=1 = logon),
status_id (1 Success, 2 Failure), disposition_id (1 Allowed, 8 Approved = allowed; 2 Blocked, 3 Quarantined, 4 Isolated, 6 Dropped, 25 Rejected, 26 Unauthorized = blocked; when disposition_id=0 fall back to action_id 1 Allowed / 2 Denied),
logon_type_id (interactive: 2, 10 RDP, 11, 12 cached; network: 3, 8 cleartext).
Never assume a field exists: check get_schema and get_field_values.
`;

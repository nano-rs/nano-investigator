/** OCSF reference. Legacy export and URI retained for existing clients. */
export const UDM_SCHEMA_URI = 'nanosiem://schema/udm';
export const UDM_SCHEMA_RESOURCE = {
  uri: UDM_SCHEMA_URI, name: 'OCSF 1.9 Field Reference',
  description: 'Canonical lake field paths; use get_schema for the deployment field universe.',
  mimeType: 'text/markdown',
};
export const UDM_SCHEMA_CONTENT = `# OCSF 1.9 investigation fields
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
Never assume a field exists: check get_schema and get_field_values.
`;

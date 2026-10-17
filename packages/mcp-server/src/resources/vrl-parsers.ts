export const VRL_PARSERS_URI = 'nanosiem://reference/vrl-parsers';
export const VRL_PARSERS_RESOURCE = {
  uri: VRL_PARSERS_URI, name: 'OCSF parser authoring guide',
  description: 'OCSF parser authoring guide', mimeType: 'text/markdown',
};
export const VRL_PARSERS_CONTENT = `# OCSF parser authoring guide

Use canonical OCSF 1.9 output. Read get_schema and inspect an existing parser for the target source before authoring.
Map actor.user.name, src_endpoint.ip, dst_endpoint.ip, device.hostname, metadata.log_source, process.file.path and process.cmd_line as appropriate.
Preserve the original message. Do not create a legacy normalization wrapper or invent event classification values.
Use nanodac pipeline validation and preview tools or nano Desktop Pipelines against representative source samples. Inspect actual output, class_uid, activity_id and field types. Do not claim a parser works from validation alone.
Inspect the saved draft separately from the active version and release rollouts. Review a frozen preview, then release the reviewed snapshot with expected_updated_at. Observe application and fresh events before reporting success; rollback creates a new release. Investigator reads status; use Desktop or nanodac for pipeline writes. Hosted push credentials, cloud pulls and connectors are managed in Add data, not by deploying a shared ingress.
Use only pure VRL transformations; never file, shell, network or environment access. Validate timestamps, malformed input and optional fields explicitly.
`;

export const VRL_PARSERS_URI = 'nanosiem://reference/vrl-parsers';
export const VRL_PARSERS_RESOURCE = {
  uri: VRL_PARSERS_URI, name: 'OCSF parser authoring guide',
  description: 'OCSF parser authoring guide', mimeType: 'text/markdown',
};
export const VRL_PARSERS_CONTENT = `# OCSF parser authoring guide

Use canonical OCSF 1.9 output. Read get_schema and inspect an existing parser for the target source before authoring.
Map actor.user.name, src_endpoint.ip, dst_endpoint.ip, device.hostname, metadata.log_source, process.file.path and process.cmd_line as appropriate.
Preserve the original message. Do not create a legacy normalization wrapper or invent event classification values.
Use validate_vrl, then test_parse_sample against representative source samples. Inspect actual output, class_uid, activity_id and field types. Do not claim a parser works from validation alone.
Save the working copy, publish it, then confirm health. Deploy alone may ship a previously active version. Source transports and credentials need their own deployment and permission checks.
Use only pure VRL transformations; never file, shell, network or environment access. Validate timestamps, malformed input and optional fields explicitly.
`;

/**
 * Guided parser-authoring prompt.
 *
 * Scripts the validate → test → save → publish → confirm loop so an analyst can
 * say "build a parser for this log" and get a disciplined, validator-first
 * workflow instead of a one-shot guess.
 */


const UDM_OUTPUT_CONTRACT = `**Output contract — UDM deployment.** Map into \`.udm.*\`:
   - \`.udm.timestamp\` — a STRING in EXACTLY \`%Y-%m-%d %H:%M:%S\`. Normalize with \`parse_timestamp()\` + \`format_timestamp!()\` even for ISO-8601 input; fall back to \`now()\`.
   - \`.udm.event_type\` — derived from the data, never pre-seeded to "unknown".
   - Well-known fields into their UDM names; source-specific extras into \`.ext.*\`; debug into \`.metadata.*\`.
   - \`.message = raw_log\` as the last statement, so the raw line survives.`;

const OCSF_OUTPUT_CONTRACT = `**Output contract — OCSF deployment.** This deployment stores OCSF, so the parser emits an OCSF EVENT OBJECT, not \`.udm.*\`. Setting \`.udm.*\` here produces a parser that validates and deploys but populates nothing.
   - Assign the whole event: \`. = { "class_uid": …, "category_uid": …, "activity_id": …, "type_uid": …, "severity_id": …, "time": …, "metadata": { … }, … }\`.
   - Pick the OCSF class for the source (1007 Process Activity, 3002 Authentication, 4001 Network Activity, 6003 API Activity, …) and set \`class_uid\`/\`category_uid\`/\`type_uid\` consistently. \`type_uid = class_uid * 100 + activity_id\`.
   - \`metadata\` must carry \`version\` ("1.9.0"), \`uid\` (use \`uuid_v4()\` — never \`string()\` on an integer record id), and \`product: { name, vendor_name }\`.
   - Map entities to their canonical OCSF paths: \`src_endpoint.ip\`, \`dst_endpoint.ip\`, \`actor.user.name\`, \`actor.process.cmd_line\`, \`device.hostname\`, \`file.path\`. Call \`get_schema\` for the exact promoted set — anything not promoted belongs under \`unmapped.*\`.
   - Keep the raw line: set \`message\` and \`raw_data\` from it.
   - Handle the parse-failure branch too: emit a well-formed event with \`activity_id: 99\` and the raw log preserved, rather than aborting.`;

const UNKNOWN_OUTPUT_CONTRACT = `**Output contract — DETERMINE THIS FIRST.** Call \`get_schema\` before drafting and read its \`schema\` field:
   - \`udm\` -> map into \`.udm.*\` (\`.udm.timestamp\` as \`%Y-%m-%d %H:%M:%S\`, \`.udm.event_type\` from the data, extras in \`.ext.*\`, \`.message = raw_log\` last).
   - \`ocsf\` -> assign a whole OCSF event object (\`class_uid\`, \`category_uid\`, \`activity_id\`, \`type_uid\`, \`metadata.version\`/\`uid\`/\`product\`, entities on canonical paths, raw line in \`message\`/\`raw_data\`) and NEVER set \`.udm.*\`.
   The two are not interchangeable: the wrong one deploys cleanly and populates nothing.`;

export const BUILD_PARSER_PROMPT = {
  name: 'build_parser',
  description:
    'Structured workflow for onboarding a nano log source (Vector VRL parser) from a sample log: read the VRL guide, draft, validate, test against the sample, save as a working copy, WIRE ROUTING (routing rule on the ingress), deploy the ingress and PUBLISH the parser, and confirm events actually flow.',
  arguments: [
    {
      name: 'source_type',
      description: 'The source_type this parser is for (e.g. "apache_http_server", "okta_system_log").',
      required: true,
    },
    {
      name: 'sample_log',
      description: 'A representative raw log line (or a few) to parse and test against.',
      required: false,
    },
  ],
};

/**
 * Build the parser-authoring workflow, targeted at the deployment's schema.
 *
 * The output contract is not the same on both: a UDM deployment wants
 * `.udm.*` fields, while an OCSF one wants the parser to emit an OCSF event
 * object outright (`class_uid`, `metadata`, `actor.*`, …) and never touch
 * `.udm`. Handing an OCSF deployment the UDM instructions produces a parser
 * that validates, deploys, and silently populates nothing.
 */
export function getBuildParserPrompt(
  args: Record<string, string | undefined>,
  schema: 'udm' | 'ocsf' | 'unknown' = 'unknown',
): {
  description: string;
  messages: Array<{ role: 'user'; content: { type: 'text'; text: string } }>;
} {
  const sourceType = args.source_type ?? 'unknown';
  const sampleLog = args.sample_log?.trim();
  const outputContract =
    schema === 'ocsf'
      ? OCSF_OUTPUT_CONTRACT
      : schema === 'udm'
        ? UDM_OUTPUT_CONTRACT
        : UNKNOWN_OUTPUT_CONTRACT;

  return {
    description: `Build a parser for ${sourceType}`,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: `You are building a nano log-source parser (Vector VRL) for source_type "${sourceType}".

${
  sampleLog
    ? `Sample log to parse:\n\`\`\`\n${sampleLog}\n\`\`\`\n`
    : `No sample log was provided. Ask me to paste one or two representative raw log lines before drafting — you cannot reliably write or test a parser without a real sample.\n`
}
Follow this workflow. Do NOT skip validation or testing.

1. **READ THE GUIDE** — load the \`nanosiem://reference/vrl-parsers\` resource. It has the input/output contract, the rules nano's VRL validator enforces, the forbidden functions, and copy-paste skeletons. Then call \`get_schema\` for THIS deployment's real field names — do not write field names from memory.

2. **CHECK FOR DUPLICATES** — call \`list_log_sources\` and check whether one already claims "${sourceType}" (as its \`source_type\`, or — for a routed feed — in its \`match_values\`; \`get_log_source\` to inspect). If so, edit it (\`get_log_source\` → \`update_log_source\`) rather than create a duplicate.

3. **DRAFT** the VRL. Write a GENERIC parser that handles all event types for this source, not just the sample. Detect the format (JSON / XML / syslog / key-value / CSV) from the sample and pick the matching skeleton. Never set \`.source_type\` — ingestion owns it.

${outputContract}

4. **VALIDATE** — call \`validate_vrl\`. If \`valid\` is false, fix every diagnostic (they carry line/col + a code like E651/E203) and re-validate. Loop until valid.

5. **TEST** — call \`test_parse_sample\` with the VRL and the sample line. Inspect the parsed output against the output contract above: are IPs, users, timestamps and the event/activity classification mapped correctly? An \`extracted_field_count\` of 0, or output carrying nothing but the raw message, means the parser isn't actually extracting — fix it. Iterate steps 4–5 until the mapping is right.

6. **SAVE** — call \`create_log_source\` with \`source_type: "routed"\` and \`match_values: ["${sourceType}"]\` (plus name + parser_vrl). This is the routed-feed convention: events arrive on a shared HTTP ingress tagged with a source_type, and the central router dispatches them to the parser whose \`match_values\` include that tag. \`source_type: "routed"\` is the sentinel that opts the parser into that router. Saves a WORKING COPY; not live yet. (Only skip this for a dedicated pull transport — Kafka/S3/PubSub — where the transport's own config carries the routing.)

7. **WIRE ROUTING** — a parser with no route deploys DEAF (healthy-looking, zero events). Find the ingress the sender will hit: \`list_source_configs\` (usually the \`http\` transport). Confirm what tag the sender sends — for HTTP that's the \`X-Source-Type\` header; ASK me if it might differ from "${sourceType}". Then \`check_rule_reachability\`, and \`create_routing_rule\` on that source config: \`{ match_field: "source_type", match_type: "exact", match_value: "<the sender's tag>", target_source_type: "<the sender's tag>" }\` (target must equal one of the parser's match_values).

8. **SHIP BOTH LAYERS** — \`deploy_source_config\` on the ingress (so the new rule takes effect), THEN \`publish_log_source\` on the parser (so the router picks up its match_values and the VRL you just wrote goes live). Order matters. Both are best-effort.

   Use \`publish_log_source\`, NOT \`deploy_log_source\`. Saving writes a working copy; deploy ships the previously PUBLISHED version, so on any parser that has been published before it silently pushes the old VRL and still reports success. Only publish promotes the working copy. Same rule every time you edit an existing parser's VRL later.

9. **CONFIRM** — publish is best-effort at the Vector reload, so wait ~1 minute then call \`get_log_source_health\`. Report honestly: "published, N events seen" vs "published but no_data — events may not be arriving, or the sender's tag may not match the rule." Parsing is not retroactive: events that arrived BEFORE the publish stay unparsed, so judge only events ingested after it. If \`no_data\` persists, re-check the sender's tag against the rule with \`check_rule_reachability\`; if events arrive but come out unparsed, call \`get_log_source_draft_status\` — \`has_draft_changes: true\` means the VRL never went live.

Present the VRL and the test output at step 5 before saving. Confirm with me before shipping (steps 7–8) — publishing pushes live config into the ingestion pipeline.`,
        },
      },
    ],
  };
}

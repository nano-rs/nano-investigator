/**
 * Guided parser-authoring prompt.
 *
 * Scripts the validate → test → save → deploy → confirm loop so an analyst can
 * say "build a parser for this log" and get a disciplined, validator-first
 * workflow instead of a one-shot guess.
 */

export const BUILD_PARSER_PROMPT = {
  name: 'build_parser',
  description:
    'Structured workflow for building a nano log-source parser (Vector VRL) from a sample log: read the VRL guide, draft, validate, test against the sample, save as a draft, deploy, and confirm events flow.',
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

export function getBuildParserPrompt(args: Record<string, string | undefined>): {
  description: string;
  messages: Array<{ role: 'user'; content: { type: 'text'; text: string } }>;
} {
  const sourceType = args.source_type ?? 'unknown';
  const sampleLog = args.sample_log?.trim();

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

1. **READ THE GUIDE** — load the \`nanosiem://reference/vrl-parsers\` resource. It has the input/output contract, the rules nano's VRL validator enforces, the forbidden functions, and copy-paste skeletons. Also skim \`nanosiem://schema/udm\` for the right UDM field names.

2. **CHECK FOR DUPLICATES** — call \`list_log_sources\` (filter by source_type "${sourceType}"). If a parser already exists, ask whether to edit it (\`get_log_source\` → \`update_log_source\`) rather than create a new one.

3. **DRAFT** the VRL. Write a GENERIC parser that handles all event types for this source, not just the sample. Detect the format (JSON / XML / syslog / key-value / CSV) from the sample and pick the matching skeleton. Always: read \`.message\`, normalize \`.udm.timestamp\` to \`%Y-%m-%d %H:%M:%S\`, set \`.udm.event_type\` from the data, and \`.message = raw_log\` at the end. Never set \`.source_type\`.

4. **VALIDATE** — call \`validate_vrl\`. If \`valid\` is false, fix every diagnostic (they carry line/col + a code like E651/E203) and re-validate. Loop until valid.

5. **TEST** — call \`test_parse_sample\` with the VRL and the sample line. Inspect \`output.udm.*\`: are IPs, users, timestamps, event_type mapped correctly? \`extracted_field_count\` of 0 or a near-empty \`output.udm\` means the parser isn't actually extracting — fix it. Iterate steps 4–5 until the mapping is right.

6. **SAVE** — call \`create_log_source\` (name, source_type "${sourceType}", parser_vrl). This saves a DRAFT; it is not live yet.

7. **DEPLOY** — call \`deploy_log_source\` with the new id.

8. **CONFIRM** — deploy is best-effort, so wait ~1 minute then call \`get_log_source_health\`. Report honestly: "deployed, N events seen" vs "deployed but health is no_data — events may not be routed here yet." If \`no_data\` persists, check routing with \`list_source_configs\` / \`check_rule_reachability\` and offer to add a \`create_routing_rule\` mapping events to source_type "${sourceType}".

Present the VRL and the test output at step 5 before saving, and confirm with me before deploying (step 7).`,
        },
      },
    ],
  };
}

/**
 * VRL Parser Authoring Reference — the steering doc that gives an MCP client
 * the same guardrails the Enterprise parser AI gets internally, so Claude can
 * hand-author Vector VRL parsers that pass nano's validator on the first try.
 *
 * Distilled from the nano parser-agent system prompt + the VRL validator's
 * hard blocks (nanosiem-core/src/parsers/validator.rs). Keep in sync when the
 * validator's blocked-function set or required-output contract changes.
 */

export const VRL_PARSERS_URI = 'nanosiem://reference/vrl-parsers';

export const VRL_PARSERS_RESOURCE = {
  uri: VRL_PARSERS_URI,
  name: 'VRL Parser Authoring Guide',
  description:
    'How to write, validate, test, and deploy a nano log-source parser (Vector VRL): the input/output contract, the rules the validator enforces, forbidden functions, and copy-paste skeletons. Read this before writing any parser_vrl.',
  mimeType: 'text/markdown',
};

export const VRL_PARSERS_CONTENT = `# Building nano log-source parsers (VRL)

A **log source** is a Vector VRL parser bound to a \`source_type\`. This guide lets you hand-author one through the parser tools — no AI wizard required. Follow it and nano's VRL validator passes on the first or second try.

## The authoring loop

1. **\`list_log_sources\`** (and \`get_source_types\`) — don't duplicate an existing \`source_type\`.
2. **Draft the VRL** using this guide.
3. **\`validate_vrl\`** — compile-check. Fix every error before moving on.
4. **\`test_parse_sample\`** — paste a real log line, inspect \`output.udm.*\`. Iterate 3–4 until the mapping is right.
5. **\`create_log_source\`** — saves a DRAFT (validated, not deployed).
6. **\`deploy_log_source\`** — pushes config to Vector.
7. **\`get_log_source_health\`** — deploy is *best-effort*; confirm events actually flow before declaring success.

## Input contract

- The raw log arrives in **\`.message\`**. Read it once: \`raw_log = string!(.message)\`.
- **\`.source_type\` is already set** by ingestion. NEVER assign it.
- Initialize \`.udm = {}\`, \`.ext = {}\`, \`.metadata = {}\` at the top.
- Map well-known fields into \`.udm.*\` (the Unified Data Model — see \`nanosiem://schema/udm\`). Put source-specific extras in \`.ext.*\`. Put debug info in \`.metadata.*\`.

## Required output — every event, no exceptions

- **\`.message\`** — preserve the raw log: end the parser with \`.message = raw_log\`.
- **\`.udm.timestamp\`** — a STRING in EXACTLY \`%Y-%m-%d %H:%M:%S\`. ALWAYS normalize with \`parse_timestamp()\` + \`format_timestamp!()\`, even for ISO-8601 input. Never assign a raw timestamp string or a parsed-timestamp object. Fallback to \`now()\`.
- **\`.metadata\`** — an object (initialize \`{}\`).
- **\`.udm.event_type\`** — derive from the event (EventID, eventName, method, …). Do NOT pre-seed \`"unknown"\`.
- A parser must extract real fields. A stub (\`.udm = {}\` and nothing else) is rejected. Write a GENERIC parser that handles ALL event types for the source, not just the sample.

## UDM field discipline

Process fields (nano convention):

| Field | Holds | Example |
|-------|-------|---------|
| \`command_line\` | full command (path + exe + args) | \`C:\\\\Windows\\\\System32\\\\cmd.exe /c x.bat\` |
| \`process_name\` | just the exe filename | \`cmd.exe\` |
| \`parent_command_line\` | full parent command | \`C:\\\\Windows\\\\explorer.exe\` |
| \`parent_process_name\` | just the parent exe filename | \`explorer.exe\` |

**Never** map high-cardinality values (session/request/trace IDs, UUIDs, full ARNs with session suffixes, URLs with query strings) into entity fields (\`user\`, \`src_ip\`, \`dest_ip\`, \`src_host\`, \`dest_host\`) — they're used in GROUP BY across the product. Extract the stable identifier (role name, username, email) and put the raw value in \`.ext\`. Rule of thumb: >~1,000 unique values/day → it belongs in \`.ext\`.

## The rules the validator enforces (get these right)

1. **Every regex literal closes on the same physical line.** \`r'...'\` never spans newlines. Too long? Split into multiple \`parse_regex\` calls.
2. **\`parse_regex\` requires a NAMED capture.** Use \`(?P<name>...)\` and access by name: \`m.name\`. Index access \`m."0"\` returns null and a downstream \`string!()\` PANICS at runtime — the validator hard-rejects this (NAN-644).
   - ✅ \`m, _ = parse_regex(path, r'(?P<name>[^\\\\/]+)$') ?? {}\` then \`.udm.file_name = string(m.name) ?? ""\`
3. **Balance regex parens.** \`(?P<name>...)\` is one open + one close. Count them.
4. **\`??\` ONLY after a call that can fail.** Fallible: \`parse_json\`, \`parse_xml\`, \`parse_timestamp\`, \`to_int\`, \`parse_regex\`, \`from_unix_timestamp\`. Infallible (adding \`??\` is an **E651** compile error): \`to_string\`, \`string!\`, \`length\`, \`downcase\`, \`upcase\`, \`split\` (on a known string), \`floor\`/\`ceil\`/\`round\`, and reading a field you just set.
5. **\`if\`/\`else\` is an EXPRESSION, not a statement.** \`else\` MUST sit on the same line as the prior closing \`}\` (a new-line \`else\` is an E203 reject, NAN-646). Assign the whole expression: \`.udm.event_type = if id == 1 { "process_create" } else if id == 3 { "network_connection" } else { "event" }\`.
6. **Define before use.** \`raw_log = string!(.message)\` must precede every read of \`raw_log\`. VRL also has **block scoping** — a var assigned inside an \`if {}\` is local to it; use the var in the same block, or assign to a \`.metadata.*\` field (globally visible).

Other footguns:

- \`string!(x)\` PANICS on null. For nullable JSON, use \`string(x) ?? ""\`.
- Inside \`if v != null { }\`, use \`string!(v)\` (safe). Do NOT \`to_string()\` a parsed XML/JSON value — that's an **E103** (\`string!\` instead).
- **Polymorphic IP fields** (CloudTrail \`sourceIPAddress\`, Windows \`IpAddress\`) can hold a DNS name or \`-\`. Guard: \`if is_ipv4(v) || is_ipv6(v) { .udm.src_ip = v }\`.
- **Unix epoch** timestamps: \`secs = to_int(floor(f))\` (NO \`??\` — floor returns int), then \`from_unix_timestamp(secs, "seconds") ?? now()\`.
- **Backslashes**: never \`contains(x, "\\\\")\` or \`split(x, "\\\\")\` (causes "unclosed string"); use a regex \`r'...'\` instead.
- **Apache vs nginx** look identical: feed name contains "apache" → \`parse_apache_log()\`; "nginx" → \`parse_nginx_log()\`. These return typed fields (status/size are already ints — don't \`to_int\` them).
- **\`for_each\` requires an array.** XML \`EventData.Data\` may be a single object OR an array — guard with \`is_array()\` / wrap with \`array!()\`.

## Forbidden functions (blocked at validation AND stripped from the runtime registry)

\`get_env_var\`, \`get_hostname\`, \`http_request\`, \`dns_lookup\`, \`reverse_dns\`, \`exec\`, \`system\`, \`shell\` — host-info disclosure / network egress / command execution. Also blocked: triple single-quotes \`'''\`, null bytes (\`\\x00\`, \`\\0\`). Limits: VRL ≤ 1 MB, nesting depth ≤ 20.

## Skeleton — JSON source

\`\`\`vrl
.udm = {}
.ext = {}
.metadata = {}
.udm.timestamp = now()  # fallback; ClickHouse requires a timestamp

raw_log = string!(.message)
parsed, err = parse_json(raw_log)

if err == null {
    if exists(parsed.eventTime) {
        ts, ts_err = parse_timestamp(string!(parsed.eventTime), "%+")
        if ts_err == null {
            .udm.timestamp = format_timestamp!(ts, format: "%Y-%m-%d %H:%M:%S")
        }
    }
    if exists(parsed.eventName) { .udm.event_type = string!(parsed.eventName) }
    if exists(parsed.user) { .udm.user = string!(parsed.user) }

    ip = string(parsed.src_ip) ?? ""
    if is_ipv4(ip) || is_ipv6(ip) { .udm.src_ip = ip }
} else {
    .metadata.parse_error = to_string(err)
}

.message = raw_log
\`\`\`

## Skeleton — regex / line-oriented source

\`\`\`vrl
.udm = {}
.metadata = {}

raw_log = string!(.message)
m, err = parse_regex(raw_log, r'^(?P<ts>\\S+) (?P<host>\\S+) (?P<msg>.*)$')
if err == null {
    ts, ts_err = parse_timestamp(string!(m.ts), "%Y-%m-%dT%H:%M:%S%.f%z")
    .udm.timestamp = if ts_err == null { format_timestamp!(ts, format: "%Y-%m-%d %H:%M:%S") } else { now() }
    .udm.src_host = string!(m.host)
    .udm.event_type = "log"
} else {
    .udm.timestamp = now()
    .metadata.parse_error = to_string(err)
}

.message = raw_log
\`\`\`

## After it parses

\`create_log_source\` (draft) → \`deploy_log_source\` → wait ~1 min → \`get_log_source_health\`. If \`health_status\` is \`no_data\` after a few minutes, events aren't reaching the parser: check that a **routing rule** maps the incoming events to this parser's \`source_type\` (\`list_source_configs\`, \`check_rule_reachability\`, \`create_routing_rule\`).
`;

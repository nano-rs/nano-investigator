/**
 * nPL Query Language Reference Resource
 */

export const NPL_REFERENCE_URI = 'nanosiem://reference/npl';

export const NPL_REFERENCE_RESOURCE = {
  uri: NPL_REFERENCE_URI,
  name: 'nPL Query Language Reference',
  description:
    'Complete reference for nPL (nano Pipe Language) — the piped query syntax used by nano',
  mimeType: 'text/markdown',
};

export const NPL_REFERENCE_CONTENT = `# nPL Query Language Reference

## Syntax
\`\`\`
search_term | command1 | command2 | ...
\`\`\`

Queries flow left to right through a pipeline. Start with a search term, then pipe through commands.

## Search Terms

### Free text
\`\`\`
error
"connection refused"
svchost.exe
\`\`\`

### Field = Value
\`\`\`
src_endpoint.ip="10.0.0.1"
status=500
actor.user.name=admin
metadata.log_source=windows_security
metadata.event_code=4625
\`\`\`

### Regex
\`\`\`
actor.user.name=/admin.*/
query.hostname=/.*\\.malware\\.com$/
process.file.name=/^(cmd|powershell)\\.exe$/i
\`\`\`

### Boolean operators
\`\`\`
src_endpoint.ip="10.0.0.1" AND dst_endpoint.port=443
actor.user.name=admin OR actor.user.name=root
NOT metadata.log_source=healthcheck
\`\`\`

### Wildcards
\`\`\`
process.file.name=svc*
file.path=*\\\\temp\\\\*
\`\`\`

## Commands

### where — Filter events
\`\`\`
| where status_code >= 400
| where src_endpoint.ip != "10.0.0.1"
| where actor.user.name IN ("admin", "root", "system")
| where actor.user.name NOT IN ("svc_account", "healthcheck")
| where process.cmd_line CONTAINS "encoded"
| where file.path NOT CONTAINS "/var/log"
| where traffic.bytes_out > 1000000
\`\`\`

### stats — Aggregate
\`\`\`
| stats count by src_endpoint.ip
| stats count, dc(actor.user.name) as unique_users by src_endpoint.ip
| stats sum(traffic.bytes_out) as total_bytes by src_endpoint.ip, dst_endpoint.ip
| stats min(time) as first_seen, max(time) as last_seen by actor.user.name
| stats values(dst_endpoint.hostname) as targets by src_endpoint.ip
| stats avg(duration) as avg_duration by endpoint
| stats count by src_endpoint.ip | where count > 100
\`\`\`

**Aggregation functions:** count, sum, avg, min, max, dc (distinct count), values (unique values list), list (all values)

### timechart — Time-series aggregation
\`\`\`
| timechart span=1h count
| timechart span=5m count by metadata.log_source
| timechart span=1d sum(traffic.bytes_out) as daily_bytes by src_endpoint.ip
\`\`\`

**Span values:** 1m, 5m, 15m, 30m, 1h, 4h, 12h, 1d

### table — Select specific columns
\`\`\`
| table time, src_endpoint.ip, dst_endpoint.ip, action, actor.user.name
| table time, device.hostname, process.file.name, process.cmd_line, process.parent_process.file.path
\`\`\`

### sort — Order results
\`\`\`
| sort time
| sort -count
| sort severity, -time
\`\`\`
Prefix with \`-\` for descending order.

### head / tail — Limit results
\`\`\`
| head 10
| tail 5
\`\`\`

### eval — Computed fields
\`\`\`
| eval total_bytes = bytes_in + traffic.bytes_out
| eval ratio = traffic.bytes_out / bytes_in
| eval is_internal = is_private_ip(src_endpoint.ip)
| eval domain = extract_domain(url)
| eval cmd_length = len(process.cmd_line)
\`\`\`

### rex — Extract fields with regular expressions
\`\`\`
| rex field=message '(?<user>[A-Za-z0-9._-]+)'
| rex field=message '"FILE_PATH":"(?<path>[^\"]+)"'
\`\`\`

When a pattern contains JSON-style double quotes, wrap the entire pattern in
single quotes. In nPL a backslash does not escape a double-quoted delimiter, so
the familiar SPL spelling \`"\\"KEY\\":..."\` is less portable than
\`'"KEY":...'\` and can fail on older nano backends.

### prevalence — Filter by prevalence
\`\`\`
| prevalence file.hashes.value < 5
| prevalence dst_endpoint.ip < 10
\`\`\`
Filters to artifacts seen on fewer than N hosts.

### lookup — Join with lookup tables
\`\`\`
| lookup threat_intel dst_endpoint.ip
| lookup asset_inventory device.hostname
\`\`\`

### risk — Add risk scoring
\`\`\`
| risk score=50 entity=src_endpoint.ip factor="Suspicious behavior detected"
| where failed_count > 100
| risk score=80 factor="High volume brute force"
\`\`\`
Accumulates risk on the specified entity field. Multiple risk commands stack.

## Eval Functions

### Network
- \`cidr_match(ip, "10.0.0.0/8")\` — Check if IP is in CIDR range
- \`is_private_ip(ip)\` — Check if IP is RFC1918 private
- \`extract_domain(url)\` — Extract base domain from URL/FQDN

### String
- \`len(field)\` — String length
- \`lower(field)\` / \`upper(field)\` — Case conversion
- \`trim(field)\` — Remove whitespace
- \`replace(field, "old", "new")\` — String replacement
- \`substr(field, start, length)\` — Substring extraction
- \`split(field, delimiter, index)\` — Split and extract

### Security
- \`base64_decode(field)\` — Decode base64 string
- \`defang(field)\` — Defang URLs/IPs for safe display (e.g., hxxp://)
- \`md5(field)\` / \`sha256(field)\` — Hash computation

### Math
- Standard operators: \`+\`, \`-\`, \`*\`, \`/\`, \`%\`
- \`round(field, decimals)\`
- \`ceil(field)\` / \`floor(field)\`
- \`abs(field)\`

### Conditional
- \`if(condition, true_value, false_value)\`
- \`coalesce(field1, field2, ...)\` — First non-null value
- \`case(cond1, val1, cond2, val2, ..., default)\`

## Query Optimization Notes

### Always filter by timestamp
nPL does this automatically from the time range you provide. For best performance, use the narrowest time range that answers your question.

### Use source_type when known
Source type is included with the time predicate, enabling partition pruning:
\`\`\`
metadata.log_source=windows_security | where metadata.event_code=4625
\`\`\`
is much faster than:
\`\`\`
metadata.event_code=4625
\`\`\`

### Aggregations preserve input and bound output
The limit parameter caps returned events or aggregate groups; it must not truncate the matching events used to compute stats/timechart values. For a meaningful top-N aggregate, sort before \`head\`/\`limit\`. If a high-cardinality aggregation cannot honor the requested output limit, the MCP tool returns an explicit error instead of risking a connection close or silently slicing groups.

### Field values are top-value discovery, not a population estimate
\`get_field_values\` returns only the limited top values. Its counts and percentages describe that returned list; their sum is neither a sample total nor the full matching event count. Use the same scoped query with an explicit \`| stats count\` when you need the population total.

### Free text search uses bloom filters
When you search free text in nPL, it compiles to \`hasToken(message_search, lower('term'))\` which leverages bloom filter indexes. This is fast.

### Field pruning
The MCP tools use \`table_view: true\` which returns minimal columns. This reduces payload size. Full event data is fetched when needed via row expansion.

## Query Refinement Protocol

After every search, evaluate the results:
- **0 results** → Check field values are correct (use get_field_values). Check source_type exists. Widen time range.
- **1-100 results** → Good. Analyze directly.
- **100-1000 results** → Summarize with stats, drill down on interesting groups.
- **1000-10000 results** → Too many to analyze individually. Add filters, narrow time, use stats aggregation first.
- **10000+ results** → Way too broad. Use stats/timechart first to understand the shape, then drill down.

When a query returns unexpected results:
1. Use explain_query to see the SQL — is it doing what you intended?
2. Check get_field_values for the fields you're filtering on — are the values what you expected?
3. Try a more specific source_type — maybe the field exists but isn't populated in all sources.
`;

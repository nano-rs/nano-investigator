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
src_ip="10.0.0.1"
status=500
user=admin
source_type=windows_security
event_id=4625
\`\`\`

### Regex
\`\`\`
user=/admin.*/
dns_query=/.*\\.malware\\.com$/
process_name=/^(cmd|powershell)\\.exe$/i
\`\`\`

### Boolean operators
\`\`\`
src_ip="10.0.0.1" AND dest_port=443
user=admin OR user=root
NOT source_type=healthcheck
\`\`\`

### Wildcards
\`\`\`
process_name=svc*
file_path=*\\\\temp\\\\*
\`\`\`

## Commands

### where — Filter events
\`\`\`
| where status_code >= 400
| where src_ip != "10.0.0.1"
| where user IN ("admin", "root", "system")
| where user NOT IN ("svc_account", "healthcheck")
| where command_line CONTAINS "encoded"
| where file_path NOT CONTAINS "/var/log"
| where bytes_out > 1000000
\`\`\`

### stats — Aggregate
\`\`\`
| stats count by src_ip
| stats count, dc(user) as unique_users by src_ip
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| stats min(timestamp) as first_seen, max(timestamp) as last_seen by user
| stats values(dest_host) as targets by src_ip
| stats avg(duration) as avg_duration by endpoint
| stats count by src_ip | where count > 100
\`\`\`

**Aggregation functions:** count, sum, avg, min, max, dc (distinct count), values (unique values list), list (all values)

### timechart — Time-series aggregation
\`\`\`
| timechart span=1h count
| timechart span=5m count by source_type
| timechart span=1d sum(bytes_out) as daily_bytes by src_ip
\`\`\`

**Span values:** 1m, 5m, 15m, 30m, 1h, 4h, 12h, 1d

### table — Select specific columns
\`\`\`
| table timestamp, src_ip, dest_ip, action, user
| table timestamp, src_host, process_name, command_line, parent_process
\`\`\`

### sort — Order results
\`\`\`
| sort timestamp
| sort -count
| sort severity, -timestamp
\`\`\`
Prefix with \`-\` for descending order.

### head / tail — Limit results
\`\`\`
| head 10
| tail 5
\`\`\`

### eval — Computed fields
\`\`\`
| eval total_bytes = bytes_in + bytes_out
| eval ratio = bytes_out / bytes_in
| eval is_internal = is_private_ip(src_ip)
| eval domain = extract_domain(url)
| eval cmd_length = len(command_line)
\`\`\`

### prevalence — Filter by prevalence
\`\`\`
| prevalence process_hash < 5
| prevalence dest_ip < 10
\`\`\`
Filters to artifacts seen on fewer than N hosts.

### lookup — Join with lookup tables
\`\`\`
| lookup threat_intel dest_ip
| lookup asset_inventory src_host
\`\`\`

### risk — Add risk scoring
\`\`\`
| risk score=50 entity=src_ip factor="Suspicious behavior detected"
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
Source type is in the PREWHERE clause, enabling partition pruning:
\`\`\`
source_type=windows_security | where event_id=4625
\`\`\`
is much faster than:
\`\`\`
event_id=4625
\`\`\`

### Stats queries return all groups
Event queries respect the limit parameter. Stats/timechart queries return all result groups (usually small). If a stats query returns too many groups, add more filters or increase the \`where\` threshold.

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

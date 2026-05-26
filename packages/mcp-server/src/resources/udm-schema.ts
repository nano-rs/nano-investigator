/**
 * UDM Schema Resource — curated investigation guide organized by scenario
 */

export const UDM_SCHEMA_URI = 'nanosiem://schema/udm';

export const UDM_SCHEMA_RESOURCE = {
  uri: UDM_SCHEMA_URI,
  name: 'UDM Field Reference',
  description:
    'nano Unified Data Model — fields organized by investigation scenario with search tips and common queries',
  mimeType: 'text/markdown',
};

export const UDM_SCHEMA_CONTENT = `# nano UDM Field Reference

## Core Fields (always available)
- **timestamp** (DateTime) — Event timestamp. Always filter on this for partition pruning.
- **source_type** (String) — Log source identifier (e.g., "windows_security", "sysmon", "firewall_paloalto"). Use in queries for PREWHERE optimization.
- **message** (String) — Raw log message. Search via \`lower(message) iLike '%term%'\` (text indexes with splitByNonAlpha tokenizer keep this fast).
- **event_type** (String) — Normalized event type.
- **action** (String) — Action performed (e.g., "login_failed", "file_created", "connection_established").
- **severity** (String) — Event severity level.

## When Investigating Authentication
**Fields:** user, src_ip, dest_host, auth_result, auth_type, auth_method, session_id, logon_type
**Search tips:**
- auth_result values are typically "success", "failure", "locked_out" (but varies by source — use get_field_values to confirm)
- logon_type for Windows: 2=Interactive, 3=Network, 10=RemoteInteractive (RDP)
- Always check both success AND failure for a given src_ip/user

**Common queries:**
\`\`\`
source_type=auth | where auth_result="failure" | stats count, values(user), values(dest_host) by src_ip
source_type=windows_security | where event_id=4625 | stats count by src_ip, user | where count > 10
user="admin" | stats count by auth_result, src_ip, dest_host | sort -count
\`\`\`

## When Investigating Process Execution
**Fields:** process_name, command_line, parent_process, parent_process_name, process_hash, process_id, file_path, process_path
**Search tips:**
- Use \`process_name\` for just the executable name, \`command_line\` for full command
- \`parent_process\` is critical — always include it for context
- \`process_hash\` can be checked against prevalence to find rare binaries

**Common queries:**
\`\`\`
process_name="powershell.exe" | table timestamp, src_host, user, command_line, parent_process
source_type=sysmon | where event_id=1 | where command_line CONTAINS "encoded" | table timestamp, src_host, user, command_line, parent_process
process_name="cmd.exe" | where parent_process CONTAINS "outlook" | table timestamp, src_host, user, command_line
\`\`\`

## When Investigating DNS
**Fields:** dns_query, dns_response, dns_response_code, dns_record_type, dest_ip (resolver), src_ip
**Search tips:**
- dns_query contains the full FQDN
- Use \`extract_domain()\` eval function to get base domain
- High volume of unique subdomains to one domain may indicate DNS tunneling/exfil
- dns_response_code: "NXDOMAIN" indicates non-existent domain (could be DGA)

**Common queries:**
\`\`\`
dns_query=/.*\\.xyz\\.ru$/ | stats count, dc(dns_query) as unique_subdomains by src_ip
source_type=dns | stats dc(dns_query) as unique_queries by src_ip | where unique_queries > 500
dns_response_code="NXDOMAIN" | stats count by src_ip, dns_query | where count > 100
\`\`\`

## When Investigating Network Connections
**Fields:** src_ip, dest_ip, src_port, dest_port, protocol, bytes_in, bytes_out, direction, network_action
**Search tips:**
- bytes_out >> bytes_in may indicate data exfiltration
- Unusual dest_ports (not 80, 443, 53) deserve attention
- Use \`is_private_ip()\` to distinguish internal vs external
- Use \`cidr_match()\` to filter by subnet

**Common queries:**
\`\`\`
dest_port NOT IN (80, 443, 53) | stats sum(bytes_out) as total_out by src_ip, dest_ip, dest_port | sort -total_out
src_ip="10.5.2.40" | stats count, sum(bytes_out) as total_bytes by dest_ip, dest_port | sort -total_bytes
protocol="tcp" | where dest_port=4444 OR dest_port=8080 | table timestamp, src_ip, dest_ip, dest_port, bytes_out
\`\`\`

## When Investigating File Activity
**Fields:** file_path, file_name, file_hash, file_action, file_size, file_type
**Search tips:**
- file_action values: "created", "modified", "deleted", "renamed", "accessed"
- Files in temp directories (/tmp, %TEMP%) warrant extra scrutiny
- Check file_hash prevalence to identify rare/unique files

**Common queries:**
\`\`\`
file_action="created" | where file_path CONTAINS "/tmp/" | table timestamp, src_host, user, file_path, process_name
file_hash="abc123..." | stats count by src_host | sort -count
source_type=sysmon | where event_id=11 | where file_path CONTAINS ".exe" | table timestamp, src_host, file_path, process_name
\`\`\`

## When Investigating Web/HTTP Activity
**Fields:** url, http_method, http_status, http_user_agent, http_referrer, dest_ip, dest_port
**Search tips:**
- Unusual user agents may indicate malware or tools
- POST requests with large bodies may indicate data exfil
- HTTP to non-standard ports is suspicious

**Common queries:**
\`\`\`
http_method="POST" | stats count, sum(bytes_out) as total_sent by src_ip, url | sort -total_sent
url CONTAINS ".php?" | where http_method="POST" | table timestamp, src_ip, url, http_user_agent, bytes_out
http_user_agent=/.*python.*|.*curl.*|.*wget.*/i | stats count by src_ip, http_user_agent
\`\`\`

## When Investigating Email
**Fields:** email_from, email_to, email_subject, email_attachment, email_direction
**Search tips:**
- Look for attachments with executable extensions or double extensions
- Outbound emails to unusual domains may indicate data exfil

**Common queries:**
\`\`\`
email_attachment=/.*\\.(exe|scr|bat|ps1|vbs)$/i | table timestamp, email_from, email_to, email_subject, email_attachment
email_direction="outbound" | stats count, dc(email_to) as unique_recipients by email_from | where unique_recipients > 50
\`\`\`

## When Investigating Cloud Activity
**Fields:** cloud_provider, cloud_service, cloud_region, cloud_account_id, resource_type, resource_id, change_type
**Search tips:**
- IAM changes are high-interest security events
- Cross-region activity may indicate compromise
- Look for resource creation + deletion patterns (attack cleanup)

**Common queries:**
\`\`\`
cloud_service="iam" | table timestamp, user, action, resource_type, resource_id, cloud_region
change_type="delete" | stats count by user, cloud_service, resource_type | where count > 5
cloud_region NOT IN ("us-east-1", "eu-west-1") | stats count by user, cloud_region, cloud_service
\`\`\`

## Enrichment Fields (auto-populated)
- **enriched_src_country**, **enriched_src_asn** — GeoIP enrichment for source IP
- **enriched_dest_country**, **enriched_dest_asn** — GeoIP enrichment for dest IP
- **ioc_match**, **ioc_type**, **ioc_threat_type** — IOC feed matches
- **prevalence_file_hash**, **prevalence_dest_ip** — Prevalence scores

## Free-text Search Optimization
For case-insensitive text search, use \`lower(field) iLike '%needle%'\`. Text indexes (splitByNonAlpha tokenizer, granularity 1) on \`lower(message)\`, \`lower(command_line)\`, \`lower(user)\`, \`lower(process_name)\`, \`lower(file_path)\`, \`lower(parent_command_line)\`, \`lower(src_user)\`, \`lower(dest_user)\` keep this fast.

**Do not** use \`hasToken()\` for variable-length needles — it silently misses substrings (NAN-1026). Older docs referencing \`_search\` materialized columns are stale; those columns no longer exist.

In nPL, free-text search is handled automatically — just search normally.

## The ext Column
Fields not in the UDM schema go into \`ext\` — a true ClickHouse JSON column (not a String). Access with dot notation in both SQL and nPL:
\`\`\`sql
SELECT ext.custom_field, ext['key.with.dots'] FROM logs WHERE ext.event_id = 4624
\`\`\`
Do NOT use \`JSONExtract\` on \`ext\` — that's for the legacy \`metadata\` String column on older rows.

See \`nano://sql-guide\` for canonical query recipes (prevalence, top-N, time bucketing, ASOF identity joins).
`;

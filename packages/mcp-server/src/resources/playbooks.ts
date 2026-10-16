/**
 * Investigation Playbook Resources
 */

export const PLAYBOOK_URI_PREFIX = 'nanosiem://reference/playbooks';

export interface PlaybookDefinition {
  type: string;
  name: string;
  description: string;
  content: string;
}

export const PLAYBOOKS: PlaybookDefinition[] = [
  {
    type: 'brute_force',
    name: 'Brute Force Investigation',
    description: 'Step-by-step methodology for investigating authentication attacks',
    content: `# Brute Force Investigation Playbook

## Step 1: Scope the Attack
- Search for the alerting source IP's authentication activity
- Query: \`metadata.log_source=auth | where src_endpoint.ip="{ip}" | stats count by actor.user.name, dst_endpoint.hostname, status\`
- How many users targeted? How many hosts? Success vs failure ratio?

## Step 2: Check for Successful Auth
- CRITICAL: Did any attempts succeed?
- Query: \`src_endpoint.ip="{ip}" status=success\`
- If yes → this is now an incident, not just an attempt

## Step 3: Entity Context
- Who owns this IP? (get_entity_context)
- Is it internal or external? (lookup_ip → GeoIP)
- Is it a known scanner? (filter search on ioc_matched / ioc_threat_type)
- Have we seen this IP before? (get_prevalence)

## Step 4: Blast Radius (if successful auth)
- What did the compromised account do after login?
- Query: \`actor.user.name="{user}" | sort time | table time, metadata.log_source, action, dst_endpoint.hostname, process.file.name\`
- Look for: lateral movement, privilege escalation, data access

## Step 5: Historical Context
- Have we seen similar attacks? (get_related_cases)
- Is this part of a campaign? Search for same src_endpoint.ip in last 30 days
- Query: \`src_endpoint.ip="{ip}" | timechart span=1d count by status\`

## Step 6: Recommend Action
- **FP**: Known scanner, expected behavior → close alert
- **Attempted brute force, no success** → block IP, close alert as benign
- **Successful brute force** → open case, reset credentials, investigate lateral movement
`,
  },
  {
    type: 'lateral_movement',
    name: 'Lateral Movement Investigation',
    description: 'How to trace host-to-host movement within the network',
    content: `# Lateral Movement Investigation Playbook

## Step 1: Identify the Pivot Point
- Which host initiated outbound connections to other internal hosts?
- Query: \`src_endpoint.ip="{ip}" | where is_private_ip(dst_endpoint.ip) | stats count, dc(dst_endpoint.ip) as targets by dst_endpoint.port\`
- Key ports: 445 (SMB), 135 (RPC), 3389 (RDP), 5985/5986 (WinRM), 22 (SSH)

## Step 2: Map the Network Path
- Build a timeline of connections from the source host
- Query: \`src_endpoint.ip="{ip}" | where dst_endpoint.port IN (445, 135, 3389, 5985, 22) | sort time | table time, dst_endpoint.ip, dst_endpoint.port, actor.user.name\`
- Which hosts were accessed? In what order?

## Step 3: Check Authentication on Target Hosts
- For each target host, check logon events
- Query: \`metadata.log_source=windows_security | where metadata.event_code=4624 AND logon_type_id=3 AND src_endpoint.ip="{ip}" | table time, dst_endpoint.hostname, actor.user.name, logon_type_id\`
- Were new accounts created? Were privileges escalated?

## Step 4: Process Execution on Targets
- What was executed on the target hosts?
- Query: \`device.hostname="{target_host}" | where process.file.name IN ("psexec.exe", "wmic.exe", "powershell.exe", "cmd.exe") | table time, actor.user.name, process.file.name, process.cmd_line, process.parent_process.file.path\`
- Look for: remote execution tools, encoded commands, suspicious scripts

## Step 5: Assess Spread
- How far did the attacker get?
- Use get_entity_context for each compromised host
- Check for data access, staging, or exfiltration from any of the targets

## Step 6: Recommend Action
- Identify all compromised hosts and accounts
- Recommend isolation of affected systems
- Reset credentials for compromised accounts
- Check for persistence mechanisms on each compromised host
`,
  },
  {
    type: 'data_exfil',
    name: 'Data Exfiltration Investigation',
    description: 'How to investigate potential data exfiltration',
    content: `# Data Exfiltration Investigation Playbook

## Step 1: Identify the Data Flow
- Which host is sending data, where, and how much?
- Query: \`src_endpoint.ip="{ip}" | stats sum(traffic.bytes_out) as total_sent, count by dst_endpoint.ip, dst_endpoint.port | sort -total_sent\`
- Is the volume unusual for this host?

## Step 2: Check the Channel
- What protocol/method is being used?
- DNS tunneling: \`src_endpoint.ip="{ip}" | where dst_endpoint.port=53 | stats dc(query.hostname) as unique_queries, count by dst_endpoint.ip\`
- HTTP/S uploads: \`src_endpoint.ip="{ip}" | where http_method="POST" | stats sum(traffic.bytes_out) by url | sort -sum\`
- Cloud storage: Check for uploads to known cloud storage domains

## Step 3: Timeline Analysis
- When did the exfiltration start?
- Query: \`src_endpoint.ip="{ip}" dst_endpoint.ip="{dest}" | timechart span=1h sum(traffic.bytes_out) as bytes_sent\`
- Is it continuous or bursty? Regular intervals suggest automation/C2

## Step 4: What Data Was Accessed
- Before exfiltration, what files/data was accessed on the host?
- Query: \`device.hostname="{host}" | where activity_name IN ("accessed", "read", "copied") | sort time | table time, file.path, file_size, process.file.name\`
- Look for: bulk file access, database exports, archive creation (zip, 7z, tar)

## Step 5: Data Staging
- Was data compressed/archived before exfiltration?
- Query: \`device.hostname="{host}" | where process.file.name IN ("7z.exe", "rar.exe", "zip.exe", "tar") | table time, process.cmd_line, file.path\`

## Step 6: Recommend Action
- Calculate total data volume exfiltrated
- Identify the destination and check IOC feeds
- Determine what data was likely taken (file types, database access)
- Recommend: block destination, isolate host, assess data sensitivity
`,
  },
  {
    type: 'malware',
    name: 'Malware Investigation',
    description: 'How to investigate suspected malware on a host',
    content: `# Malware Investigation Playbook

## Step 1: Identify the Suspicious Process
- What process triggered the alert?
- Use get_detection to read the rule and ai_triage_hints
- Query: \`device.hostname="{host}" process.file.name="{process}" | table time, actor.user.name, process.cmd_line, process.parent_process.file.path, file.hashes.value\`

## Step 2: Check Prevalence
- Is this binary/process common in the environment?
- Use get_prevalence with the process hash
- Prevalence 1/4000 = very suspicious. Prevalence 3500/4000 = probably legitimate.

## Step 3: Process Ancestry
- What spawned this process? Build the process tree
- Query: \`device.hostname="{host}" | where process.pid="{pid}" OR process.parent_process.pid="{pid}" | sort time | table time, process.file.name, process.cmd_line, process.parent_process.file.path, process.pid, process.parent_process.pid\`
- Suspicious chains: browser → cmd → powershell, explorer → script → executable

## Step 4: Network Activity
- What did the suspicious process connect to?
- Query: \`device.hostname="{host}" process.file.name="{process}" | where dst_endpoint.ip != "" | stats count by dst_endpoint.ip, dst_endpoint.port\`
- Check destinations with lookup_ip; flag threat-intel hits via the ioc_matched / ioc_threat_type columns

## Step 5: File Activity
- What files did the process create/modify?
- Query: \`device.hostname="{host}" process.file.name="{process}" | where file.path != "" | table time, activity_name, file.path, file.hashes.value\`
- Look for: persistence (startup, scheduled tasks, services), payloads dropped

## Step 6: Lateral Check
- Is the same binary/process on other hosts?
- Query: \`file.hashes.value="{hash}" | stats count, dc(device.hostname) as host_count by process.file.name\`
- If on multiple hosts, this may be a wider compromise

## Step 7: Recommend Action
- Isolate affected host(s)
- Block IOCs (IPs, domains, hashes) at perimeter
- Collect forensic artifacts
- Check for persistence mechanisms and remove
`,
  },
  {
    type: 'phishing',
    name: 'Phishing Investigation',
    description: 'How to investigate phishing campaigns and compromised accounts',
    content: `# Phishing Investigation Playbook

## Step 1: Identify Recipients
- Who received the phishing email?
- Query: \`email_from="{sender}" | stats count, values(email_to) as recipients, values(email_subject) as subjects\`
- How many users received it? Is this targeted or spray-and-pray?

## Step 2: Check for Clicks/Interaction
- Did anyone click the link or open the attachment?
- Query: \`url CONTAINS "{phishing_domain}" | stats count by src_endpoint.ip, actor.user.name\`
- Query: \`file.name="{attachment}" | stats count by device.hostname, actor.user.name, activity_name\`

## Step 3: Post-Click Activity
- For users who clicked, what happened next?
- Query: \`actor.user.name="{compromised_user}" | sort time | table time, metadata.log_source, action, src_endpoint.ip, dst_endpoint.ip, process.file.name\`
- Look for: credential theft (login from new IP), malware download, macro execution

## Step 4: Credential Compromise
- Were credentials entered on the phishing site?
- Query: \`actor.user.name="{user}" | where status="success" | stats values(src_endpoint.ip) by dst_endpoint.hostname\`
- New source IPs appearing after the phishing email = likely compromise

## Step 5: Campaign Scope
- Is this part of a larger campaign?
- Check the sending domain for threat-intel hits (ioc_matched / ioc_threat_type in search)
- Query: \`email_from=/.*@{sending_domain}$/ | stats count, dc(email_to) as targets by email_subject\`

## Step 6: Recommend Action
- Reset credentials for affected users
- Block phishing domain/URL at email gateway and proxy
- Revoke any active sessions for compromised accounts
- Notify affected users
- Report phishing infrastructure
`,
  },
  {
    type: 'insider_threat',
    name: 'Insider Threat Investigation',
    description: 'How to investigate suspicious insider behavior',
    content: `# Insider Threat Investigation Playbook

## Step 1: Establish Baseline Behavior
- What is normal activity for this user?
- Query: \`actor.user.name="{user}" | timechart span=1d count by metadata.log_source\` (30-day lookback)
- When do they normally work? What systems do they access?

## Step 2: Identify Anomalies
- What changed? Look for deviations from baseline
- Off-hours activity: Query with time filters outside business hours
- New systems accessed: \`actor.user.name="{user}" | stats min(time) as first_access by dst_endpoint.hostname | where first_access > "{recent_date}"\`
- Volume anomalies: Sudden increase in data access/transfer

## Step 3: Data Access Patterns
- What sensitive data is being accessed?
- Query: \`actor.user.name="{user}" | where file.path CONTAINS "confidential" OR file.path CONTAINS "restricted" | table time, file.path, activity_name, device.hostname\`
- Bulk downloads or copies to removable media

## Step 4: Communication Channels
- Is data being sent externally?
- Query: \`actor.user.name="{user}" | where dst_endpoint.port IN (25, 587, 443) | stats sum(traffic.bytes_out) as total_sent by dst_endpoint.ip | sort -total_sent\`
- Personal email, cloud storage, USB drives

## Step 5: Account Activity
- Multiple accounts? Privilege escalation?
- Query: \`src_endpoint.ip IN ({user_ips}) | stats dc(actor.user.name) as identities, values(actor.user.name) by src_endpoint.ip\`
- Shared account usage, service account access

## Step 6: Context and Intent
- Check organizational context (get_org_context) — is this person in a sensitive role?
- HR context: Notice period, performance issues, access reviews
- Note: This is sensitive — document all findings carefully

## Step 7: Recommend Action
- Preserve all evidence
- Document findings with timeline
- Coordinate with HR and Legal before any confrontation
- Consider enhanced monitoring vs immediate action based on risk
`,
  },
  {
    type: 'generic',
    name: 'Generic Investigation',
    description: 'General investigation methodology for any security event',
    content: `# Generic Investigation Methodology

## Phase 1: Scope
1. **Read the alert/event** — What triggered this? What is the detection logic?
2. **Identify key entities** — IPs, users, hosts, hashes, domains involved
3. **Determine time window** — When did this start? Is it ongoing?

## Phase 2: Enrich
4. **Entity context** — For each key entity, call get_entity_context
5. **Prevalence check** — Is this artifact common or rare? (get_prevalence)
6. **GeoIP/IOC** — Is this IP from an expected location? Is it a known IOC?
7. **Risk score** — What's the accumulated risk for involved entities?

## Phase 3: Correlate
8. **Related alerts** — Are there other alerts involving the same entities?
9. **Related cases** — Have we investigated this before? (get_related_cases)
10. **Timeline** — Build a chronological timeline of events
11. **Search for more** — Run targeted queries to fill gaps in understanding

## Phase 4: Present
12. **Summarize findings** — What happened, who/what was involved, what's the impact?
13. **Classify severity** — Based on evidence, how bad is this?
14. **Show evidence** — Include specific events, queries, and data points

## Phase 5: Recommend
15. **Immediate actions** — What should happen right now? (block, isolate, reset)
16. **Investigation actions** — What needs deeper analysis?
17. **Long-term actions** — Detection improvements, policy changes, hardening

## Key Principles
- **Never go more than 2 levels deep without checking with the analyst**
- **Always check prevalence before flagging something as suspicious**
- **Always check related cases before declaring something novel**
- **Use ai_triage_hints from detection rules when triaging alerts**
- **Present findings at each checkpoint, don't silently investigate**
`,
  },
];

export function getPlaybookResources() {
  return PLAYBOOKS.map((p) => ({
    uri: `${PLAYBOOK_URI_PREFIX}/${p.type}`,
    name: p.name,
    description: p.description,
    mimeType: 'text/markdown' as const,
  }));
}

export function getPlaybookContent(type: string): string | null {
  const playbook = PLAYBOOKS.find((p) => p.type === type);
  return playbook?.content ?? null;
}

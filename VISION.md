# nano-investigator

Interactive SOC operations through Claude Code. Ask questions in natural language, get investigations that chain across your SIEM automatically.

## What This Is

An MCP server that turns Claude Code (or any MCP client) into an interactive SOC analyst workstation. Unlike nanodac which focuses on detection-as-code workflows (write rules, validate, deploy via PR), nano-investigator is the **operations** side: searching logs, triaging alerts, investigating cases, hunting threats, and understanding your environment.

```
You: "anything weird from the VPN subnet last night?"

Claude: *searches VPN activity → spots anomalous DNS from 10.5.2.40 →
        checks asset ownership → finds it's jsmith's laptop →
        pivots to jsmith's full timeline → discovers suspicious process →
        checks prevalence → searches for related alerts*

        "jsmith's laptop (10.5.2.40) made 200+ DNS queries to unique
         subdomains of xyz.ru between 2-3am. The process responsible
         was 'svchost.exe' running on macOS — that's wrong. Parent
         process was a Python script in /tmp. This host has no prior
         alerts. No other hosts contacted xyz.ru. Prevalence: 1/4000.

         Recommend opening a case. Want me to?"
```

## Architecture

```
nano-investigator/
├── packages/
│   ├── core/                    # Shared client, types, utilities
│   │   └── src/
│   │       ├── client.ts        # nano API client (extend from @nanodac/core)
│   │       ├── types.ts         # Response types for all API surfaces
│   │       ├── formatters.ts    # Result → markdown table/narrative formatters
│   │       └── npl.ts           # nPL query builder helpers
│   │
│   └── mcp-server/              # The MCP server
│       └── src/
│           ├── index.ts         # Server entry, stdio transport
│           ├── tools/
│           │   ├── search.ts        # Log search + nPL execution
│           │   ├── alerts.ts        # Alert triage operations
│           │   ├── cases.ts         # Case management + investigation
│           │   ├── assets.ts        # Entity context + asset lookup
│           │   ├── detections.ts    # Detection rule inspection
│           │   ├── prevalence.ts    # "Is this normal?" queries
│           │   ├── risk.ts          # Risk scoring + entity risk
│           │   ├── enrichment.ts    # IP/IOC/domain enrichment
│           │   ├── notebooks.ts     # Investigation notebooks
│           │   ├── mitre.ts         # ATT&CK context + coverage
│           │   └── system.ts        # Health, storage, meta
│           ├── resources/
│           │   ├── udm-schema.ts    # UDM field catalog as MCP resource
│           │   ├── npl-reference.ts # nPL query language reference
│           │   └── playbooks.ts     # Investigation playbook resources
│           └── prompts/
│               ├── investigate.ts   # Investigation workflow prompts
│               ├── hunt.ts          # Threat hunting prompts
│               └── triage.ts        # Alert triage prompts
├── CLAUDE.md                    # Context for Claude Code sessions
├── package.json
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

## Relationship to nanodac

**nanodac** = detection engineering (write, test, deploy rules via GitOps)
**nano-investigator** = SOC operations (search, triage, investigate, hunt)

They share:
- `@nanodac/core` NanosiemClient as the base API client (extend, don't fork)
- Same env vars (`NANOSIEM_API_URL`, `NANOSIEM_API_KEY`, `NANOSIEM_SEARCH_URL`)
- Can run as separate MCP servers or combined

They differ:
- nanodac writes to the SIEM (create/update rules, git workflows)
- nano-investigator primarily reads (searches, lookups, context gathering) with limited writes (case comments, alert status)
- nanodac tools are for detection engineers
- nano-investigator tools are for SOC analysts

Users can run both simultaneously:
```json
{
  "mcpServers": {
    "nanodac": { "command": "nanodac-mcp", "env": { ... } },
    "nano-investigator": { "command": "nano-investigator", "env": { ... } }
  }
}
```

Or — future option — a combined `nanosiem-mcp` that exposes both tool sets.

---

## MCP Tools — Complete Catalog

### Search (the workhorse)

The most-used tools. Claude builds nPL queries from natural language and interprets results.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `search` | Execute nPL query with time range. Returns events + metadata. The primary investigation tool. | `POST /api/search` (search service) |
| `search_sql` | Execute raw SQL (for advanced/edge cases Claude can't express in nPL) | `POST /api/search/sql` (search service) |
| `explain_query` | Show the SQL that a nPL query compiles to (useful for debugging/learning) | `POST /api/search/explain` (search service) |
| `get_field_values` | Get top values for a specific field within a query context (e.g., "what source_types exist?") | `POST /api/search/field-values` (search service) |
| `get_field_stats` | Get field statistics (cardinality, top values) for a query result set | `POST /api/search/field-stats` (search service) |

**`search` tool — the critical one:**

```typescript
{
  name: 'search',
  description: `Execute a search query against nano logs using nPL (piped query syntax).

Examples:
  - "error" — free text search
  - "src_ip=10.0.0.1 | stats count by dest_ip" — entity search with aggregation
  - "source_type=windows_security | where event_id=4625 | stats count by src_ip, user | where count > 5" — failed login detection

Time ranges accept relative ("-24h", "-7d", "-30m") or ISO 8601.
Default limit is 100 results. Use limit for event queries, stats queries return all groups.`,
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description: 'nPL query. Piped syntax: search_term | command1 | command2. Commands: where, stats, timechart, table, sort, head, tail, eval, prevalence, lookup, risk',
      },
      start_time: {
        type: 'string',
        description: 'Start time — relative ("-24h", "-7d") or ISO 8601',
      },
      end_time: {
        type: 'string',
        description: 'End time — relative or ISO 8601 (default: "now")',
      },
      limit: {
        type: 'number',
        description: 'Max events to return (default: 100, max: 10000). Does not apply to stats/timechart queries.',
      },
      source_type: {
        type: 'string',
        description: 'Filter to specific source type (optional, can also be in query)',
      },
    },
    required: ['query', 'start_time'],
  },
}
```

**Key design decisions for search:**
- Return results as **structured JSON**, not pre-formatted text. Claude decides how to present based on what was asked ("show me the raw logs" vs "summarize the activity").
- Include metadata in response: `total_count`, `query_time_ms`, `compiled_sql` (so Claude can debug if results are unexpected).
- For stats queries, return the full aggregation result (usually small). For event queries, respect the limit and include `has_more: true` if truncated.
- Truncate very long field values (e.g., `command_line` > 500 chars) with `[truncated]` marker.

### Alerts

Read-only alert visibility. Alerts are managed exclusively through cases — they cannot be independently acknowledged, closed, or assigned. To triage alerts, add them to a case and manage the case lifecycle.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `list_alerts` | List alerts with filters (severity, status, time range, rule name, assigned_to). Returns summary view. | `GET /api/alerts` |
| `get_alert` | Full alert detail: matched events, detection rule info, ai_triage_hints, enrichment, linked case. | `GET /api/alerts/:id` |
| `get_alert_counts` | Alert count breakdown by severity, status, source. "How busy is the SOC?" | `GET /api/alerts/counts` |

**Design: alert → case escalation flow**

```
Claude triages alert-456:
  → get_alert(456) — reads matched events + detection rule
  → Detection has ai_triage_hints: suspicious_when includes "activity outside business hours"
  → Alert fired at 3am → matches suspicious_when criteria

  [investigation happens via search/entity tools]

  → create_case(title="...", severity="high")
  → add_alert_to_case(case_id, alert_id=456)
  → change_case_status(case_id, status="in_progress")
```

The `get_alert` response should include the detection rule's `ai_triage_hints` so Claude can use the ignore_when/suspicious_when guidance the detection author wrote.

### Cases

Full investigation lifecycle — read, create, update, link alerts, manage status.

**Read operations:**

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `list_cases` | List cases with filters (status, severity, assignee, search text, tags, time range) | `GET /api/cases` |
| `get_case` | Full case detail: alerts, entities, wall entries, timeline, linked notebook | `GET /api/cases/:id` |
| `get_my_cases` | Get cases assigned to the current user | `GET /api/cases/my` |
| `get_case_stats` | Case workload overview (open by severity, avg time to resolve) | `GET /api/cases/stats` |
| `get_related_cases` | Find historically similar cases (entity overlap, technique similarity) | `GET /api/cases/:id/related` |
| `get_case_wall` | Get case wall entries (comments, status changes, AI analysis, enrichment results) | `GET /api/cases/:id/wall` |

**Write operations:**

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `create_case` | Create new case from investigation findings. Accepts title, description, severity, tags. Optionally links an initial alert. | `POST /api/cases` |
| `update_case` | Update case metadata (title, description, severity, tags) | `PUT /api/cases/:id` |
| `change_case_status` | Update case status with optional disposition: `open → in_progress → resolved → closed`. Disposition: `true_positive`, `false_positive`, `benign`, `inconclusive`. | `POST /api/cases/:id/status` |
| `assign_case` | Assign case to a user (or unassign) | `POST /api/cases/:id/assign` |
| `add_alert_to_case` | Link an alert to a case (correlate related alerts) | `POST /api/cases/:id/alerts` |
| `remove_alert_from_case` | Unlink an alert from a case | `DELETE /api/cases/:id/alerts/:alert_id` |
| `add_case_wall_entry` | Add investigation finding, comment, or recommendation to the case wall. Entry types: `comment`, `ai_analysis`, `enrichment_result`, `action_taken`. | `POST /api/cases/:id/wall` |
| `merge_cases` | Merge duplicate/related cases into a single case | `POST /api/cases/:id/merge` |
| `link_notebook_to_case` | Attach a notebook to a case as the investigation workspace | `POST /api/cases/:id/notebook` |

**How Claude uses cases during investigation:**

```
User: "investigate alert-456"

Claude:
  → get_alert(456) — reads the alert
  → get_related_cases(entities from alert) — "have we seen this before?"
  → No related cases. This is new.
  → create_case(title="Suspicious DNS exfil from 10.5.2.40", severity="high")
  → add_alert_to_case(case_id, alert_id=456)
  → create_notebook(title="Investigation: DNS exfil 10.5.2.40")
  → link_notebook_to_case(case_id, notebook_id)

  [investigation proceeds, findings go to notebook]

  → add_case_wall_entry(case_id, type="ai_analysis",
      content="Confirmed DNS tunneling to xyz.ru. See notebook for full timeline.")
  → change_case_status(case_id, status="in_progress")
```

**Critical for agentic investigation: `get_related_cases`**

This is the "have I seen this before?" branch. When Claude finds something suspicious, it should always check for related cases. The response includes:
- Historical cases sharing entities (IPs, users, hosts, hashes)
- Disposition of those cases (was it FP? TP? What was the resolution?)
- This prevents Claude from re-investigating known patterns

### Entity Context & Assets

"Who/what is this?" — the enrichment layer that makes investigation useful.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `get_entity_context` | Rich context for any entity: IP, host, user, domain, hash. Returns activity summary, first/last seen, associated alerts, risk score. | `GET /api/enrichment/entity` |
| `get_asset_events` | Full activity timeline for an asset (host/IP) within a time range | `POST /api/search/assets/events` (search service) |
| `get_asset_artifacts` | Unique artifacts seen on an asset: processes, domains, IPs, users, files | `POST /api/search/assets/artifacts` (search service) |
| `lookup_ip` | GeoIP + ASN enrichment for an IP address | `GET /api/enrichment/ip/:ip` |
| `lookup_ioc` | Check if a domain/IP/hash is a known IOC (ThreatFox, Tor exit nodes) | `GET /api/enrichment/ioc/:value` |

**`get_entity_context` is the investigation pivot:**

When Claude encounters an entity (IP, user, host), this single call returns everything needed to decide "is this interesting?":
- First/last seen timestamps
- Total event count in last 24h/7d
- Associated alert count and severities
- Risk score (from risk scoring engine)
- Known asset info (hostname, OS, owner) if available
- Recent source_types (what kind of logs do we have for this entity?)

This is the tool that enables the "one search leads to three parallel investigations" pattern — Claude sees an IP, calls `get_entity_context`, and based on the response decides whether to dig deeper.

### Prevalence ("Is this normal?")

The #1 SOC question. These tools answer it quantitatively.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `get_prevalence` | How common is this artifact? Returns host count, event count, first/last seen. Works for: file hash, domain, IP, process name, URL. | `GET /api/prevalence/:type/:value` |
| `get_rare_artifacts` | Find rare artifacts in a time range (things seen on < N hosts) | `GET /api/prevalence/rare` |
| `get_new_artifacts` | Find artifacts seen for the first time in a time range | `GET /api/prevalence/new` |

**Why this matters for agentic investigation:**

Claude finds a process hash → calls prevalence → learns it exists on 1 of 4000 hosts → immediately flags it as suspicious. Without prevalence, Claude can only say "this process exists." With prevalence, Claude can say "this process is unique to this machine and was first seen 2 hours ago."

### Risk Scoring

Entity-level risk aggregation.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `get_risky_entities` | Top entities by risk score (who/what is most suspicious right now?) | `GET /api/risk/entities` |
| `get_risk_overview` | Risk landscape summary: count of entities above thresholds, trend | `GET /api/risk/overview` |
| `get_entity_risk_timeline` | Risk score over time for a specific entity (spot escalation) | `GET /api/risk/entities/:entity/timeline` |

### Detection Rules

Read-only inspection of the detection library. (Write operations stay in nanodac.)

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `list_detections` | List all detection rules with summary (name, severity, mode, match_count) | `GET /api/detections` |
| `get_detection` | Full detection rule including query, MITRE mapping, ai_triage_hints | `GET /api/detections/:id` |
| `get_detection_matches` | Recent matches for a specific detection (what's it been catching?) | `GET /api/detections/:id/matches` |
| `get_detection_stats` | Match counts over time for a detection (is it noisy?) | `GET /api/detections/:id/stats` |

**Use case:** Claude is triaging an alert → reads the detection rule that fired → uses ai_triage_hints → checks recent match volume → provides informed triage recommendation.

### Investigation Notebooks

Persistent investigation workspaces. The durable memory layer for multi-step investigations. Notebooks are the connective tissue between Claude's investigation and the SIEM UI — everything Claude writes to a notebook is visible to analysts in the web interface.

**Read operations:**

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `list_notebooks` | List notebooks with filters (by case, by reference entity, shared with me) | `GET /api/notebooks` |
| `get_notebook` | Get notebook metadata (title, status, linked case, visibility) | `GET /api/notebooks/:id` |
| `get_notebook_entries` | Read all entries (findings, queries, notes, screenshots) — paginated | `GET /api/notebooks/:id/entries` |
| `get_notebook_references` | Get entities/artifacts referenced by this notebook (IPs, hashes, etc.) | `GET /api/notebooks/:id/references` |
| `find_notebooks_by_reference` | Find notebooks that reference a specific entity (e.g., "all notebooks mentioning 10.5.2.40") | `GET /api/notebooks/by-reference` |

**Write operations:**

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `create_notebook` | Create a new investigation notebook. Optionally link to a case immediately. | `POST /api/notebooks` |
| `add_notebook_entry` | Add an entry to a notebook. Types: `text` (narrative/finding), `query` (nPL query + results), `code` (scripts/IOCs), `note` (quick note). Content is JSON with type-specific structure. | `POST /api/notebooks/:id/entries` |
| `add_notebook_reference` | Link an entity/artifact to the notebook (creates a cross-reference for future lookups) | `POST /api/notebooks/:id/references` |
| `link_notebook_to_case` | Attach notebook to a case as the investigation workspace | `POST /api/notebooks/:id/link-case` |
| `unlink_notebook_from_case` | Detach notebook from a case | `DELETE /api/notebooks/:id/link-case` |
| `update_notebook` | Update notebook metadata (title, status, description) | `PUT /api/notebooks/:id` |
| `share_notebook` | Share notebook with another user or group | `POST /api/notebooks/:id/shares` |

**Entry type structures:**

```typescript
// Text entry — narrative findings, analysis, recommendations
{ type: "text", content: { text: "## Finding: DNS Exfiltration\n\nConfirmed tunneling..." } }

// Query entry — nPL query with results snapshot
{ type: "query", content: {
    query: "src_ip=10.5.2.40 | stats count by dns_query",
    time_range: { start: "...", end: "..." },
    results_summary: "247 unique DNS queries to xyz.ru subdomains",
    row_count: 247
  }
}

// Code entry — IOC lists, scripts, technical artifacts
{ type: "code", content: { language: "text", code: "xyz.ru\nabc.xyz.ru\ndef.xyz.ru\n..." } }

// Note entry — quick observations
{ type: "note", content: { text: "Parent process /tmp/.hidden/loader.py — need to check other hosts" } }
```

**How Claude uses notebooks — the investigation lifecycle:**

```
Phase 1: Setup
  → create_notebook(title="Investigation: Alert-456 DNS Exfil")
  → link_notebook_to_case(notebook_id, case_id)

Phase 2: Investigation (findings accumulate)
  → add_notebook_entry(type="query", content={query: "src_ip=10.5.2.40...", ...})
  → add_notebook_entry(type="text", content={text: "## Entity: 10.5.2.40\n\nThis is jsmith's laptop..."})
  → add_notebook_reference(entity_type="ip", value="10.5.2.40")
  → add_notebook_reference(entity_type="domain", value="xyz.ru")
  → add_notebook_entry(type="query", content={query: "dns_query=*.xyz.ru...", ...})
  → add_notebook_entry(type="text", content={text: "## Finding: Confirmed DNS Tunneling\n\n..."})

Phase 3: Conclusion
  → add_notebook_entry(type="text", content={text: "## Recommendations\n\n1. Block xyz.ru at DNS\n2. Isolate host\n3. ..."})
  → update_notebook(status="completed")
```

**Why notebooks matter for the agent pattern:**

1. **Investigation memory** — Long investigations exceed context windows. Claude persists findings as it goes, and can read them back after context compression. The notebook IS the investigation's long-term memory.
2. **Visibility** — Everything Claude writes is visible in the SIEM UI. Other analysts see the notebook in real-time, can jump in, add their own findings.
3. **Continuity** — Shadow investigation writes to notebooks. Claude can pick up where shadow investigation left off, or a human analyst can pick up where Claude left off.
4. **Cross-referencing** — `find_notebooks_by_reference` means Claude can ask "have we investigated this IP before in any notebook?" Not just cases — notebooks capture informal investigations too.
5. **Audit trail** — Every entry has a timestamp and creator. The investigation record is complete and attributable.

### MITRE ATT&CK

Technique context for investigations.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `get_mitre_technique` | Get details about a MITRE technique (description, detection guidance, examples) | `GET /api/mitre/techniques/:id` |
| `get_mitre_coverage` | What techniques does the detection library cover? Where are gaps? | `GET /api/mitre/coverage` |

### System Context

Environmental awareness.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `get_source_types` | What log sources are available? (helps Claude build valid queries) | `GET /api/fields/source-types` |
| `get_org_context` | Organizational context (industry, compliance requirements, etc.) | `GET /api/settings/organizational-context` |
| `health_check` | Is the SIEM healthy? ClickHouse status, search service status. | `GET /health` |

---

## MCP Resources

Resources are static-ish context that Claude loads once and uses throughout a session. These teach Claude *how* to be a SOC analyst on this specific SIEM.

### `nanosiem://schema/udm`

The full UDM field catalog. Every column name, type, description, and which `_search` column maps to it. This is the most important resource — it's how Claude knows what fields exist and how to query them.

```
UDM Field Reference

timestamp (DateTime) - Event timestamp. Always filter on this.
source_type (String) - Log source identifier. Use in PREWHERE.
message (String) - Raw log message. Search via message_search with hasToken().
src_ip (String) - Source IP address.
dest_ip (String) - Destination IP address.
...
```

### `nanosiem://reference/npl`

The nPL query language reference. Syntax, commands, functions, examples. Claude reads this to build correct queries.

```
nPL Query Reference

SYNTAX: search_term | command1 | command2

SEARCH TERMS:
  free text:    error, "connection refused"
  field=value:  src_ip="10.0.0.1", status=500
  regex:        user=/admin.*/
  ...

COMMANDS:
  where <condition>           - Filter events
  stats <agg> by <field>      - Aggregate
  timechart span=<interval>   - Time-series aggregation
  table <fields>              - Select columns
  sort [-]<field>             - Order results
  head <n>                    - First N results
  eval <expr>                 - Computed fields
  prevalence <field> <op> <n> - Filter by prevalence
  lookup <table> <field>      - Join lookup table
  risk score=<n> entity=<f>   - Add risk score
  ...

EVAL FUNCTIONS:
  cidr_match(ip, "10.0.0.0/8")
  is_private_ip(ip)
  extract_domain(url)
  base64_decode(field)
  md5(field), sha256(field)
  len(field), lower(field), upper(field)
  ...

CLICKHOUSE OPTIMIZATION NOTES:
  - Always filter by timestamp (partition pruning)
  - Use source_type in searches (PREWHERE optimization)
  - For free text search, nPL uses hasToken() on _search columns (bloom filters)
  - Stats queries return all groups, event queries respect limit
```

### `nanosiem://reference/playbooks/{type}`

Investigation methodology playbooks. These teach Claude the *process*, not just the tools.

**Available playbooks:**
- `brute_force` — How to investigate authentication attacks
- `lateral_movement` — How to trace host-to-host movement
- `data_exfil` — How to investigate potential data exfiltration
- `malware` — How to investigate suspected malware
- `phishing` — How to investigate phishing campaigns
- `insider_threat` — How to investigate insider behavior
- `generic` — General investigation methodology

**Example: `nanosiem://reference/playbooks/brute_force`**

```markdown
# Brute Force Investigation Playbook

## Step 1: Scope the Attack
- Search for the alerting source IP's authentication activity
- Query: `source_type=auth | where src_ip="{ip}" | stats count by user, dest_host, auth_result`
- How many users targeted? How many hosts? Success vs failure ratio?

## Step 2: Check for Successful Auth
- CRITICAL: Did any attempts succeed?
- Query: `src_ip="{ip}" auth_result=success`
- If yes → this is now an incident, not just an attempt

## Step 3: Entity Context
- Who owns this IP? (get_entity_context)
- Is it internal or external? (lookup_ip → GeoIP)
- Is it a known scanner? (lookup_ioc)
- Have we seen this IP before? (prevalence)

## Step 4: Blast Radius (if successful auth)
- What did the compromised account do after login?
- Query: `user="{user}" | sort timestamp | table timestamp, source_type, action, dest_host, process_name`
- Look for: lateral movement, privilege escalation, data access

## Step 5: Historical Context
- Have we seen similar attacks? (get_related_cases)
- Is this part of a campaign? (search for same src_ip in last 30 days)

## Step 6: Recommend Action
- FP: Known scanner, expected behavior → close alert
- Attempted brute force, no success → block IP, close alert
- Successful brute force → open case, reset credentials, investigate lateral movement
```

---

## MCP Prompts

Prompts are structured workflows that Claude follows when invoked. They're more opinionated than resources — they define a specific process.

### `investigate_alert`

Triggered when a user says "investigate this alert" or "triage alert 123."

```
You are investigating alert {alert_id} from nano.

Follow this investigation process:

1. READ the alert using get_alert — understand what fired and why
2. READ the detection rule using get_detection — understand the logic and ai_triage_hints
3. ASSESS: based on ignore_when/suspicious_when hints, is this likely FP or TP?
4. ENRICH key entities: for each IP/user/host in the alert, call get_entity_context
5. SEARCH for related activity: run 1-2 focused nPL queries to expand context
6. CHECK history: call get_related_cases to see if we've seen this before
7. PRESENT findings and recommend:
   - FALSE POSITIVE → explain why, recommend closing with disposition
   - NEEDS INVESTIGATION → explain concerns, recommend opening a case
   - TRUE POSITIVE → explain impact, recommend immediate actions

IMPORTANT: Do NOT investigate more than 2 levels deep without asking the analyst.
Present findings after each level and let them direct next steps.
```

### `hunt_entity`

Triggered when a user says "investigate this IP" or "hunt 10.0.0.1."

```
You are hunting for activity related to entity: {entity} (type: {entity_type})

Phase 1 — Context (run in parallel):
- get_entity_context for the entity
- lookup_ip (if IP) or lookup_ioc (if hash/domain) for enrichment
- get_prevalence to understand how common this entity is
- search last 24h for all activity involving this entity

Phase 2 — Assessment:
- Is this entity expected in this environment?
- What's its risk score?
- What source types have data for it?
- Any existing alerts or cases?

Phase 3 — Deep Dive (only the interesting branches):
- If external IP: what internal hosts communicated with it? What ports/protocols?
- If user: what hosts did they access? Any privilege escalation? Off-hours activity?
- If host: what processes ran? What network connections? Any rare artifacts?
- If hash/domain: prevalence across environment? First appearance?

Present findings after Phase 2. Ask analyst which threads to pull in Phase 3.
```

### `morning_briefing`

"What happened overnight?" — SOC shift handoff.

```
Generate a SOC shift briefing covering the last 12 hours.

1. ALERT SUMMARY
   - Call get_alert_counts for severity breakdown
   - Call list_alerts for critical/high alerts in last 12h
   - How many new vs acknowledged vs closed?

2. CASE STATUS
   - Call get_case_stats for open case overview
   - Any cases escalated or newly created?

3. RISK LANDSCAPE
   - Call get_risky_entities for top 10 riskiest entities
   - Any new entities appearing on the risk list?

4. DETECTION HEALTH
   - Any detections with unusual match volume (spike or drop)?
   - Call get_detection_stats for top noisy rules

5. ENVIRONMENT HEALTH
   - Call health_check — any data source issues?
   - Any log source gaps?

Present as a concise briefing with actionable items highlighted.
```

### `hunt_campaign`

Proactive threat hunting for a specific TTP or campaign.

```
You are conducting a proactive threat hunt for: {description}

1. PLAN the hunt
   - What MITRE techniques are relevant? (get_mitre_technique)
   - What log sources do we need? (get_source_types)
   - What entities/artifacts should we look for?

2. BUILD AND RUN QUERIES
   - Construct 3-5 nPL queries targeting different indicators
   - Run each with a 7-day lookback
   - Assess results: any hits? False positives?

3. ENRICH FINDINGS
   - For any suspicious hits, check prevalence
   - Cross-reference with IOC feeds (lookup_ioc)
   - Check for related alerts

4. REPORT
   - Summary of hunt (what we looked for, what we found)
   - Findings with evidence (specific events, entities)
   - Recommendations (new detection rules, blocks, investigations)
   - Detection gaps identified
```

---

## Agentic Investigation Patterns

### Depth Control

The core problem with agent-driven investigation isn't getting Claude to investigate — it will. The problem is **controlling scope** so it's useful without burning time/tokens.

**Investigation depth levels:**

| Level | Description | When to use |
|-------|-------------|------------|
| **Quick** | Answer the literal question. 1-2 tool calls. | "How many alerts today?" |
| **Standard** | Answer + one level of context. 3-5 tool calls. | "Anything weird from VPN?" |
| **Deep** | Multi-step investigation with branching. 5-15 tool calls. | "Investigate alert-123" |
| **Autonomous** | Full shadow-investigation style. 15-30 tool calls. | "Run a full investigation on this case" |

**Default: Standard.** Claude should:
1. Answer the question (1-2 queries)
2. Add one level of enrichment (entity context, prevalence check)
3. **Stop and present findings**
4. Offer specific next steps the analyst can choose

**Deep mode** is activated explicitly ("investigate this thoroughly") or when Claude identifies something clearly anomalous that warrants deeper analysis. Even then, Claude should checkpoint after each phase.

### Parallel Investigation Branching

When Claude encounters multiple entities of interest, it investigates them in parallel using MCP's native tool call batching:

```
Claude finds 3 suspicious IPs in a search result

→ Parallel tool calls:
  get_entity_context(ip="10.5.2.40")
  get_entity_context(ip="10.5.3.12")
  get_entity_context(ip="10.5.4.88")

→ Results come back:
  10.5.2.40: risk=75, 3 prior alerts, rare process
  10.5.3.12: risk=0, normal activity, known server
  10.5.4.88: risk=45, first seen today, unknown owner

→ Claude focuses investigation on 10.5.2.40 and 10.5.4.88
  (drops 10.5.3.12 — normal activity)
```

For Claude Code specifically, the Task tool (subagents) enables heavier parallel branching:

```
Main agent: "Two interesting entities. Investigating in parallel."

  → Task agent 1: "Full timeline for 10.5.2.40, last 48h"
     (calls search, get_asset_artifacts, lookup_ip, etc.)

  → Task agent 2: "Who is 10.5.4.88? New host investigation"
     (calls get_entity_context, search, get_prevalence, etc.)

Main agent: Synthesizes findings from both branches
```

### Investigation Memory via Notebooks

Long investigations exceed context windows. Claude persists findings to notebooks:

```
Claude: "This investigation is getting complex. Let me save my findings so far."
  → add_notebook_entry(case_notebook, type="ai_analysis", content="...")

[Later, after context compression]

Claude: "Let me check my investigation notes."
  → get_notebook(case_notebook)
  → Reads previous findings, continues from where it left off
```

This also means other analysts can see Claude's work in the SIEM UI.

### The "Have I Seen This Before?" Pattern

Every non-trivial investigation should include a historical case search. This is the most underrated SOC capability — it's the difference between investigating from scratch and standing on the shoulders of past incidents.

```
Claude: *investigating DNS exfiltration pattern*
  → get_related_cases(entities=["xyz.ru", "10.5.2.40"])
  → Finds CASE-0412 from 3 months ago: DNS tunneling, same subnet
  → CASE-0412 was true positive, resolved by blocking domain + reimaging host
  → Claude: "We had a similar case 3 months ago (CASE-0412). Same technique,
     same subnet. That was confirmed DNS tunneling. Recommend same response playbook."
```

---

## CLAUDE.md Context (bundled with the MCP server)

The MCP server should ship with a `CLAUDE.md` that gets added to projects using it. This teaches Claude the SIEM-specific knowledge it needs:

```markdown
# nano Investigation Context

## You are a SOC analyst assistant. When investigating:

### Query Building Rules
- Always filter by timestamp (nPL does this automatically from time range)
- Use source_type when known (optimizes query via PREWHERE)
- For free text, just search the term: `connection refused`
- For field searches: `src_ip="10.0.0.1"`, `user=admin`
- Use stats for aggregation: `| stats count by src_ip`
- Chain commands: `source_type=auth | where action="failed" | stats count by src_ip | where count > 10`

### Key Source Types
[populated from get_source_types on first run — or from org config]

### Investigation Methodology
1. Scope → Enrich → Correlate → Present → Recommend
2. Never go more than 2 levels deep without checking with the analyst
3. Always check prevalence before flagging something as suspicious
4. Always check related cases before declaring something novel
5. Use ai_triage_hints from detection rules when triaging alerts

### Entity Types and How to Investigate
- **IP**: get_entity_context → lookup_ip → search activity → check alerts
- **User**: get_entity_context → search auth activity → check for priv esc → check off-hours
- **Host**: get_entity_context → get_asset_artifacts → search processes → check prevalence
- **Hash**: get_prevalence → lookup_ioc → search for all hosts with this hash
- **Domain**: get_prevalence → lookup_ioc → search DNS + proxy logs
```

---

## Result Formatting

Claude Code renders GitHub-flavored markdown in a monospace terminal. The MCP tools return structured JSON, and Claude chooses the right presentation:

**Event results → table:**
```
| timestamp           | src_ip     | dest_ip     | action  | user    |
|---------------------|------------|-------------|---------|---------|
| 2026-02-22 03:14:02 | 10.5.2.40  | 8.8.8.8     | dns     | -       |
| 2026-02-22 03:14:03 | 10.5.2.40  | 8.8.8.8     | dns     | -       |
```

**Stats results → summary table:**
```
Top source IPs by failed logins (last 24h):

| src_ip        | attempts | unique_users | first_seen          |
|---------------|----------|--------------|---------------------|
| 203.0.113.50  | 1,247    | 89           | 2026-02-21 18:30:00 |
| 198.51.100.23 | 456      | 12           | 2026-02-22 01:15:00 |
```

**Investigation findings → narrative:**
```
## Investigation: 10.5.2.40

**Asset:** jsmith-macbook (macOS 14.2, owner: jsmith@company.com)
**Risk Score:** 75/100 (elevated)
**First Seen:** 2025-08-15 | **Last Active:** 2026-02-22 03:14

### Findings
- 247 DNS queries to unique subdomains of `xyz.ru` between 02:00-03:14
- All queries from process `svchost.exe` (PID 4821) — **anomalous on macOS**
- Parent process: `/tmp/.hidden/loader.py` — **first seen today, prevalence 1/4000**
- No prior alerts for this host
- 1 related case: CASE-0412 (DNS tunneling, same subnet, confirmed TP)

### Recommendation
**Severity: High** — Likely DNS exfiltration/C2 beaconing.
Recommend: Isolate host, block xyz.ru at DNS, open case, engage IR.
```

---

## Auth & API Key Scoping

The MCP server authenticates via API key. The key should be scoped to minimize blast radius:

**Required permissions (view):**
- `search:view` — View saved searches
- `search:execute` — Execute nPL queries, field stats, asset lookups
- `search:save` — Save searches, create shared search links
- `detections:view` — View detection rules, matches, stats
- `alerts:view` — List and view alerts
- `cases:view` — List and view cases, wall entries, related cases
- `enrichments:view` — Entity context, IOC lookups
- `prevalence:view` — Prevalence lookups (domain, IP, hash, user, process)
- `notebooks:view` — Read notebooks, entries, references
- `risk:view` — Risk scores, entity risk, overview
- `mitre:view` — ATT&CK data, coverage

**Required permissions (write):**
- `cases:create` — Create new cases
- `cases:edit` — Update case status, add wall entries, manage alerts, merge cases
- `cases:assign` — Assign cases to analysts
- `notebooks:create` — Create investigation notebooks
- `notebooks:edit` — Add entries, add references, link to cases, share, update status

**NOT needed:**
- `detections:edit` — That's nanodac's domain
- `settings:*` — No config changes
- `users:*` — No user management
- `admin:*` — No system administration
- `log_sources:*` — No ingestion pipeline changes
- `dashboards:*` — Not in scope (yet)

The MCP server self-restricts by only wrapping the endpoints listed in the tool catalog. Even if the API key has broader permissions, the MCP server doesn't expose tools for destructive operations (delete case, delete alert, etc.). The one exception is `merge_cases` which is destructive but operationally necessary — Claude should always confirm before merging.

---

## Implementation Phases

### Phase 1: Foundation
- MCP server skeleton with stdio transport
- Core client extending `@nanodac/core` NanosiemClient (add search service methods)
- `search` tool — the most important one
- `list_alerts` + `get_alert` tools
- `get_entity_context` tool
- UDM schema resource
- nPL reference resource
- Basic CLAUDE.md

**Validates:** Can Claude build queries, search, and present results?

### Phase 2: Investigation Depth
- Full alert toolkit (acknowledge, close)
- Full case toolkit (list, get, create, comment, related)
- Prevalence tools
- Risk tools
- Detection inspection tools
- `investigate_alert` prompt
- `hunt_entity` prompt

**Validates:** Can Claude run a complete alert triage workflow?

### Phase 3: Advanced Operations
- Enrichment tools (IP, IOC, domain)
- Notebook tools (read, write, create)
- MITRE tools
- Investigation playbook resources
- `morning_briefing` prompt
- `hunt_campaign` prompt
- Result formatters for different output types

**Validates:** Can Claude run autonomous multi-step investigations?

### Phase 4: Polish & Integration
- Combined server option with nanodac (detect → investigate loop)
- Investigation memory (notebook persistence for long investigations)
- Slash commands for Claude Code (`/investigate`, `/hunt`, `/briefing`)
- Per-org customization (custom playbooks, source type catalog)
- Token/cost optimization (truncation strategies, smart field selection)

---

## Differentiators — What Sets the Bar

These are the features that move this from "MCP wrapper around a SIEM API" to "no other SOC tool does this."

### 1. Shared Search Links (Terminal → SIEM UI Bridge)

Claude creates shareable links that open directly in the SIEM web UI. This bridges the terminal investigation to the visual interface:

```
Claude: "Here's what I found. Three interesting queries if you want
         to explore further in the UI:"

  → create_shared_search(query="src_ip=10.5.2.40 | timechart span=1m count by dns_query",
      time_range="-24h")

  "1. DNS activity timeline: https://nanosiem.local/search?s=abc123
   2. Process tree: https://nanosiem.local/search?s=def456
   3. Full asset view: https://nanosiem.local/search?s=ghi789"
```

Other analysts can click those links and see exactly what Claude was looking at, with the same time range and query. This is how you hand off from terminal to team.

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `create_shared_search` | Generate a short URL for a query + time range. Opens in SIEM web UI. | `POST /api/search/share` |

### 2. Second Opinion on Shadow Investigations

Shadow investigation runs automatically when a case is created. Claude can read its output and provide a **second opinion** — catching what the automated investigation missed:

```
User: "review the shadow investigation for case 789"

Claude:
  → get_case(789) — reads case details
  → get_notebook(case_notebook_id) — reads shadow investigation findings
  → get_notebook_entries(notebook_id) — reads all entries

  "The shadow investigation covered the alerting IP and user but missed two things:

   1. It didn't check the parent process — the Python script in /tmp
      was spawned by a cron job that was added 3 days ago. That cron job
      is on 2 other hosts too.

   2. It found 'no related cases' but there IS a related notebook (not case)
      from analyst jdoe last month investigating the same subnet.

   Let me fill in these gaps."

  → search for parent process chain
  → find_notebooks_by_reference("10.5.2.0/24")
  → add_notebook_entry(type="text", content="## Second Opinion: Gaps in Auto-Investigation\n\n...")
```

### 3. Saved Search Library Access

The SIEM has a library of pre-built queries. Claude can browse and use them instead of always building from scratch:

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `list_saved_searches` | List user's saved searches + shared searches from the team | `GET /api/search/saved` |
| `get_saved_search` | Get a saved search's query, time range, description | `GET /api/search/saved/:id` |
| `save_search` | Save a query Claude built for reuse by the team | `POST /api/search/saved` |

```
Claude: "Let me check if we have an existing query for lateral movement detection."
  → list_saved_searches(filter="lateral movement")
  → Finds "Lateral Movement - PsExec Detection" saved by senior analyst
  → Uses that query instead of building from scratch
  → "Using the team's existing lateral movement query. Here's what it found..."
```

Claude learns from the team's query library. And when Claude builds a good query during investigation, it saves it back for the team.

### 4. Query Explanation + Teaching Mode

Claude can explain any query, any detection rule, any MITRE technique — making it a training tool for junior analysts:

```
User: "explain the query behind rule brute_force_ssh"

Claude:
  → get_detection("brute_force_ssh")
  → explain_query(rule.query)  — gets the compiled SQL too

  "This detection does 4 things:

   1. Filters to SSH auth logs (source_type=ssh_logs)
   2. Keeps only failed logins (where action='login_failed')
   3. Counts failures grouped by source IP
   4. Fires when any IP has > 10 failures in the 15-min window

   The compiled SQL uses PREWHERE on timestamp + source_type for
   partition pruning, then hasToken on message_search for the
   action filter. The stats become a GROUP BY with HAVING.

   The ai_triage_hints say to ignore known security scanners
   and flag especially when multiple usernames are targeted."
```

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `explain_query` | Show the SQL a nPL query compiles to, with explanation | `POST /api/search/explain` |

### 5. Audit Trail of Claude's Actions

Every action Claude takes through the MCP server is logged in the SIEM's audit trail. This means complete accountability:

```
AUDIT LOG:
  2026-02-22 15:30:01 | api_key:mcp-investigator | search:execute | query="src_ip=10.5.2.40"
  2026-02-22 15:30:03 | api_key:mcp-investigator | alert:acknowledge | alert_id=456
  2026-02-22 15:30:15 | api_key:mcp-investigator | case:create | case_id=789
  2026-02-22 15:30:16 | api_key:mcp-investigator | notebook:create | notebook_id=abc
  2026-02-22 15:30:45 | api_key:mcp-investigator | notebook:add_entry | type=query
  ...
```

| Tool | Description | API Endpoint |
|------|-------------|-------------|
| `get_audit_trail` | Query audit logs — including Claude's own actions. "What did I do during this investigation?" | `POST /api/audit/search` |

This serves double duty: accountability for what Claude did, and Claude can review its own investigation history.

### 6. Risk-Based Prioritization

Instead of just "show me alerts," Claude can reason about entity risk to prioritize what matters:

```
User: "what should I be looking at right now?"

Claude:
  → get_risky_entities(limit=10) — top 10 by risk score
  → get_alert_counts() — current alert volume
  → list_alerts(status="new", severity=["critical","high"])

  "3 things need attention:

   1. **10.5.2.40** — Risk score 82 (jumped from 15 yesterday).
      3 detections fired: DNS exfil, rare process, off-hours activity.
      No case open yet.

   2. **svc-backup** (service account) — Risk score 65.
      Authenticated to 12 hosts in 10 minutes (normally touches 2).
      1 alert: lateral movement detection.

   3. 14 medium alerts from brute_force_ssh — all from the same
      scanner IP (203.0.113.50). Recommend bulk close as FP."
```

This is triage-by-risk, not triage-by-queue. Claude combines risk scores, alert context, and prevalence to surface what actually matters.

### 7. The Full Investigation Report

At the end of an investigation, Claude can synthesize everything into a structured report — pulling from the notebook, case wall, queries run, and findings:

```
User: "write up the investigation for case 789"

Claude:
  → get_case(789)
  → get_notebook_entries(notebook_id)
  → get_audit_trail(filter="case_id=789")

  ## Investigation Report: CASE-789 — DNS C2 Beaconing

  **Severity:** High | **Status:** In Progress | **Analyst:** claude-investigator
  **Duration:** 2026-02-22 15:30 → 15:52 (22 minutes)

  ### Executive Summary
  Confirmed DNS-based C2 beaconing from jsmith's laptop (10.5.2.40)
  to xyz.ru. Malicious Python loader in /tmp, first seen 2026-02-22 01:47.
  2 other hosts in the same subnet have the same cron persistence mechanism.

  ### Timeline
  - 01:47 — Loader script dropped to /tmp/.hidden/loader.py
  - 01:48 — Cron job created for persistence
  - 02:00 — DNS beaconing begins (30s intervals, TXT records)
  - 03:14 — Detection fires: dns_exfil_beaconing
  - 15:30 — Investigation initiated via Claude

  ### Entities Involved
  | Entity | Type | Risk | Notes |
  |--------|------|------|-------|
  | 10.5.2.40 | IP | 82 | jsmith-macbook, patient zero |
  | xyz.ru | Domain | - | C2 domain, prevalence 1/4000 |
  | /tmp/.hidden/loader.py | File | - | Dropper, SHA256: abc... |

  ### Queries Run (shareable)
  1. [DNS activity timeline](https://nanosiem.local/search?s=abc123)
  2. [Process tree analysis](https://nanosiem.local/search?s=def456)
  3. [Lateral spread check](https://nanosiem.local/search?s=ghi789)

  ### Recommendations
  1. Isolate 10.5.2.40, 10.5.3.22, 10.5.4.11 (all compromised)
  2. Block xyz.ru at DNS resolver
  3. Detection rule created: dns_txt_beaconing (PR #42)
  4. Scan all hosts for /tmp/.hidden/ directory

  → add_case_wall_entry(case_id, type="ai_analysis", content=report)
  → add_notebook_entry(notebook_id, type="text", content=report)
```

The report lives in the case wall AND the notebook — visible to the entire SOC team in the SIEM UI.

### 8. Query Intelligence — Finding the Needle

This is the real make-or-break. Tools don't matter if Claude writes bad queries that miss the signal or return garbage. The UDM has **484 fields**, nPL has its own optimization patterns, and ClickHouse has specific behaviors that matter. Claude needs to be _good_ at this.

**Three layers that make Claude's queries precise:**

#### Layer 1: The UDM Schema Resource (loaded once per session)

Not just field names — a **curated investigation guide** per field category. The MCP resource `nanosiem://schema/udm` doesn't dump 484 raw fields. It's organized by investigation scenario:

```markdown
## When Investigating Authentication
Fields: user, src_ip, dest_host, auth_result, auth_type, auth_method, session_id
Search tip: auth_result values are "success", "failure", "locked_out"
Common query: source_type=auth | where auth_result="failure" | stats count, values(user), values(dest_host) by src_ip

## When Investigating Process Execution
Fields: process_name, command_line, parent_process, process_hash, process_id, file_path
Search tip: Use `process` for full command line, `process_name` for just the exe.
  parent_process is critical — always include it.
Common query: process_name="powershell.exe" | table timestamp, src_host, user, process, parent_process

## When Investigating DNS
Fields: dns_query, dns_response, dns_response_code, dest_ip (resolver), src_ip
Search tip: dns_query contains the full FQDN. Use extract_domain() to get base domain.
Common query: dns_query=/.*\.xyz\.ru$/ | stats count, dc(dns_query) as unique_subdomains by src_ip

## When Investigating Network Connections
Fields: src_ip, dest_ip, src_port, dest_port, protocol, bytes_in, bytes_out
Search tip: bytes_out > bytes_in may indicate exfiltration
Common query: dest_port NOT IN (80, 443, 53) | stats sum(bytes_out) as total_out by src_ip, dest_ip, dest_port | sort -total_out
```

This teaches Claude **what to search for** and **how to express it**, not just what fields exist.

#### Layer 2: Dynamic Source Type Discovery

Before building a query about a topic Claude hasn't searched before, it calls `get_source_types` and `get_field_values` to learn what data actually exists:

```
User: "any lateral movement?"

Claude: *thinks: I need to search for host-to-host connections, but
         what source types contain this data?*

  → get_field_values(field="source_type", limit=50)
  → Finds: windows_security, sysmon, firewall_paloalto, zeek_conn, ...

  → get_field_values(field="event_id", filter="source_type=windows_security")
  → Finds: 4624, 4625, 4648, 4688, 4689, ...

  *Now builds targeted queries per source:*
  → search("source_type=windows_security event_id=4624 logon_type=3
            | stats count, values(src_host), values(user) by dest_host
            | where count > 1 AND src_host != dest_host")

  → search("source_type=sysmon event_id=3
            | where dest_port IN (445, 135, 5985, 5986, 3389)
            | stats count by src_ip, dest_ip, dest_port")
```

Claude doesn't guess — it discovers what's available, then builds precise queries against actual data.

#### Layer 3: Query Refinement Loop

Claude doesn't fire-and-forget queries. It evaluates results and refines:

```
Claude: *runs initial query — gets 0 results*
  → "No results. Let me check if the field values I used are correct."
  → get_field_values(field="auth_result", source_type="ssh_logs")
  → Finds values are "accepted", "failed" (not "success", "failure")
  → Rewrites query with correct values
  → Gets 247 results

Claude: *runs a query — gets 50,000 results*
  → "Too broad. Let me narrow by adding source_type and time constraint."
  → Adds source_type filter + narrows time range
  → Gets 340 results — manageable

Claude: *runs a stats query — gets 1 group*
  → "Only one IP matched, but with 10,000 events. Let me drill down."
  → Pivots to event-level query for that IP with table view
  → Gets the specific events to analyze
```

**This refinement loop should be built into the system prompt:**

```markdown
## Query Refinement Protocol

After every search, evaluate the results:
- 0 results → Check field values are correct (get_field_values). Check source_type exists. Widen time range.
- 1-100 results → Good. Analyze directly.
- 100-1000 results → Summarize with stats, drill down on interesting groups.
- 1000-10000 results → Too many to analyze. Add filters, narrow time, use stats aggregation.
- 10000+ results → Way too broad. Use stats/timechart first to understand the shape, then drill down.

When a query returns unexpected results:
1. Use explain_query to see the SQL — is it doing what you intended?
2. Check get_field_values for the fields you're filtering on — are the values what you expected?
3. Try a more specific source_type — maybe the field exists but isn't populated in all sources.
```

#### Layer 4: The "Hunting Patterns" Library

Pre-built query patterns for common investigation scenarios. Not just saved searches — templates with placeholders that Claude fills in:

```markdown
## Hunting Pattern: Beacon Detection
# Find regular-interval callbacks (C2 beaconing)
source_type={network_source}
  | where dest_ip="{suspect_ip}" OR dns_query="{suspect_domain}"
  | eval interval=timestamp - lag(timestamp) by src_ip
  | stats avg(interval) as avg_interval,
          stddev(interval) as jitter,
          count() as total_connections,
          min(timestamp) as first_seen,
          max(timestamp) as last_seen
    by src_ip, dest_ip
  | where avg_interval > 10 AND avg_interval < 300
  | where jitter / avg_interval < 0.3  -- low jitter = beaconing

## Hunting Pattern: Credential Dumping
# LSASS access or known dumping tools
source_type=sysmon
  | where (event_id=10 AND target_process CONTAINS "lsass")
     OR process_name IN ("mimikatz.exe", "procdump.exe", "nanodump.exe")
     OR (process_name="rundll32.exe" AND command_line CONTAINS "comsvcs")
  | table timestamp, src_host, user, process_name, command_line, parent_process, target_process

## Hunting Pattern: Data Staging
# Large file operations or compression before exfil
source_type=sysmon
  | where process_name IN ("7z.exe", "rar.exe", "zip.exe", "tar.exe", "winrar.exe")
     OR (process_name="powershell.exe" AND command_line CONTAINS "Compress-Archive")
  | table timestamp, src_host, user, process, parent_process, file_path
  | eval cmd_len=len(command_line)
  | where cmd_len > 50
```

These live as MCP resources. Claude reads the relevant pattern, fills in the entity/context from the current investigation, and runs it. Much more reliable than generating from scratch every time.

**The combination of these four layers** means Claude isn't just throwing queries at the wall. It knows the schema, discovers what data exists, refines based on results, and has proven patterns for common hunts. That's what finds the needle.

---

## Open Questions

1. **Combined vs separate MCP servers?** Running nanodac + nano-investigator separately keeps concerns clean but adds config overhead. A combined `nanosiem-mcp` with both tool sets is simpler for users. Lean toward combined with feature flags.

2. **Result size management.** Large search results can blow up MCP message sizes. Strategy: always limit events to 100 by default, include `has_more` flag, let Claude request more if needed. For stats, return all groups (usually small).

3. **Streaming search results.** The search service supports streaming (`search_stream`). MCP doesn't natively support streaming tool results. For now, use standard request/response with limits. If MCP adds streaming, adopt it.

4. **Write operations scope.** How much should Claude be able to *do* vs *recommend*? Starting conservative: Claude can search (read), triage alerts (limited write), add case comments (write). Cannot: create detection rules (that's nanodac), modify system settings, delete anything.

5. **Multi-tenant.** If the SIEM has RBAC, the MCP API key inherits those restrictions. Claude only sees what the key's user can see. No additional tenant isolation needed in the MCP server.

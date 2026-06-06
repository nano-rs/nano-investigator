# Getting Started with nano-investigator

An MCP server that turns Claude Code (or any MCP client) into an interactive SOC analyst workstation. Search logs, triage alerts, investigate cases, and hunt threats — all through natural language.

## Prerequisites

- Node.js >= 20.0.0
- pnpm >= 9.0.0
- A running nano instance

## Install

```bash
git clone <repo-url> nano-investigator
cd nano-investigator
pnpm install
pnpm build
```

## Configure your MCP client

Add nano-investigator to your MCP client config. For Claude Code, add to `~/.claude/settings.json` (or your project's `.mcp.json`):

```json
{
  "mcpServers": {
    "nano-investigator": {
      "command": "node",
      "args": ["/path/to/nano-investigator/packages/mcp-server/dist/index.cjs"],
      "env": {
        "NANOSIEM_API_URL": "https://nanosiem.example.com:3000",
        "NANOSIEM_API_KEY": "your-api-key",
        "NANOSIEM_SEARCH_URL": "https://nanosiem.example.com:3002"
      }
    }
  }
}
```

| Variable | Required | Description |
|----------|----------|-------------|
| `NANOSIEM_API_URL` | Yes | nano API URL (port 3000) |
| `NANOSIEM_API_KEY` | Yes | API key for authentication |
| `NANOSIEM_SEARCH_URL` | No | Search service URL (port 3002). Falls back to `NANOSIEM_API_URL` if not set. |

The server also reads `.env` / `.env.local` files from the working directory.

## API key permissions

Create an API key in nano with the following scopes. The server only needs view access for most operations, plus limited create/edit access for triage workflows.

### Required — view

| Permission | What it enables |
|------------|-----------------|
| `search:view` | View saved searches |
| `search:execute` | Execute nPL queries, field stats, asset lookups |
| `search:save` | Save searches, create shared search links |
| `detections:view` | View detection rules, matches, stats |
| `alerts:view` | List and view alerts |
| `cases:view` | List and view cases, wall entries, related cases |
| `enrichments:view` | Entity context, IOC lookups |
| `prevalence:view` | Prevalence lookups (domain, IP, hash, user, process) |
| `notebooks:view` | Read notebooks, entries, references |
| `risk:view` | Risk scores, entity risk, overview |
| `mitre:view` | ATT&CK data, coverage |

### Required — write

| Permission | What it enables |
|------------|-----------------|
| `cases:create` | Create new cases |
| `cases:edit` | Update case status, add wall entries, manage alerts, merge |
| `cases:assign` | Assign cases to analysts |
| `notebooks:create` | Create investigation notebooks |
| `notebooks:edit` | Add entries/references, link to cases, share, update |

### Optional — log source & parser management

Add these only if you want the assistant to author and deploy log-source parsers — the `list_log_sources` / `create_log_source` / `update_log_source` / `deploy_log_source` / `import_parser` / routing-rule tools. They control what nano ingests and how it's parsed, so grant them only when you want that capability.

| Permission | What it enables |
|------------|-----------------|
| `log_sources:view` | List/inspect log sources, deployments and health; validate and test VRL |
| `log_sources:create` | Save new parsers as drafts |
| `log_sources:edit` | Update existing parsers, toggle enabled |
| `log_sources:deploy` | Deploy / undeploy parsers to Vector |
| `source_configs:view` | List source configurations and routing rules, check rule reachability |
| `source_configs:edit` | Create and edit routing rules |
| `parser_repositories:view` | Browse parser repositories and their parsers |
| `parser_repositories:sync` | Refresh a parser repository |
| `parser_repositories:import` | Import a prebuilt parser as a draft |

### Not needed

`detections:edit`, `settings:*`, `users:*`, `admin:*`, `dashboards:*`, `log_sources:delete`, `source_configs:create`, `source_configs:delete`, `parser_repositories:manage`

Even if the key has broader permissions, the MCP server self-restricts to the tools listed above — it never exposes destructive operations like deleting cases, alerts, or log sources.

## Verify it works

Once configured, start a Claude Code session and try:

```
> how many alerts fired today?

> is the SIEM healthy?
```

Claude will call `get_alert_counts` and `health_check` behind the scenes.

## Quick commands to try

### Search & explore

```
> search for failed logins in the last 24 hours
> any DNS activity to .ru domains this week?
> what source types are available?
> show me the top talkers by bytes out in the last hour
```

### Alert triage

```
> show me today's critical alerts
> investigate alert 456
> how many alerts fired this week?
```

### Entity investigation

```
> what do we know about 10.5.2.40?
> is 203.0.113.50 a known IOC?
> how common is svchost.exe running on macOS hosts?
> investigate user jsmith — anything unusual in the last 48h?
```

### Cases & notebooks

```
> open cases assigned to me
> create a case for the DNS exfil from 10.5.2.40
> add a finding to the notebook for case 789
> any previous investigations involving xyz.ru?
```

### Risk & prevalence

```
> who are the riskiest entities right now?
> what should I be looking at first this morning?
> find artifacts seen for the first time today
```

### Threat hunting

```
> hunt for lateral movement in the last 7 days
> look for beacon-like traffic to external IPs
> any credential dumping activity on Windows hosts?
```

## Available tools (49)

The full tool catalog, grouped by category:

### Search (8)
`search` `search_sql` `explain_query` `get_field_values` `list_saved_searches` `get_saved_search` `save_search` `create_shared_search`

### Alerts (3)
`list_alerts` `get_alert` `get_alert_counts`

### Cases (10)
`list_cases` `get_case` `get_case_stats` `get_related_cases` `create_case` `update_case` `change_case_status` `assign_case` `add_alert_to_case` `add_case_wall_entry` `merge_cases`

### Notebooks (8)
`list_notebooks` `get_notebook` `get_notebook_entries` `find_notebooks_by_reference` `create_notebook` `add_notebook_entry` `add_notebook_reference` `update_notebook` `share_notebook`

### Detections (3)
`list_detections` `get_detection` `get_detection_matches`

### Prevalence (3)
`get_prevalence` `get_rare_artifacts` `get_new_artifacts`

### Risk (3)
`get_risky_entities` `get_risk_overview` `get_entity_risk_timeline`

### Enrichment (3)
`get_entity_context` `lookup_ip` `lookup_ioc`

### MITRE ATT&CK (2)
`get_mitre_technique` `get_mitre_coverage`

### System (3)
`get_source_types` `get_org_context` `health_check`

### Audit (1)
`get_audit_trail`

## Resources & prompts

The server also exposes **MCP resources** (context that gets loaded into the conversation) and **prompts** (structured investigation workflows):

**Resources:**
- `nanosiem://schema/udm` — UDM field catalog organized by investigation scenario
- `nanosiem://reference/npl` — nPL query language reference
- `nanosiem://reference/playbooks/{type}` — Investigation playbooks (brute_force, lateral_movement, data_exfil, malware, phishing, insider_threat, generic)

**Prompts:**
- `investigate_alert` — Full alert triage workflow
- `hunt_entity` — Entity-focused threat hunt
- `hunt_campaign` — Proactive campaign hunting
- `morning_briefing` — SOC shift handoff briefing

## Development

```bash
pnpm dev          # watch mode (rebuilds on change)
pnpm test         # run tests
pnpm typecheck    # type check without emitting
pnpm clean        # remove build artifacts
```

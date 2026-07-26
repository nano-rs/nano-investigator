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

Each tool publishes its exact, versioned requirement in MCP `_meta` under
`io.nano/permission-requirements`. The tables below are useful key profiles;
clients should use the tool metadata as the authoritative contract.

### Investigation baseline

| Permission | What it enables |
|------------|-----------------|
| `search:view` | Read saved searches and the base UDM schema |
| `search:execute` | Execute and explain nPL, field stats, extended-schema discovery |
| `log_sources:view` | Inspect log sources and use the parser validation tools |
| `lookup:view` | Execute nPL searches that use the `lookup` command |
| `detections:view` | View detection rules, matches, stats |
| `alerts:view` | List and view alerts |
| `cases:view` | List and view cases, wall entries, related cases |
| `enrichments:view` | IP enrichment |
| `prevalence:view` | Prevalence lookups |
| `notebooks:view` | Read notebooks, entries, references |
| `risk:view` | Risk scores, entity context, activity, and overview |
| `mitre:view` | ATT&CK data and technique details |
| `dashboards:view` | Read dashboards and run nPL dashboard panels |
| `source_configs:view` | Inspect ingress transports and routing |
| `parser_repositories:view` | Browse the prebuilt-parser catalogue |

Raw SQL is not part of the baseline. nPL is the primary search surface and works
with `search:execute`. Grant `search:sql` only for queries nPL cannot express,
such as cross-table joins, prevalence-state aggregates, or direct `ext` JSON
access. Raw SQL is also rejected when the API principal is source-scoped, so
granting the scope does not bypass source isolation.

### Optional — investigation writes

| Permission | What it enables |
|------------|-----------------|
| `cases:create` | Create new cases |
| `cases:edit` | Edit and merge cases, attach alerts, update non-closed status |
| `cases:close` | Close or reopen cases |
| `cases:assign` | Assign cases to analysts |
| `cases:comment` | Add case wall entries |
| `notebooks:create` | Create investigation notebooks |
| `notebooks:edit` | Add entries/references and update notebooks |
| `notebooks:share` | Share notebooks |
| `search:save` | Save a reusable search |
| `search:share` | Create a shared-search link |
| `risk:clear` | Reset one entity's accumulated risk |
| `dashboards:create` | Create dashboards |
| `dashboards:edit` | Update dashboards |

### Optional — log source & parser management

Add these only if you want the assistant to author, route, and deploy ingestion.
They control what nano ingests and how it is parsed.

| Permission | What it enables |
|------------|-----------------|
| `log_sources:create` | Save new parsers as drafts |
| `log_sources:edit` | Update existing parsers |
| `log_sources:deploy` | Deploy or undeploy parsers |
| `source_configs:view` | Inspect transports and check rule reachability |
| `source_configs:create` | Create an ingress transport |
| `source_configs:edit` | Create and edit routing rules |
| `source_configs:deploy` | Deploy or undeploy an ingress transport |
| `credentials:create` | Store a new transport credential |
| `credentials:use` | Attach a stored credential to a transport and deploy it |
| `parser_repositories:view` | Browse parser repositories |
| `parser_repositories:sync` | Refresh a parser repository |
| `parser_repositories:import` | Import a prebuilt parser as a draft |

### Optional — sensitive context

| Permission | What it enables |
|------------|-----------------|
| `settings:ai` | Read organizational context |
| `audit:view` | Read the audit trail |

The server exposes no delete tool for cases, alerts, dashboards, log sources, or
source configurations. Broader key permissions do not create tools that are not
in the MCP inventory.

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

## Available tools (84)

The full tool catalog, grouped by category:

### Search (9)
`search` `search_sql` `get_schema` `explain_query` `get_field_values` `list_saved_searches` `get_saved_search` `save_search` `create_shared_search`

### Alerts (3)
`list_alerts` `get_alert` `get_alert_counts`

### Cases (12)
`list_cases` `get_case` `review_case` `get_case_stats` `get_related_cases` `create_case` `update_case` `change_case_status` `assign_case` `add_alert_to_case` `add_case_wall_entry` `merge_cases`

### Notebooks (9)
`list_notebooks` `get_notebook` `get_notebook_entries` `find_notebooks_by_reference` `create_notebook` `add_notebook_entry` `add_notebook_reference` `update_notebook` `share_notebook`

### Dashboards (7)
`get_dashboard_schema` `validate_dashboard` `dashboard_panel_query` `list_dashboards` `get_dashboard` `create_dashboard` `update_dashboard`

### Detections (3)
`list_detections` `get_detection` `get_detection_matches`

### Prevalence (3)
`get_prevalence` `get_rare_artifacts` `get_new_artifacts`

### Risk (5)
`get_risky_entities` `get_risk_overview` `get_entity_risk_timeline` `get_entity_risk_activity` `reset_entity_risk`

### Enrichment (2)
`get_entity_context` `lookup_ip`

### MITRE ATT&CK (2)
`get_mitre_technique` `get_mitre_coverage`

### System (4)
`get_source_types` `get_org_context` `health_check` `get_audit_trail`

### Parser authoring & ingestion (21)
`list_log_sources` `get_log_source` `validate_vrl` `test_parse_sample` `test_parse_live` `create_log_source` `update_log_source` `deploy_log_source` `undeploy_log_source` `get_log_source_health` `get_log_source_deployments` `list_source_config_types` `list_source_configs` `create_routing_rule` `check_rule_reachability` `deploy_source_config` `undeploy_source_config` `list_parser_repositories` `sync_parser_repository` `list_repository_parsers` `import_parser`

### Guided onboarding (4)
`onboarding_requirements` `import_credential_from_file` `create_credential` `create_source_config`

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

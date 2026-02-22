# nano-investigator

MCP server that turns Claude Code (or any MCP client) into an interactive SOC analyst workstation for [nano](https://nanosiem.io). Search logs, triage alerts, investigate cases, and hunt threats through natural language.

## Quick Start

```bash
git clone git@github.com:nanos-sh/nano-investigator.git
cd nano-investigator
pnpm install
pnpm build
```

Copy the example config and fill in your credentials:

```bash
cp .mcp.json.example .mcp.json
# Edit .mcp.json with your nano URL and API key
```

Or add to your Claude Code settings (`~/.claude/settings.json`):

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
| `NANOSIEM_API_URL` | Yes | nano API URL |
| `NANOSIEM_API_KEY` | Yes | API key for authentication |
| `NANOSIEM_SEARCH_URL` | No | Search service URL (falls back to `NANOSIEM_API_URL`) |

## What You Can Do

```
> how many alerts fired today?
> investigate alert 456
> what do we know about 10.5.2.40?
> search for failed logins in the last 24 hours
> any DNS activity to .ru domains this week?
> who are the riskiest entities right now?
> create a case for the DNS exfil from 10.5.2.40
> hunt for lateral movement in the last 7 days
```

## Tools (49)

| Category | Count | Tools |
|----------|-------|-------|
| **Search** | 8 | `search` `search_sql` `explain_query` `get_field_values` `list_saved_searches` `get_saved_search` `save_search` `create_shared_search` |
| **Alerts** | 3 | `list_alerts` `get_alert` `get_alert_counts` |
| **Cases** | 11 | `list_cases` `get_case` `get_case_stats` `get_related_cases` `create_case` `update_case` `change_case_status` `assign_case` `add_alert_to_case` `add_case_wall_entry` `merge_cases` |
| **Notebooks** | 9 | `list_notebooks` `get_notebook` `get_notebook_entries` `find_notebooks_by_reference` `create_notebook` `add_notebook_entry` `add_notebook_reference` `update_notebook` `share_notebook` |
| **Detections** | 3 | `list_detections` `get_detection` `get_detection_matches` |
| **Prevalence** | 3 | `get_prevalence` `get_rare_artifacts` `get_new_artifacts` |
| **Risk** | 3 | `get_risky_entities` `get_risk_overview` `get_entity_risk_timeline` |
| **Enrichment** | 3 | `get_entity_context` `lookup_ip` `lookup_ioc` |
| **MITRE ATT&CK** | 2 | `get_mitre_technique` `get_mitre_coverage` |
| **System** | 4 | `get_source_types` `get_org_context` `health_check` `get_audit_trail` |

## Resources & Prompts

**Resources** (context loaded into conversation):
- `nanosiem://schema/udm` -- UDM field catalog
- `nanosiem://reference/npl` -- nPL query language reference
- `nanosiem://reference/playbooks/{type}` -- Investigation playbooks

**Prompts** (structured workflows):
- `investigate_alert` -- Full alert triage
- `hunt_entity` -- Entity-focused threat hunt
- `hunt_campaign` -- Proactive campaign hunting
- `morning_briefing` -- SOC shift handoff

## Project Structure

```
packages/
  core/           # API client + TypeScript types
  mcp-server/     # MCP server (tools, resources, prompts)
```

## Development

```bash
pnpm dev          # watch mode
pnpm test         # run tests
pnpm typecheck    # type check
pnpm clean        # remove build artifacts
```

## API Key Permissions

See [GETTING_STARTED.md](./GETTING_STARTED.md) for the full list of required API key scopes.

## License

MIT

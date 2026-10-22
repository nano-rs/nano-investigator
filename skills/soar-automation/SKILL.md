---
name: soar-automation
description: >-
  Use when asked to automate a response or build SOAR content in nano with the MCP tools, without
  the UI. Covers installing an integration pack, creating and testing a connection, running a pack
  action (contain a host, disable a user, block an IOC), and building a flow/playbook with alert,
  case or schedule triggers. Also use to review run history, approvals or SOAR audit. Applies the
  confirmation, dry-run and write-only credential rules that every SOAR write needs.
---

# SOAR Automation

**Principle: every SOAR action can reach a production system outside nano. Rehearse with a dry run, show the user exactly what will be sent, and act only on their explicit approval of that specific change.**

The MCP server serves the same guidance as the `soar_workflow` prompt. Use these tools from desktop or pivt.

## Workflow

| Step | Tools | Gate |
|---|---|---|
| 0. Is SOAR on? | `get_soar_settings` | If disabled, stop. A human tenant admin enables it in nano Settings. API keys cannot. |
| 1. Find a pack | `list_soar_packs` → `get_soar_pack` | Read only. Use only signed-catalog names. |
| 2. Install / upgrade | `install_soar_pack`, `upgrade_soar_pack` | `user_confirmed=true`. Show `change_summary` before an upgrade. |
| 3. Connect | `create_soar_connection`, `update_soar_connection` | `user_confirmed=true`. Credentials are write-only (see below). |
| 4. Test | `test_soar_connection` | `user_confirmed=true`. Calls the vendor's read-only test action. |
| 5. Run an action | `list_soar_actions` → `run_soar_action dry_run=true` → `get_soar_run` → `run_soar_action user_confirmed=true` | A live run is MUTATING. Dry run first, every time. |
| 6. Approvals | `list_soar_approvals`, `get_soar_approval` | Read only. A human decides in nano. Agents cannot approve. |
| 7. Flows (playbooks) | `validate_soar_flow` → `create_soar_flow` (draft) → `run_soar_flow dry_run=true` → `update_soar_flow status=live` | `user_confirmed=true`. **live arms automatic triggers.** |
| 8. History / audit | `list_soar_runs`, `get_soar_run`, `get_audit_trail resource_type=soar`, `cancel_soar_run` | Cancel needs confirmation. Sent steps cannot be recalled. |

## Confirmation rules

- Ask before every write tool. Name the pack, connection, action, inputs, target entity and expected effect. Then pass `user_confirmed=true`.
- One approval covers one change. Re-ask if the action, connection, inputs or flow status changes.
- `run_soar_action` / `run_soar_flow` with `dry_run=true` need no confirmation. Nothing is sent, and approvals are skipped.
- Moving a flow to `live` means future alerts, cases or schedules run it **without asking anyone**. Say so explicitly.
- A step marked `ambiguous` may already have reached the vendor. Never retry it blindly. Check the vendor state with the user.

## Credentials are write-only

- Ask the user to provide credentials for the fields in `get_soar_pack` `credential_fields`. Never guess, generate or reuse them from elsewhere.
- Send them once in `create_soar_connection` / `update_soar_connection`. The API never returns them, and the tools redact them from every output, including errors.
- Never write credential values into notebooks, case walls, summaries or follow-up messages. Refer to them as "the configured credential".
- To check configuration, use `credential_fields[].configured` and `ready`, never the value.

## Checklist

- [ ] SOAR enabled (`get_soar_settings`)
- [ ] Pack installed at the intended version
- [ ] Connection `ready` and last test succeeded
- [ ] Dry run reviewed with the user (rendered `request_summary`)
- [ ] Explicit approval for this exact live change, then `user_confirmed=true`
- [ ] Run outcome read back (`get_soar_run`), with any approval wait reported, not assumed
- [ ] Case linked (`case_id`) when the action is part of an investigation

## Related skills

- `benign-business-ruleout`: rule out legitimate activity before containing a host or disabling a user.
- `case-temporal-scoping`: scope the incident before choosing a response.

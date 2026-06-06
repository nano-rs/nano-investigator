---
name: case-temporal-scoping
description: >-
  Use when reviewing, resuming, or investigating a case, alert, or entity in nano-investigator —
  BEFORE trusting the case/alert time window. A case window only reflects when detections fired,
  not when the activity started or whether it is still going. This skill expands the investigation
  window in BOTH directions: backward into the lead-up period (to catch earlier-stage activity the
  rules missed) and forward through "now" (to detect whether the campaign is ongoing or has spread).
  Trigger on requests like "review/investigate case X", "deep dive", "build a timeline",
  "what happened on this host/user", or any time you are about to scope an investigation to the
  alert timestamps alone.
---

# Case Temporal Scoping

**Principle: the case window is where detections *fired*, not where the activity *lived*. Never let the alert/case timestamps define your investigation window.**

A case grouped from alerts at 23:03–23:05 tells you when rules matched — it tells you nothing about the loader that ran at 23:00, the recon that ran two days earlier, or whether the same actor is still active today. Most missed scope comes from investigating only the window the SIEM handed you.

## Always investigate three windows

1. **The case window** — what the alerts captured. Start here, but treat it as the *middle* of the story.
2. **The lead-up (look backward)** — sweep the entity's activity in the hours-to-weeks *before* the first alert. This is where you find: the initial loader/dropper, first-stage execution, the *first* occurrence of a chain that later recurred, and recon that preceded the noisy step. In this codebase's reference case, the LSASS-dump chain had run twice on a prior day and was preceded by an `update.exe` loader and followed by a `del /f /q` cleanup — none of which were in the case's alerts.
3. **The follow-up (look forward through now)** — sweep from the case window to the present. This reveals: whether the activity is a one-off or recurring, whether it spread to other hosts/users (lateral movement), and whether it is still active. "Last finding today" on an entity's risk timeline is a forward-scope signal — chase it.

## How to do it (nano-investigator)

Anchor on the primary entity (host/user) from the case, not just the matched events.

```
# 1. Lead-up: did this behavior exist before the case? (baseline window, e.g. -14d to case start)
source_type=windows_sysmon (src_host="<host>" OR user="<user>") action=process_create
| table timestamp, src_host, user, process_name, command_line, parent_process_name

# 2. Full local context around the case window (NOT just the matched events) — get the process tree
source_type=windows_sysmon (src_host="<host>") 
| table timestamp, action, process_name, command_line, parent_process_name, process_id, parent_process_id
# widen ±15min first; the loader and the cleanup live just outside the alerts

# 3. Follow-up: is it still happening / has it spread? (case end → now)
source_type=windows_sysmon (user="<user>") | stats count by src_host | sort -count
source_type=windows_sysmon (user="<user>") action=process_create <suspicious-indicators>
| table timestamp, src_host, process_name, command_line
```

- Lead with a `timechart`/histogram or `stats count by` to see *bursts* across the wide window cheaply, then drill into the bursts. Don't pull raw rows across weeks.
- Pull the **parent/child process tree** around key events — the alert shows you the matched process, not what spawned it or what it spawned next.
- When you find activity on a new host/user in the forward sweep, that host/user becomes a new entity to scope (recurse, but check in with the analyst per the depth rules in CLAUDE.md).

## Checklist before you call scoping "done"

- [ ] Searched the lead-up window — confirmed where the activity actually *began* (not where it was detected).
- [ ] Pulled the full process tree around the case window, not just the alert's matched events.
- [ ] Swept forward to *now* — established whether the activity is one-off, recurring, or ongoing.
- [ ] Checked whether the same entity/behavior appears on *other* hosts or accounts.
- [ ] Recorded the *true* first-seen and last-seen times in the notebook timeline (these usually differ from the case timestamps).

## Related skills
- `entity-baseline-comparison` — once you have the lead-up data, use it to judge whether the behavior is actually new/anomalous.
- `benign-business-ruleout` — apply before concluding the in-window or follow-up activity is malicious.

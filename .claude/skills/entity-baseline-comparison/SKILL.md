---
name: entity-baseline-comparison
description: >-
  Use when you've found a notable behavior, command, process, IOC, or pattern for an entity
  (user, host, or IP) and need to judge whether it is actually anomalous — before flagging it as
  suspicious, rare, new, or "first seen." Establishes the entity's HISTORICAL baseline by querying
  its activity in the period BEFORE the incident window, so you can tell new/escalating behavior
  apart from routine activity for that entity. Trigger whenever you are about to describe something
  as "suspicious", "unusual", "rare", "new", "never seen before", or are assessing whether an
  entity's activity represents a change.
---

# Entity Baseline Comparison

**Principle: "suspicious" is a comparison, not an absolute. Before you call activity anomalous, ask "is this new or escalating *for this entity*?" and answer it with data.**

The same command can be routine for one account and a red flag for another. A `wmic /node:` sweep from an SCCM service account is business as usual; from a workstation user it is enumeration. You cannot make that call without the entity's baseline.

## When to pull a baseline

Any time you're tempted to write "unusual," "rare," "first time," "spike," or "new behavior" — stop and establish the baseline first. Also pull a baseline whenever an investigation's verdict hinges on whether activity is a *change*.

## How to baseline (nano-investigator)

Query the entity's activity in a window **before** the incident's first activity (e.g. the 1–4 weeks prior), then compare to the in-incident activity.

```
# Does this specific behavior predate the incident? (the decisive query)
source_type=windows_sysmon user="<user>" <the-behavior-filter>
| stats count by command_line | sort -count
#   run once for the baseline window (e.g. -21d .. incident_start)
#   run again for the incident window — compare presence, volume, breadth

# Volume/breadth baseline for the entity
source_type=windows_sysmon (user="<user>" OR src_host="<host>")
| timechart span=1h count by action       # establish the entity's normal rhythm
source_type=windows_sysmon user="<user>" <behavior> | stats dc(src_host) as hosts, dc(dest_ip) as dests
```

Also use the platform's built-in baseline tooling — don't hand-roll everything:
- **`get_prevalence`** (hash/domain) — how common is this artifact across the whole environment? Rare ≠ malicious, but common usually = benign. CLAUDE.md requires checking prevalence before flagging.
- **`get_entity_context` / `get_entity_risk_timeline`** — has this entity been risky before, or is this a step change?
- **`get_new_artifacts` / `get_rare_artifacts`** — what is genuinely first-seen vs. long-standing for the scope.

## Interpreting the comparison

| Baseline result | Reading |
|---|---|
| Behavior **absent** before incident, appears now | Genuinely new → elevates suspicion. State the first-seen date. |
| Behavior **present** before incident, similar volume/breadth | Pre-existing pattern → may be routine **or** a campaign that started earlier than the case. Pivot to `benign-business-ruleout`; do **not** assume benign just because it's old. |
| Behavior present before but **lower** volume/narrower | Escalation → describe the change quantitatively (was N hosts, now M). |

**Critical nuance:** a baseline match does *not* prove benign — it may mean the campaign predates the case (push the start date earlier in your timeline). A baseline miss does *not* prove malicious — it may be a new-but-legitimate tool rollout. Baseline tells you *whether it changed*; `benign-business-ruleout` tells you *whether it's legitimate*. Use both.

## Checklist

- [ ] Defined a pre-incident baseline window and queried the specific behavior in it.
- [ ] Compared presence / volume / breadth between baseline and incident windows.
- [ ] Ran `get_prevalence` for any hash/domain before calling it rare or suspicious.
- [ ] Stated the finding quantitatively ("first observed 5/27; absent in prior 30d" — not just "looks new").
- [ ] If the behavior predates the case, updated the timeline's start date accordingly.

## Related skills
- `case-temporal-scoping` — produces the lead-up data this skill compares against.
- `benign-business-ruleout` — the next step once you know whether behavior changed.

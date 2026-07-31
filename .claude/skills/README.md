# Investigation Rigor Skills

A growing set of focused skills that encode SOC investigation tradecraft for nano-investigator,
so the harness applies it **up front and automatically** during case reviews — rather than only
when an analyst happens to ask.

Each skill is one investigative lens with clear trigger conditions, nPL query templates, and a
checklist. They cross-reference each other and are designed to be added to over time.

## Activating

These are the canonical, version-controlled copies. Claude Code auto-loads skills from
`.claude/skills/`, so copy (or symlink) them there to turn them on: `cp -R skills/. .claude/skills/`.

## Current set

| Skill | Lens | Fires when |
|---|---|---|
| `case-temporal-scoping` | **When to look** | Scoping/starting/resuming a case or entity investigation. Expands the window backward (lead-up) and forward (follow-up through now) instead of trusting the alert timestamps. |
| `entity-baseline-comparison` | **Is it new?** | About to call something suspicious/rare/new. Pulls the entity's pre-incident baseline to judge whether behavior actually changed. |
| `benign-business-ruleout` | **Is it legitimate?** | At the verdict/disposition step. Applies discriminators to exclude normal business/admin/automation before a TP or FP call. |

## Origin

Seeded from a case review (Case #402, ws-eng-001 / jsmith) where the initial pass risked stopping
at the case window. Analyst guidance — *"do a deeper dive into the follow-up days and make sure
it's malicious activity and not just normal business activity"* — surfaced prior activity (the
chain had run on an earlier day; a loader and a cleanup step sat just outside the alerts) and
required validating "normal" against a baseline. These skills make that behavior the default.

## Conventions for adding skills

- One skill = one focused lens. Keep triggers in the `description` concrete (the model decides to
  invoke based on it).
- Include nano-investigator-specific query templates (respect the field names and tools in `CLAUDE.md`).
- End with a checklist and `## Related skills` cross-links.
- When a real investigation teaches a new lesson, add or extend a skill here and note it in `CLAUDE.md`'s
  Investigation Rigor section.

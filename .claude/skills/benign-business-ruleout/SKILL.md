---
name: benign-business-ruleout
description: >-
  Use before concluding that flagged activity is malicious (true positive) OR before dismissing it
  as benign — i.e. at the verdict/disposition step of any investigation or triage. Applies a set of
  discriminators to rule out legitimate business/admin/automation explanations: payload semantics,
  method diversity, breadth/fan-out, cadence/timing, identity & role context, and corroborating
  activity. Prevents both false positives (calling normal admin work an attack) and premature
  true-positive calls (assuming malicious without excluding the benign explanation). Trigger when
  assigning a verdict, writing an FP/TP assessment, or whenever the analyst asks "is this actually
  malicious or just normal activity?"
---

# Benign Business Rule-Out

**Principle: a true-positive call requires you to have *considered and rejected* the legitimate explanation. "It matched a detection" is not a verdict — "it matched, and here is why it can't be normal business" is.**

This applies symmetrically: don't cry wolf on normal admin work, and don't wave through real tradecraft because the account is "supposed" to do remote things.

## The discriminators

Run the flagged activity through each lens. No single lens decides; weigh them together.

1. **Payload semantics — what did it actually *do*?**
   Legitimate admin/automation accomplishes *work* (installs, config changes, data collection, service control). Recon/tradecraft accomplishes *knowledge* (`whoami`, `net group`, `nltest`, process listings) or nothing useful repeated many times. Ask: "what business task does this command complete?" If the answer is "none — it just enumerates," lean malicious.

2. **Method diversity for the same goal.**
   Legitimate tooling standardizes on one mechanism. Seeing the *same trivial payload* delivered via several interchangeable techniques (e.g. `winrs` + `wmic process call create` + PowerShell `Invoke-Command` all running `whoami`) is "test which technique lands" behavior — a strong malicious tell.

3. **Breadth / fan-out.**
   Role-scoped admin work touches a bounded, sensible set of assets. One account touching one box in *every* business unit (FIN, HR, LEGAL, EXEC, …), or enumerating a domain controller from a workstation, is enterprise-wide reconnaissance.

4. **Cadence & timing.**
   Human admin work is irregular and task-shaped. Metronomic spacing (e.g. each step exactly 60s apart), tight automated bursts, or repeating near-identical target sets day over day indicate scripting/scheduling — note it. Off-hours alone is weak; off-hours + the other lenses is strong.

5. **Identity & role context.**
   Is the account *supposed* to do this? Check the account's role/function (ask IT/HR if the platform won't say; `get_org_context` may be permission-gated). Caveat: if a privileged account is doing the activity, that does **not** clear it — privileged accounts are the prime compromise target. A sysadmin account dumping LSASS is *account abuse/compromise*, not "expected."

6. **Corroborating context.**
   Does the activity sit alongside confirmed-malicious actions by the same entity (credential dump, exfil, C2)? Coupling collapses the benign explanation even for individually-ambiguous steps.

## Decide

- **Malicious (TP):** multiple lenses point the same way and you can articulate why the benign explanation fails. Write that articulation into the disposition.
- **Benign / FP:** the activity completes a real business task, via expected tooling, at expected breadth, by an account whose role fits — and you confirmed it (ideally against `entity-baseline-comparison`). Document what made it benign so the next analyst doesn't re-litigate it.
- **Unresolved:** if a lens is unknowable from telemetry (e.g. role unconfirmed), say so explicitly and state what would resolve it — don't paper over the gap with a confident verdict.

## Honest-verdict rules

- State your caveats. If you couldn't confirm role, business hours, or actual network egress, say it plainly in the assessment.
- Distinguish "no evidence it's benign" from "evidence it's malicious" — and vice versa. Absence of logs (e.g. no proxy record of egress) is not proof either way; flag it as a gap to close.
- Prefer "consistent with X, pending Y" over false certainty.

## Checklist

- [ ] Ran the activity through all six discriminators.
- [ ] Explicitly stated why the *legitimate* explanation does or doesn't hold.
- [ ] Checked the account's role/function (or flagged it as unconfirmed).
- [ ] Used `entity-baseline-comparison` to ground "normal" in data, not assumption.
- [ ] Wrote caveats and evidence gaps into the verdict — no unsupported certainty.

## Related skills
- `entity-baseline-comparison` — supplies the "what's normal for this entity" evidence this skill reasons over.
- `case-temporal-scoping` — ensures you're judging the *full* activity, not just the case window, before issuing a verdict.

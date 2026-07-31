/**
 * Lead capture for an unattended hunt sweep — the sweep runs on the analyst's own
 * coding CLI and hands findings back one at a time, as it finds them.
 *
 * WHY A TOOL AND NOT A FINAL JSON BLOB: a sweep can be cut off at any turn. If the
 * agent is asked to remember everything and emit one blob at the end, a sweep killed
 * at turn 30 loses everything it found, and whatever does come back has to be parsed
 * out of prose and trusted. Here every call appends one durable line, so partial
 * capture is the normal case, not the failure case.
 *
 * SAFETY — this is deliberately the least privileged thing in the system, because an
 * unattended agent with attacker-authored log content in its context is holding it:
 *   1. NO network, NO nano API client, NO API key, NO subprocesses.
 *   2. It writes ONE file: the absolute path in NANO_HUNT_LEADS_FILE. Unset ⇒ the
 *      tool fails loudly rather than picking a path of its own.
 *   3. NO tool argument can influence WHERE it writes — the path comes only from the
 *      environment, is required to be absolute, is normalised, and must land directly
 *      in the (real) directory that contains it. A symlink at that path is refused,
 *      so the file cannot be redirected outside the directory either.
 *   4. It never reads a file back; it only appends.
 *   5. Everything is capped — per string, per array, per record, per file — so a
 *      runaway or hostile agent cannot fill the analyst's disk.
 *
 * FILE FORMAT (fixed contract with the desktop hunt runner — do NOT change):
 *   leads:      {"entity_type":…,"entity_value":…,"mitre_technique":…,"signals":[…],
 *                "evidence_event_ids":[…],"narrative":…}      ← no discriminator
 *   trail:      {"kind":"trail","at":"<ISO-8601>","note":…}   ← discriminator "kind"
 *   knowledge:  {"kind":"knowledge","category":…,"subject":…,"fact":…,
 *                "confidence":<number>,"evidence_event_ids":[…],"ttl_days":<number>}
 *   suppression:{"kind":"suppression","entity_type":…,"entity_value":…,"reason":…,
 *                "ttl_days":<number>}
 * One JSON object per line, appended and flushed per call. A reader treats any line
 * without `kind` as a lead.
 *
 * WHY KNOWLEDGE AND SUPPRESSION COME OUT THE SAME PIPE: recording either one
 * server-side needs `hunts:report`, and the sweep agent must never hold it — the
 * desktop's AGENT_KEY_FORBIDDEN says so, because this agent has attacker-authored
 * log content in its context. So the agent writes a line here, exactly like a lead,
 * and the runner — which does hold `hunts:report` — submits it to
 * POST /api/hunts/knowledge or POST /api/hunts/suppressions afterwards. The sweep id
 * is deliberately NOT a tool argument: the runner knows which lease it holds, and an
 * agent-supplied one would be the agent asserting that.
 *
 * WHY A SUPPRESSION IS STILL SAFE TO WRITE FROM HERE. Suppression is the one thing
 * on this surface an unattended agent must not be handed carelessly — a process that
 * can suppress can blind its own successors. Four properties keep it bounded, and
 * all four live outside this file: it names an ENTITY, and the server resolves that
 * to a lead THIS SWEEP filed and takes the fingerprint from the lead, so a sweep can
 * only ever suppress a finding it actually reported; the row it writes carries that
 * one fingerprint and no wildcard, hunt-wide or playbook form; a suppression ZEROES
 * a lead's score without hiding the lead, so an analyst still sees it, flagged, with
 * the reason attached; and it expires, on a ceiling the database enforces.
 *
 * The entity is deliberately the ONLY identity this tool asks for. An earlier
 * revision asked for a fingerprint, which no agent can obtain — fingerprints are
 * derived server-side from evidence the server resolved, this process has no network
 * and no hunt id, and record_lead returns none. Naming the entity is both the only
 * satisfiable contract and the safer one: it leaves no server-derived value a caller
 * could supply at all.
 */

import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { dirname, basename, isAbsolute, resolve, sep } from 'node:path';

export type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };

const ok = (data: unknown): ToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
});
const err = (message: string): ToolResult => ({
  content: [{ type: 'text', text: `Error: ${message}` }],
  isError: true,
});

// ── Caps (stated in the tool descriptions so the model knows them) ────────────
export const CAPS = {
  ENTITY_VALUE: 512, // identifier — rejected when longer, never silently truncated
  SIGNALS: 25,
  SIGNAL_LEN: 128,
  EVENT_IDS: 50,
  EVENT_ID_LEN: 128,
  NARRATIVE: 2000, // prose — truncated, never rejected (losing a lead is worse)
  TRAIL_NOTE: 300,
  MITRE_LEN: 16,
  // Knowledge. Category and subject are IDENTIFIERS — they group a rail in the UI —
  // so they are rejected when over-long, never truncated into a second identity.
  KNOWLEDGE_CATEGORY: 64, // matches the server's MAX_CATEGORY_CHARS
  KNOWLEDGE_SUBJECT: 512, // matches the server's MAX_SUBJECT_CHARS
  // Prose, so truncated — but far below the server's 4096-char bound on a fact,
  // because every live fact may be recalled into a LATER sweep's prompt. The cap
  // is a prompt-budget decision, not a storage one, and it keeps the truncated
  // form (plus its marker) comfortably inside what the server will accept.
  KNOWLEDGE_FACT: 1000,
  // Mirrors the server's MAX_TTL_DAYS. The server clamps regardless — this is here
  // so an agent asking for "permanent" learns immediately that nothing is.
  KNOWLEDGE_TTL_DAYS: 90,
  // Suppression. It names an entity, so it reuses ENTITY_VALUE's cap — the value
  // here is the SAME identifier that went to record_lead, and a cap that disagreed
  // would let a lead be recorded that could never afterwards be named.
  //
  // Prose, so truncated rather than rejected: an unexplained suppression is
  // unreviewable, and losing the reason's last clause beats losing the whole call.
  SUPPRESSION_REASON: 1000,
  // A reason shorter than this is almost certainly "noisy" or "benign" — a verdict
  // with no working shown. Warned about, not rejected, because the agent may have
  // been terse about something it genuinely established.
  SUPPRESSION_REASON_THIN: 40,
  // Mirrors the server's MAX_AGENT_SUPPRESSION_TTL_DAYS, and it is DELIBERATELY a
  // fraction of a fact's 90. The asymmetry is the point: a wrong fact costs a later
  // sweep a bad prior it can check, a wrong suppression costs it the finding. A
  // fortnight means a poisoned suppression self-heals before it can hide a campaign.
  SUPPRESSION_TTL_DAYS: 14,
  // The server's DEFAULT_AGENT_SUPPRESSION_TTL_DAYS, stated so an agent that omits
  // the field knows what it accepted rather than guessing.
  SUPPRESSION_TTL_DAYS_DEFAULT: 7,
  RECORDS_PER_PROCESS: 1000,
  FILE_BYTES: 16 * 1024 * 1024,
} as const;

export const ENTITY_TYPES = [
  'ip',
  'user',
  'host',
  'domain',
  'hash',
  'process',
  'url',
  'email',
  'file',
] as const;

/** T1021 / T1021.001 — a technique id, not a technique name. */
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;

/** The normalised category the knowledge API will accept: `[a-z0-9][a-z0-9_-]*`.
 *  Anything left outside it after folding is REJECTED here rather than stripped,
 *  for the same reason the server rejects it — a "category" that is really a
 *  paragraph of injected prose must not become a UI grouping header, and silently
 *  deleting characters would map two distinct categories onto one identity. */
const KNOWLEDGE_CATEGORY_RE = /^[a-z0-9][a-z0-9_-]*$/;

const LEADS_ENV = 'NANO_HUNT_LEADS_FILE';

// ── Path resolution + confinement ────────────────────────────────────────────
// Resolved per call (not at import) so the runner can set the env var however it
// likes and so tests can exercise the failure modes.

type ResolvedFile = { path: string };

async function resolveLeadsFile(): Promise<ResolvedFile | ToolResult> {
  const raw = (process.env[LEADS_ENV] ?? '').trim();
  if (!raw) {
    return err(
      `${LEADS_ENV} is not set, so there is nowhere to record this lead. The hunt runner sets it to the absolute path of the sweep's lead file. Report the finding in your answer instead — do not retry.`,
    );
  }
  if (!isAbsolute(raw)) {
    return err(`${LEADS_ENV} must be an absolute path (got "${raw}").`);
  }

  const target = resolve(raw); // normalises any "." / ".." inside the env value
  const name = basename(target);
  if (!name || name === '.' || name === '..') {
    return err(`${LEADS_ENV} must point at a file, not a directory (got "${raw}").`);
  }

  // The directory that CONTAINS the file is the only place we may write. Resolve it
  // through symlinks once, then require the target to sit directly inside it.
  let dir: string;
  try {
    dir = await realpath(dirname(target));
  } catch {
    return err(`The directory for ${LEADS_ENV} does not exist: ${dirname(target)}`);
  }
  const finalPath = `${dir}${dir.endsWith(sep) ? '' : sep}${name}`;
  if (dirname(finalPath) !== dir) {
    return err(`${LEADS_ENV} resolves outside its own directory — refusing to write.`);
  }

  // A symlink sitting at the lead path could redirect the append anywhere; refuse it.
  try {
    const st = await lstat(finalPath);
    if (st.isSymbolicLink()) {
      return err(`${LEADS_ENV} is a symlink — refusing to write through it.`);
    }
    if (!st.isFile()) {
      return err(`${LEADS_ENV} exists and is not a regular file — refusing to write.`);
    }
    if (st.size >= CAPS.FILE_BYTES) {
      return err(
        `The lead file has reached its ${CAPS.FILE_BYTES}-byte cap; nothing more will be recorded. Stop recording and summarise what you have.`,
      );
    }
  } catch {
    // Does not exist yet — the first append creates it.
  }

  return { path: finalPath };
}

const isToolResult = (v: ResolvedFile | ToolResult): v is ToolResult =>
  (v as ToolResult).content !== undefined;

// ── Append: one line, flushed, serialised ────────────────────────────────────
let recordsWritten = 0;
let writeChain: Promise<unknown> = Promise.resolve();

/** Serialise appends so two concurrent tool calls can never interleave a line. */
function serialised<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeChain.then(fn, fn);
  writeChain = next.catch(() => undefined);
  return next;
}

// Append-only, and O_NOFOLLOW where the platform has it: the lstat symlink check in
// resolveLeadsFile is a check-then-act, so the open itself must also refuse to
// follow a link planted in between. Windows has no O_NOFOLLOW — the lstat check
// stands alone there. Mode 0600: a sweep's leads are the analyst's, not the box's.
const APPEND_FLAGS =
  constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | (constants.O_NOFOLLOW ?? 0);

async function appendLine(path: string, line: string): Promise<void> {
  const fh = await open(path, APPEND_FLAGS, 0o600);
  try {
    await fh.write(`${line}\n`);
    // Flush per call: a sweep killed mid-run keeps everything already recorded.
    await fh.sync().catch(() => undefined);
  } finally {
    await fh.close();
  }
}

/** ELOOP means O_NOFOLLOW refused a symlink at the lead path — say so plainly
 *  rather than handing the model an errno. */
function writeFailure(e: unknown): string {
  const errno = (e as { code?: string }).code;
  if (errno === 'ELOOP') return `${LEADS_ENV} is a symlink — refusing to write through it.`;
  return (e as Error).message ?? String(e);
}

// ── Input coercion + caps ────────────────────────────────────────────────────

/** NULs would truncate the value for some readers; nothing else is stripped
 *  (JSON.stringify escapes newlines, so a line stays a line). */
const clean = (s: string): string => s.replace(/\u0000/g, '').trim();

function asString(v: unknown): string | null {
  if (typeof v === 'string') return clean(v);
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return null;
}

/** Collapse every whitespace run — INCLUDING newlines — to a single space.
 *
 *  A fact is one statement. The collapsed form is also what the server stores, and
 *  it denies a multi-line payload the framing it would need once the fact is
 *  recalled into a later sweep's prompt: no headings, no blank-line separation, no
 *  fake transcript. Applied to the fact only; a lead narrative is written for a
 *  human reading it in a pane and keeps its shape. */
const collapse = (s: string): string => s.split(/\s+/).filter(Boolean).join(' ');

/** Cut prose to a length without splitting a surrogate pair.
 *
 *  A cut through an emoji leaves a lone surrogate, which survives JSON.stringify as
 *  a `\udXXX` escape — and the runner's JSON parser REJECTS an unpaired one, so the
 *  whole record is lost to save one character. Same concern as the NUL strip above:
 *  the line has to survive a reader we do not control. */
const cut = (s: string, max: number): string => s.slice(0, max).replace(/[\uD800-\uDBFF]$/, '');

/** A finite number from a model that may have sent it as a string. Returns null for
 *  anything else — including NaN and ±Infinity, which must not reach the file. */
function asFiniteNumber(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string') {
    const trimmed = v.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

type ListResult = { items: string[]; warnings: string[] };

/** Accepts a string[] — or a lone string, since a model often sends one that way.
 *  Over-long items are dropped (an identifier cut in half is worse than absent),
 *  extra items past the cap are dropped; both are reported back to the caller. */
function asStringList(v: unknown, field: string, maxItems: number, maxLen: number): ListResult {
  const warnings: string[] = [];
  if (v === undefined || v === null) return { items: [], warnings };

  const raw = Array.isArray(v) ? v : [v];
  const items: string[] = [];
  let tooLong = 0;
  let nonString = 0;
  let overCap = 0;

  for (const entry of raw) {
    const s = asString(entry);
    if (s === null) {
      nonString += 1;
      continue;
    }
    if (!s) continue;
    if (s.length > maxLen) {
      tooLong += 1;
      continue;
    }
    if (items.includes(s)) continue; // duplicate — silently collapsed
    if (items.length >= maxItems) {
      overCap += 1;
      continue;
    }
    items.push(s);
  }

  if (tooLong) warnings.push(`${tooLong} ${field} entry/entries dropped: over ${maxLen} chars.`);
  if (nonString) warnings.push(`${nonString} ${field} entry/entries dropped: not text.`);
  if (overCap) warnings.push(`${overCap} ${field} entry/entries dropped: over the ${maxItems}-item cap.`);
  return { items, warnings };
}

// ── Tool definitions ─────────────────────────────────────────────────────────
// These descriptions are the sweep's ONLY instructions for how to use the tools.

export const TOOLS = [
  {
    name: 'record_lead',
    description:
      'Record ONE candidate finding from a hunt sweep. Call this the moment you are confident a finding is worth an analyst\'s attention — mid-sweep, once per lead. Do NOT batch leads and dump them at the end: the sweep can be cut off at any turn, and only what you have already recorded survives. ' +
      'Each call appends one line to the sweep\'s local lead file. Nothing is sent anywhere, nothing else is written, and no other tool state depends on it. ' +
      '`signals` must be stable IDENTIFIERS — MITRE technique ids, detection rule ids/names, source types — NOT prose; a sentence in `signals` is useless to the runner. ' +
      '`mitre_technique` is what you ACTUALLY found, which may differ from the technique this sweep set out to hunt — record what the evidence shows. ' +
      '`narrative` is written for a human analyst who will read it cold, with no memory of this sweep: name the entity, what it did, when, and why it is suspicious. ' +
      `Caps: entity_value ≤${CAPS.ENTITY_VALUE} chars (rejected if longer); signals ≤${CAPS.SIGNALS} items of ≤${CAPS.SIGNAL_LEN} chars; evidence_event_ids ≤${CAPS.EVENT_IDS} items of ≤${CAPS.EVENT_ID_LEN} chars; narrative ≤${CAPS.NARRATIVE} chars (truncated, not rejected); ≤${CAPS.RECORDS_PER_PROCESS} records per sweep. Over-cap list entries are dropped and reported back to you.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        entity_type: {
          type: 'string',
          enum: [...ENTITY_TYPES],
          description: 'What kind of thing the lead is about.',
        },
        entity_value: {
          type: 'string',
          description: `The entity itself — the IP, username, hostname, domain, hash, process name, URL, address or path. Exact value as it appears in the logs, ≤${CAPS.ENTITY_VALUE} chars.`,
        },
        signals: {
          type: 'array',
          items: { type: 'string' },
          description: `Stable identifiers for WHY this is a lead: MITRE technique ids, detection rule ids or names, source types. Identifiers only — no prose, no sentences. ≤${CAPS.SIGNALS} items of ≤${CAPS.SIGNAL_LEN} chars.`,
        },
        evidence_event_ids: {
          type: 'array',
          items: { type: 'string' },
          description: `Canonical event ids for the events that support this lead, exactly as returned by search. The runner resolves them back to the events, so an analyst can open the evidence — do not paraphrase or invent them. ≤${CAPS.EVENT_IDS} items.`,
        },
        mitre_technique: {
          type: 'string',
          description:
            'MITRE ATT&CK technique id for what you ACTUALLY found (e.g. T1021 or T1021.001) — may differ from the technique the sweep was hunting. Id only, not the technique name. Omit if nothing fits.',
        },
        narrative: {
          type: 'string',
          description: `Why this is interesting, for a human analyst reading it cold: entity, behaviour, timing, and what makes it stand out from normal. 1-4 sentences. ≤${CAPS.NARRATIVE} chars (longer is truncated).`,
        },
      },
      required: ['entity_type', 'entity_value'],
    },
  },
  {
    name: 'note_trail',
    description:
      'Record a one-line breadcrumb of what the sweep is doing right now — e.g. "sweeping T1021 lateral movement across srv-* for the last 24h" or "ruled out svc_backup: same pattern every night for 90 days". ' +
      'Cheap, call it when you start or finish a stage of the sweep. It gives the analyst the path the sweep took, including the dead ends, which is what makes the surviving leads readable. ' +
      `This is NOT a lead — findings go to record_lead. Cap: note ≤${CAPS.TRAIL_NOTE} chars (truncated).`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        note: {
          type: 'string',
          description: `One line of what the sweep is doing or has just concluded. ≤${CAPS.TRAIL_NOTE} chars.`,
        },
      },
      required: ['note'],
    },
  },
  {
    name: 'record_knowledge',
    description:
      'Record ONE durable fact about THIS environment that a future sweep should not have to re-derive. Every sweep starts cold; this is the only thing that carries forward. Call it when you have established something about the estate that cost you real work — not once per interesting event. ' +
      'GOOD knowledge is the boring explanation you paid for: "the 03:00 spike on svc_backup is the nightly job, confirmed across 90 days", "app_endpoint /api/bulk-export returns 200 with a 40MB body by design", "the srv-build-* fleet reimages nightly, so every host is 0-day-old". BAD knowledge is a restatement of a finding ("srv-web06 looks compromised"), a to-do, or anything you have not actually established. ' +
      'THIS IS NOT A SUPPRESSION. Knowledge only ever reaches a later sweep\'s PROMPT — it never dismisses a lead, hides a finding or down-ranks anything. If something looks malicious, it still goes to record_lead, today, whatever you have recorded about it before. ' +
      '`category` is yours to choose — there is deliberately no fixed taxonomy. Pick what the estate warrants (`account`, `app`, `app_endpoint`, `host`, `schedule`, `network`) and then REUSE it consistently: categories are the grouping headers an analyst reads, so twenty one-off categories are worth less than five reused ones. It is a header, not a sentence — the explanation goes in `fact`. ' +
      '`subject` is the one entity or thing the fact is about; `fact` is a single statement, on one line, that a stranger could act on without this sweep\'s context. ' +
      'Each call appends one line to the sweep\'s local file, exactly like record_lead. Nothing is sent anywhere: the hunt runner submits it after the sweep, and it stamps which sweep this was — you do not name it. ' +
      `Facts expire (default 30 days, ≤${CAPS.KNOWLEDGE_TTL_DAYS}); re-record one that still holds and it is reconfirmed rather than duplicated. An analyst can revoke one permanently. ` +
      `Caps: category ≤${CAPS.KNOWLEDGE_CATEGORY} chars of a-z, 0-9, _ or - (rejected otherwise, never mangled); subject ≤${CAPS.KNOWLEDGE_SUBJECT} chars (rejected if longer); fact ≤${CAPS.KNOWLEDGE_FACT} chars (truncated, not rejected) with newlines collapsed to spaces; evidence_event_ids ≤${CAPS.EVENT_IDS} items of ≤${CAPS.EVENT_ID_LEN} chars; ≤${CAPS.RECORDS_PER_PROCESS} records per sweep, shared with record_lead and note_trail.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        category: {
          type: 'string',
          description: `Your own grouping header for this kind of fact — e.g. account, app, app_endpoint, host, schedule, network. Reuse the same one across sweeps for the same kind of fact. Spaces become underscores and case is folded; anything else outside a-z, 0-9, _ or - is rejected. ≤${CAPS.KNOWLEDGE_CATEGORY} chars.`,
        },
        subject: {
          type: 'string',
          description: `The single entity or thing the fact is about — an account, host, endpoint, subnet, job name. Lowercased for stable grouping. ≤${CAPS.KNOWLEDGE_SUBJECT} chars.`,
        },
        fact: {
          type: 'string',
          description: `What you established, as ONE statement, understandable with no memory of this sweep: what is true, how you know, and over what period. Whitespace and newlines collapse to single spaces. ≤${CAPS.KNOWLEDGE_FACT} chars (longer is truncated).`,
        },
        confidence: {
          type: 'number',
          description:
            'How sure you are, 0 to 1 (0.9 = near-certain, 0.5 = plausible). Optional; the server defaults to 0.5. A value outside 0-1 is rejected, not clamped.',
        },
        evidence_event_ids: {
          type: 'array',
          items: { type: 'string' },
          description: `Canonical event ids that establish the fact, exactly as returned by search — pointers, not pasted log bodies. Record them: a fact with no resolvable evidence is hidden from any analyst whose access is scoped to particular sources. ≤${CAPS.EVENT_IDS} items.`,
        },
        ttl_days: {
          type: 'number',
          description: `How long this should stay true before it needs re-establishing. Optional; defaults to 30 and is capped at ${CAPS.KNOWLEDGE_TTL_DAYS}. Ask for less when the estate churns — a stale fact is worse than none.`,
        },
      },
      required: ['category', 'subject', 'fact'],
    },
  },
  {
    name: 'record_suppression',
    description:
      'Suppress ONE lead you have ESTABLISHED is benign, and say why. Use it only when you have done the work and can state the explanation: what the pattern is, what actually causes it, and over what period you confirmed it. If you are recording this because a lead looks noisy, repetitive or boring rather than because you understand it, do not — record_knowledge is where an unproven observation belongs, and an unsure lead stays a lead. ' +
      'WHAT IT ACTUALLY DOES: it ZEROES THE LEAD\'S SCORE. IT DOES NOT HIDE THE LEAD. An analyst still sees it on the bench, flagged as agent-suppressed, and reads your reason as the justification for why it scored zero — so write the reason for that analyst, not for yourself. A suppression you cannot justify is a suppression that gets revoked and held against every other conclusion in this sweep. ' +
      'It also EXPIRES, and it is narrow: it applies to that ONE finding. There is deliberately no way from here to suppress a hunt, a pattern or a whole entity class — an unattended sweep that could suppress broadly could blind its own successors, so it cannot. ' +
      'YOU MAY ONLY SUPPRESS A LEAD YOU YOURSELF FILED IN THIS SWEEP. Name the SAME `entity_type` and `entity_value` you passed to record_lead — that is the entire identity you need, and it is the one you already have. The server looks the entity up among this sweep\'s own leads and takes the finding\'s identity from the lead it finds; if this sweep filed no lead for that entity, nothing is suppressed. So record the lead FIRST, then suppress it — and never name an entity you did not report, because you would only be describing a finding you never saw. The value is matched without regard to case, so echo back whatever casing the log showed you. ' +
      '`reason` is required and is the whole point: an unexplained suppression is unreviewable, which defeats the visibility this is built on. "noisy" is not a reason. "the 03:00 spike on svc_backup is the nightly job, confirmed across 90 days of the same schedule and the same parent process" is. ' +
      'Each call appends one line to the sweep\'s local file, exactly like record_lead. Nothing is sent anywhere: the hunt runner submits it after the sweep and stamps which sweep this was — you do not name it. ' +
      `Caps: entity_value ≤${CAPS.ENTITY_VALUE} chars (rejected if longer, exactly as on record_lead); reason ≤${CAPS.SUPPRESSION_REASON} chars (truncated, not rejected) with newlines collapsed to spaces; ttl_days defaults to ${CAPS.SUPPRESSION_TTL_DAYS_DEFAULT} and is capped at ${CAPS.SUPPRESSION_TTL_DAYS}; ≤${CAPS.RECORDS_PER_PROCESS} records per sweep, shared with record_lead, note_trail and record_knowledge.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        entity_type: {
          type: 'string',
          enum: [...ENTITY_TYPES],
          description:
            'The entity_type of the lead you are suppressing — the SAME one you passed to record_lead for it.',
        },
        entity_value: {
          type: 'string',
          description: `The entity itself, as you gave it to record_lead — the IP, username, hostname, domain, hash, process name, URL, address or path. Matched without regard to case, so the casing you saw in the log is fine. ≤${CAPS.ENTITY_VALUE} chars.`,
        },
        reason: {
          type: 'string',
          description: `Why this is benign, written for the analyst who will read it next to the lead: what the pattern is, what causes it, and how long you confirmed it holds. Required — this is the record of your reasoning, and it is what a reviewer uses to keep or revoke the suppression. Whitespace and newlines collapse to single spaces. ≤${CAPS.SUPPRESSION_REASON} chars (longer is truncated).`,
        },
        ttl_days: {
          type: 'number',
          description: `How long the suppression should hold before the lead scores normally again. Optional; defaults to ${CAPS.SUPPRESSION_TTL_DAYS_DEFAULT} days and is capped at ${CAPS.SUPPRESSION_TTL_DAYS}. Nothing you suppress here stays suppressed indefinitely, and asking for less is right whenever the estate changes.`,
        },
      },
      required: ['entity_type', 'entity_value', 'reason'],
    },
  },
];

// ── Handlers ─────────────────────────────────────────────────────────────────

async function recordLead(args: Record<string, unknown>): Promise<ToolResult> {
  const entityType = (asString(args.entity_type) ?? '').toLowerCase();
  if (!(ENTITY_TYPES as readonly string[]).includes(entityType)) {
    return err(`\`entity_type\` must be one of: ${ENTITY_TYPES.join(', ')}.`);
  }

  const entityValue = asString(args.entity_value) ?? '';
  if (!entityValue) return err('`entity_value` is required — the entity this lead is about.');
  if (entityValue.length > CAPS.ENTITY_VALUE) {
    return err(
      `\`entity_value\` is ${entityValue.length} chars, over the ${CAPS.ENTITY_VALUE}-char cap. Record the entity itself, not a description of it.`,
    );
  }

  const warnings: string[] = [];

  let mitre: string | undefined;
  const mitreRaw = asString(args.mitre_technique) ?? '';
  if (mitreRaw) {
    if (mitreRaw.length > CAPS.MITRE_LEN || !MITRE_RE.test(mitreRaw.toUpperCase())) {
      return err(
        `\`mitre_technique\` must be a MITRE ATT&CK technique id like T1021 or T1021.001 (got "${mitreRaw.slice(0, 64)}"). Use the id, not the technique name, or omit the field.`,
      );
    }
    mitre = mitreRaw.toUpperCase();
  }

  const signals = asStringList(args.signals, 'signals', CAPS.SIGNALS, CAPS.SIGNAL_LEN);
  const events = asStringList(
    args.evidence_event_ids,
    'evidence_event_ids',
    CAPS.EVENT_IDS,
    CAPS.EVENT_ID_LEN,
  );
  warnings.push(...signals.warnings, ...events.warnings);

  let narrative = asString(args.narrative) ?? '';
  if (narrative.length > CAPS.NARRATIVE) {
    narrative = `${cut(narrative, CAPS.NARRATIVE)}… [truncated at ${CAPS.NARRATIVE} chars]`;
    warnings.push(`narrative truncated at ${CAPS.NARRATIVE} chars.`);
  }
  if (!signals.items.length && !events.items.length) {
    warnings.push(
      'No signals and no evidence_event_ids — an analyst cannot check this lead. Include the identifiers and event ids next time.',
    );
  }

  // Key order below IS the file contract; do not reorder.
  const record: Record<string, unknown> = { entity_type: entityType, entity_value: entityValue };
  if (mitre) record.mitre_technique = mitre;
  record.signals = signals.items;
  record.evidence_event_ids = events.items;
  if (narrative) record.narrative = narrative;

  return serialised(async () => {
    if (recordsWritten >= CAPS.RECORDS_PER_PROCESS) {
      return err(
        `This sweep has already recorded ${CAPS.RECORDS_PER_PROCESS} records — the cap. Stop recording and summarise what you have.`,
      );
    }
    const file = await resolveLeadsFile();
    if (isToolResult(file)) return file;

    try {
      await appendLine(file.path, JSON.stringify(record));
    } catch (e) {
      return err(`Could not write the lead: ${writeFailure(e)}`);
    }
    recordsWritten += 1;

    return ok({
      recorded: true,
      entity_type: entityType,
      entity_value: entityValue,
      records_this_sweep: recordsWritten,
      leads_file: file.path,
      ...(warnings.length ? { warnings } : {}),
    });
  });
}

async function noteTrail(args: Record<string, unknown>): Promise<ToolResult> {
  let note = asString(args.note) ?? '';
  if (!note) return err('`note` is required — one line of what the sweep is doing.');
  let truncated = false;
  if (note.length > CAPS.TRAIL_NOTE) {
    note = `${cut(note, CAPS.TRAIL_NOTE)}…`;
    truncated = true;
  }

  const record = { kind: 'trail', at: new Date().toISOString(), note };

  return serialised(async () => {
    if (recordsWritten >= CAPS.RECORDS_PER_PROCESS) {
      return err(
        `This sweep has already recorded ${CAPS.RECORDS_PER_PROCESS} records — the cap. Stop recording and summarise what you have.`,
      );
    }
    const file = await resolveLeadsFile();
    if (isToolResult(file)) return file;

    try {
      await appendLine(file.path, JSON.stringify(record));
    } catch (e) {
      return err(`Could not write the trail note: ${writeFailure(e)}`);
    }
    recordsWritten += 1;

    return ok({
      recorded: true,
      kind: 'trail',
      records_this_sweep: recordsWritten,
      ...(truncated ? { warnings: [`note truncated at ${CAPS.TRAIL_NOTE} chars.`] } : {}),
    });
  });
}

async function recordKnowledge(args: Record<string, unknown>): Promise<ToolResult> {
  // Category: fold, then accept or refuse — the same rules the server applies, run
  // here so the agent gets an explicable error NOW rather than a rejection an hour
  // later when the runner submits the batch.
  const categoryRaw = asString(args.category) ?? '';
  if (!categoryRaw) {
    return err('`category` is required — the grouping header this fact belongs under.');
  }
  // Spaces become underscores so "App Endpoint" is a usable category rather than a
  // rejection. Nothing else is rewritten.
  const category = categoryRaw.toLowerCase().split(/\s+/).filter(Boolean).join('_');
  if (category.length > CAPS.KNOWLEDGE_CATEGORY) {
    return err(
      `\`category\` is ${category.length} chars, over the ${CAPS.KNOWLEDGE_CATEGORY}-char cap. It is a grouping header like \`account\` or \`app_endpoint\`, not a description — put the description in \`fact\`.`,
    );
  }
  if (!KNOWLEDGE_CATEGORY_RE.test(category)) {
    return err(
      `\`category\` must be ${CAPS.KNOWLEDGE_CATEGORY} chars or fewer of a-z, 0-9, _ or -, starting with a letter or digit (got "${category.slice(0, 64)}"). It is rejected rather than cleaned up, because a category that is really a sentence would become a grouping header an analyst has to read. Send a short header like \`account\` and put the sentence in \`fact\`.`,
    );
  }

  const subject = (asString(args.subject) ?? '').toLowerCase();
  if (!subject) {
    return err('`subject` is required — the one entity or thing this fact is about.');
  }
  if (subject.length > CAPS.KNOWLEDGE_SUBJECT) {
    return err(
      `\`subject\` is ${subject.length} chars, over the ${CAPS.KNOWLEDGE_SUBJECT}-char cap. Name the entity, not the fact about it.`,
    );
  }

  const warnings: string[] = [];

  // Collapsed BEFORE the cap, so the cap counts the statement rather than the
  // whitespace somebody padded it with.
  let fact = collapse(asString(args.fact) ?? '');
  if (!fact) return err('`fact` is required — the single statement you established.');
  if (fact.length > CAPS.KNOWLEDGE_FACT) {
    fact = `${cut(fact, CAPS.KNOWLEDGE_FACT)}… [truncated at ${CAPS.KNOWLEDGE_FACT} chars]`;
    warnings.push(`fact truncated at ${CAPS.KNOWLEDGE_FACT} chars.`);
  }

  // Rejected rather than clamped, unlike the server, and deliberately: an agent that
  // sends 95 meant 0.95, and clamping it to 1.0 would record certainty it never
  // claimed. A confidence is a claim, so a malformed one is corrected by the agent.
  let confidence: number | undefined;
  if (args.confidence !== undefined && args.confidence !== null) {
    const value = asFiniteNumber(args.confidence);
    if (value === null || value < 0 || value > 1) {
      return err(
        '`confidence` must be a number from 0 to 1 (0.9 = near-certain, 0.5 = plausible). Out-of-range values are rejected rather than clamped, so a stray 95 does not become certainty you did not claim. Omit the field to accept the default of 0.5.',
      );
    }
    confidence = value;
  }

  // Clamped rather than rejected: a shorter lifetime asserts nothing false, and
  // decay is one of the few bounds on a fact that turns out to be wrong.
  let ttlDays: number | undefined;
  if (args.ttl_days !== undefined && args.ttl_days !== null) {
    const value = asFiniteNumber(args.ttl_days);
    if (value === null || value < 1) {
      return err(
        `\`ttl_days\` must be a whole number of days of 1 or more (capped at ${CAPS.KNOWLEDGE_TTL_DAYS}). Omit it for the default of 30 days.`,
      );
    }
    const requested = Math.round(value);
    ttlDays = Math.min(requested, CAPS.KNOWLEDGE_TTL_DAYS);
    if (ttlDays !== requested) {
      warnings.push(
        `ttl_days capped at ${CAPS.KNOWLEDGE_TTL_DAYS} days — nothing recorded here is permanent, so re-establish the fact instead.`,
      );
    }
  }

  const events = asStringList(
    args.evidence_event_ids,
    'evidence_event_ids',
    CAPS.EVENT_IDS,
    CAPS.EVENT_ID_LEN,
  );
  warnings.push(...events.warnings);
  if (!events.items.length) {
    warnings.push(
      'No evidence_event_ids — the fact will be stored with an incomplete provenance record, which hides it from analysts whose access is scoped to particular sources. Record the event ids you learned it from.',
    );
  }

  // Key order below IS the file contract; do not reorder.
  const record: Record<string, unknown> = { kind: 'knowledge', category, subject, fact };
  if (confidence !== undefined) record.confidence = confidence;
  record.evidence_event_ids = events.items;
  if (ttlDays !== undefined) record.ttl_days = ttlDays;

  return serialised(async () => {
    if (recordsWritten >= CAPS.RECORDS_PER_PROCESS) {
      return err(
        `This sweep has already recorded ${CAPS.RECORDS_PER_PROCESS} records — the cap. Stop recording and summarise what you have.`,
      );
    }
    const file = await resolveLeadsFile();
    if (isToolResult(file)) return file;

    try {
      await appendLine(file.path, JSON.stringify(record));
    } catch (e) {
      return err(`Could not write the knowledge: ${writeFailure(e)}`);
    }
    recordsWritten += 1;

    return ok({
      recorded: true,
      kind: 'knowledge',
      category,
      subject,
      records_this_sweep: recordsWritten,
      leads_file: file.path,
      ...(warnings.length ? { warnings } : {}),
    });
  });
}

async function recordSuppression(args: Record<string, unknown>): Promise<ToolResult> {
  // The SAME vocabulary and the same cap record_lead applies, reusing its constants
  // rather than restating them: this names a lead the sweep already filed, so a
  // suppression the lead's own rules would have rejected could never match anything.
  // `entity_type` is folded exactly as record_lead folds it, because the server
  // compares it EXACTLY — an unfolded "User" would resolve to no lead at all.
  const entityType = (asString(args.entity_type) ?? '').toLowerCase();
  if (!(ENTITY_TYPES as readonly string[]).includes(entityType)) {
    return err(
      `\`entity_type\` must be one of: ${ENTITY_TYPES.join(', ')} — the same one you gave record_lead for this finding.`,
    );
  }

  // NOT case-folded, unlike the type. The server matches the value
  // case-insensitively, so folding would buy nothing, and the analyst reading this
  // suppression should see the entity spelled the way the log spelled it.
  const entityValue = asString(args.entity_value) ?? '';
  if (!entityValue) {
    return err(
      '`entity_value` is required — the entity of the lead you are suppressing, exactly as you gave it to record_lead. A suppression names a finding you filed; if you did not file one, there is nothing to suppress.',
    );
  }
  if (entityValue.length > CAPS.ENTITY_VALUE) {
    return err(
      `\`entity_value\` is ${entityValue.length} chars, over the ${CAPS.ENTITY_VALUE}-char cap — the same cap record_lead applies, so no lead you could have filed exceeds it. Name the entity itself, not a description of it.`,
    );
  }

  const warnings: string[] = [];

  // Collapsed BEFORE the cap, like a fact: the reason is rendered on one row beside
  // the lead it zeroed, and the cap should count the justification rather than the
  // whitespace somebody padded it with.
  let reason = collapse(asString(args.reason) ?? '');
  if (!reason) {
    return err(
      '`reason` is required — an unexplained suppression is unreviewable, which is the whole thing this is built to avoid. State what the pattern is, what causes it, and over what period you confirmed it.',
    );
  }
  if (reason.length > CAPS.SUPPRESSION_REASON) {
    reason = `${cut(reason, CAPS.SUPPRESSION_REASON)}… [truncated at ${CAPS.SUPPRESSION_REASON} chars]`;
    warnings.push(`reason truncated at ${CAPS.SUPPRESSION_REASON} chars.`);
  }
  // Warned, not rejected: the agent may be terse about something it genuinely
  // established, and losing the suppression would not improve the reason. But a
  // one-word verdict is what a reviewer revokes, so say so while it can be fixed.
  if (reason.length < CAPS.SUPPRESSION_REASON_THIN) {
    warnings.push(
      `The reason is only ${reason.length} characters. An analyst reads it as the entire justification for a lead scoring zero — a verdict with no working shown ("noisy", "benign", "expected") is what gets a suppression revoked. Say what causes the pattern and over what period you confirmed it.`,
    );
  }

  // Clamped rather than rejected, exactly as a fact's ttl is: a shorter suppression
  // asserts nothing false, and expiry is the main thing bounding one that was wrong.
  let ttlDays: number | undefined;
  if (args.ttl_days !== undefined && args.ttl_days !== null) {
    const value = asFiniteNumber(args.ttl_days);
    if (value === null || value < 1) {
      return err(
        `\`ttl_days\` must be a whole number of days of 1 or more (capped at ${CAPS.SUPPRESSION_TTL_DAYS}). Omit it to accept the default of ${CAPS.SUPPRESSION_TTL_DAYS_DEFAULT} days.`,
      );
    }
    const requested = Math.round(value);
    ttlDays = Math.min(requested, CAPS.SUPPRESSION_TTL_DAYS);
    if (ttlDays !== requested) {
      warnings.push(
        `ttl_days capped at ${CAPS.SUPPRESSION_TTL_DAYS} days — a suppression written by an unattended sweep is deliberately short-lived, so re-establish it next time if it still holds.`,
      );
    }
  }

  // Key order below IS the file contract; do not reorder.
  const record: Record<string, unknown> = {
    kind: 'suppression',
    entity_type: entityType,
    entity_value: entityValue,
    reason,
  };
  if (ttlDays !== undefined) record.ttl_days = ttlDays;

  return serialised(async () => {
    if (recordsWritten >= CAPS.RECORDS_PER_PROCESS) {
      return err(
        `This sweep has already recorded ${CAPS.RECORDS_PER_PROCESS} records — the cap. Stop recording and summarise what you have.`,
      );
    }
    const file = await resolveLeadsFile();
    if (isToolResult(file)) return file;

    try {
      await appendLine(file.path, JSON.stringify(record));
    } catch (e) {
      return err(`Could not write the suppression: ${writeFailure(e)}`);
    }
    recordsWritten += 1;

    return ok({
      recorded: true,
      kind: 'suppression',
      entity_type: entityType,
      entity_value: entityValue,
      records_this_sweep: recordsWritten,
      leads_file: file.path,
      ...(warnings.length ? { warnings } : {}),
    });
  });
}

export async function handleHuntTool(
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  switch (name) {
    case 'record_lead':
      return recordLead(args);
    case 'note_trail':
      return noteTrail(args);
    case 'record_knowledge':
      return recordKnowledge(args);
    case 'record_suppression':
      return recordSuppression(args);
    default:
      return err(`Unknown hunt tool: ${name}`);
  }
}

/** Test-only: the per-process record counter is process state. */
export function __resetRecordCount(): void {
  recordsWritten = 0;
}

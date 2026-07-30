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
 *   leads:  {"entity_type":…,"entity_value":…,"mitre_technique":…,"signals":[…],
 *            "evidence_event_ids":[…],"narrative":…}      ← no discriminator
 *   trail:  {"kind":"trail","at":"<ISO-8601>","note":…}   ← discriminator "kind"
 * One JSON object per line, appended and flushed per call. A reader treats any line
 * without `kind` as a lead.
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
    narrative = `${narrative.slice(0, CAPS.NARRATIVE)}… [truncated at ${CAPS.NARRATIVE} chars]`;
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
    note = `${note.slice(0, CAPS.TRAIL_NOTE)}…`;
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

export async function handleHuntTool(
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  switch (name) {
    case 'record_lead':
      return recordLead(args);
    case 'note_trail':
      return noteTrail(args);
    default:
      return err(`Unknown hunt tool: ${name}`);
  }
}

/** Test-only: the per-process record counter is process state. */
export function __resetRecordCount(): void {
  recordsWritten = 0;
}

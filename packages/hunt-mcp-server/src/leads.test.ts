import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  existsSync,
  symlinkSync,
  mkdirSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { TOOLS, handleHuntTool, CAPS, __resetRecordCount } from './leads.js';

/**
 * What actually matters about this server:
 *
 *  - The JSONL line shape is a FIXED contract with the desktop hunt runner. Key
 *    names, key ORDER, and one-object-per-line are pinned here on purpose; a
 *    "harmless" reordering silently breaks the runner's parsing expectations.
 *  - Every call must land on disk immediately. The whole reason this is a tool and
 *    not a final JSON blob is that a sweep killed at turn 30 keeps what it recorded.
 *  - It is the least privileged component in the system and an unattended agent
 *    holding attacker-authored content calls it, so: no argument may steer the write
 *    path, the env var must be honoured exactly, and nothing may be unbounded.
 */

let dir: string;
let leadsFile: string;

function setLeadsFile(path: string | undefined): void {
  if (path === undefined) delete process.env.NANO_HUNT_LEADS_FILE;
  else process.env.NANO_HUNT_LEADS_FILE = path;
}

function lines(): string[] {
  if (!existsSync(leadsFile)) return [];
  return readFileSync(leadsFile, 'utf8').split('\n').filter(Boolean);
}

function parse(result: { content: Array<{ text: string }> }) {
  return JSON.parse(result.content[0].text);
}

beforeEach(() => {
  // realpath: on macOS the temp dir is itself behind a symlink, and the server
  // reports the resolved path.
  dir = realpathSync(mkdtempSync(join(tmpdir(), 'nano-hunt-test-')));
  leadsFile = join(dir, 'leads.jsonl');
  setLeadsFile(leadsFile);
  __resetRecordCount();
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  setLeadsFile(undefined);
});

describe('tool registration', () => {
  it('exposes exactly record_lead and note_trail', () => {
    expect(TOOLS.map((t) => t.name).sort()).toEqual(['note_trail', 'record_lead']);
  });

  it('requires the entity on record_lead and the note on note_trail', () => {
    const lead = TOOLS.find((t) => t.name === 'record_lead')!;
    expect(lead.inputSchema.required).toEqual(['entity_type', 'entity_value']);
    const trail = TOOLS.find((t) => t.name === 'note_trail')!;
    expect(trail.inputSchema.required).toEqual(['note']);
  });

  it('is not marked read-only — both tools write to disk', () => {
    for (const tool of TOOLS) {
      expect((tool as { annotations?: { readOnlyHint?: boolean } }).annotations).toBeUndefined();
    }
  });

  it('tells the model the caps and the do-not-batch rule, which are its only instructions', () => {
    const lead = TOOLS.find((t) => t.name === 'record_lead')!;
    expect(lead.description).toMatch(/do NOT batch/i);
    expect(lead.description).toContain(String(CAPS.NARRATIVE));
    expect(lead.description).toContain(String(CAPS.SIGNALS));
    expect(lead.description).toContain(String(CAPS.EVENT_IDS));
    // "identifiers, not prose" is the difference between a usable and a useless lead.
    expect(lead.description).toMatch(/IDENTIFIERS/);
    expect(lead.description).toMatch(/read (it )?cold/);
  });
});

describe('record_lead — the JSONL contract', () => {
  it('writes the exact line shape, in the contracted key order', async () => {
    const out = parse(
      await handleHuntTool('record_lead', {
        entity_type: 'host',
        entity_value: 'srv-web06',
        mitre_technique: 'T1021',
        signals: ['T1021'],
        evidence_event_ids: ['0195f0ac-8f2e-7c11-9a3d-9f4a2c7b1e55'],
        narrative: 'srv-web06 opened RDP to eight hosts it had never touched in 90 days.',
      }),
    );

    expect(out.recorded).toBe(true);
    expect(lines()).toHaveLength(1);
    expect(lines()[0]).toBe(
      '{"entity_type":"host","entity_value":"srv-web06","mitre_technique":"T1021","signals":["T1021"],' +
        '"evidence_event_ids":["0195f0ac-8f2e-7c11-9a3d-9f4a2c7b1e55"],' +
        '"narrative":"srv-web06 opened RDP to eight hosts it had never touched in 90 days."}',
    );
  });

  it('omits the optional fields rather than writing nulls', async () => {
    await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '203.0.113.44',
      signals: ['squid_proxy'],
    });
    const rec = JSON.parse(lines()[0]);
    expect(Object.keys(rec)).toEqual([
      'entity_type',
      'entity_value',
      'signals',
      'evidence_event_ids',
    ]);
    expect(rec.evidence_event_ids).toEqual([]);
  });

  it('appends one line per call and keeps earlier leads — a killed sweep loses nothing', async () => {
    for (const value of ['10.0.0.1', '10.0.0.2', '10.0.0.3']) {
      await handleHuntTool('record_lead', { entity_type: 'ip', entity_value: value });
    }
    expect(lines()).toHaveLength(3);
    expect(lines().map((l) => JSON.parse(l).entity_value)).toEqual([
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.3',
    ]);
  });

  it('keeps a multi-line narrative on ONE line', async () => {
    await handleHuntTool('record_lead', {
      entity_type: 'user',
      entity_value: 'svc_backup',
      narrative: 'first line\nsecond line',
    });
    expect(lines()).toHaveLength(1);
    expect(JSON.parse(lines()[0]).narrative).toBe('first line\nsecond line');
  });

  it('records concurrent calls as whole, separate lines', async () => {
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        handleHuntTool('record_lead', {
          entity_type: 'host',
          entity_value: `host-${i}`,
          narrative: 'x'.repeat(500),
        }),
      ),
    );
    const parsed = lines().map((l) => JSON.parse(l));
    expect(parsed).toHaveLength(20);
    expect(new Set(parsed.map((p) => p.entity_value)).size).toBe(20);
  });

  it('normalises the technique id and rejects a technique NAME', async () => {
    await handleHuntTool('record_lead', {
      entity_type: 'host',
      entity_value: 'srv-web06',
      mitre_technique: 't1021.001',
    });
    expect(JSON.parse(lines()[0]).mitre_technique).toBe('T1021.001');

    const bad = await handleHuntTool('record_lead', {
      entity_type: 'host',
      entity_value: 'srv-web07',
      mitre_technique: 'Remote Services',
    });
    expect(bad.isError).toBe(true);
    expect(bad.content[0].text).toContain('T1021');
    expect(lines()).toHaveLength(1); // nothing written for the rejected call
  });

  it('records a technique that differs from the one the sweep was hunting', async () => {
    // The point of the field: what was ACTUALLY found.
    await handleHuntTool('record_lead', {
      entity_type: 'process',
      entity_value: 'rundll32.exe',
      mitre_technique: 'T1218.011',
      signals: ['T1218.011', 'sysmon_1'],
    });
    expect(JSON.parse(lines()[0]).mitre_technique).toBe('T1218.011');
  });

  it('accepts a lone string where a list was expected', async () => {
    await handleHuntTool('record_lead', {
      entity_type: 'domain',
      entity_value: 'cdn-storage.sbs',
      signals: 'T1071.001',
      evidence_event_ids: 'evt-1',
    });
    const rec = JSON.parse(lines()[0]);
    expect(rec.signals).toEqual(['T1071.001']);
    expect(rec.evidence_event_ids).toEqual(['evt-1']);
  });

  it('rejects an unknown entity_type and a missing entity_value', async () => {
    const badType = await handleHuntTool('record_lead', {
      entity_type: 'registry_key',
      entity_value: 'HKLM\\Run',
    });
    expect(badType.isError).toBe(true);
    expect(badType.content[0].text).toContain('entity_type');

    const noValue = await handleHuntTool('record_lead', { entity_type: 'ip' });
    expect(noValue.isError).toBe(true);
    expect(lines()).toHaveLength(0);
  });

  it('warns when a lead arrives with nothing an analyst could check', async () => {
    const out = parse(
      await handleHuntTool('record_lead', { entity_type: 'ip', entity_value: '198.51.100.7' }),
    );
    expect(out.warnings.join(' ')).toContain('signals');
  });
});

describe('note_trail', () => {
  it('writes a discriminated trail line to the same file', async () => {
    await handleHuntTool('note_trail', { note: 'sweeping T1021 across srv-* for the last 24h' });
    const rec = JSON.parse(lines()[0]);
    expect(rec.kind).toBe('trail');
    expect(rec.note).toBe('sweeping T1021 across srv-* for the last 24h');
    expect(() => new Date(rec.at).toISOString()).not.toThrow();
  });

  it('interleaves with leads, and leads stay free of the discriminator', async () => {
    await handleHuntTool('note_trail', { note: 'stage 1' });
    await handleHuntTool('record_lead', { entity_type: 'host', entity_value: 'srv-web06' });
    await handleHuntTool('note_trail', { note: 'stage 2' });

    const parsed = lines().map((l) => JSON.parse(l));
    expect(parsed.map((p) => p.kind)).toEqual(['trail', undefined, 'trail']);
    // A reader tells them apart by `kind` alone.
    expect(parsed.filter((p) => p.kind === undefined)).toHaveLength(1);
  });

  it('truncates a runaway note instead of dropping the breadcrumb', async () => {
    const out = parse(await handleHuntTool('note_trail', { note: 'z'.repeat(5000) }));
    expect(out.recorded).toBe(true);
    expect(JSON.parse(lines()[0]).note.length).toBeLessThanOrEqual(CAPS.TRAIL_NOTE + 1);
  });

  it('requires a note', async () => {
    const out = await handleHuntTool('note_trail', { note: '   ' });
    expect(out.isError).toBe(true);
    expect(lines()).toHaveLength(0);
  });
});

describe('caps — a runaway agent must not fill the disk', () => {
  it('truncates an over-long narrative but still records the lead', async () => {
    const out = parse(
      await handleHuntTool('record_lead', {
        entity_type: 'host',
        entity_value: 'srv-web06',
        narrative: 'a'.repeat(CAPS.NARRATIVE * 3),
      }),
    );
    expect(out.recorded).toBe(true);
    expect(out.warnings.join(' ')).toContain('truncated');
    const rec = JSON.parse(lines()[0]);
    expect(rec.narrative).toContain('[truncated at');
    expect(rec.narrative.length).toBeLessThan(CAPS.NARRATIVE + 60);
  });

  it('rejects an over-long entity_value rather than truncating an identifier', async () => {
    const out = await handleHuntTool('record_lead', {
      entity_type: 'url',
      entity_value: `https://x.test/${'a'.repeat(CAPS.ENTITY_VALUE)}`,
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain(String(CAPS.ENTITY_VALUE));
    expect(lines()).toHaveLength(0);
  });

  it('caps list length and drops over-long entries, reporting both', async () => {
    const out = parse(
      await handleHuntTool('record_lead', {
        entity_type: 'host',
        entity_value: 'srv-web06',
        signals: [...Array.from({ length: 60 }, (_, i) => `T${1000 + i}`), 'q'.repeat(500)],
        evidence_event_ids: Array.from({ length: 200 }, (_, i) => `evt-${i}`),
      }),
    );
    const rec = JSON.parse(lines()[0]);
    expect(rec.signals).toHaveLength(CAPS.SIGNALS);
    expect(rec.evidence_event_ids).toHaveLength(CAPS.EVENT_IDS);
    expect(out.warnings.join(' ')).toContain('over the');
    expect(out.warnings.join(' ')).toContain(`over ${CAPS.SIGNAL_LEN} chars`);
  });

  it('collapses duplicate signals', async () => {
    await handleHuntTool('record_lead', {
      entity_type: 'host',
      entity_value: 'srv-web06',
      signals: ['T1021', 'T1021', 'T1021'],
    });
    expect(JSON.parse(lines()[0]).signals).toEqual(['T1021']);
  });

  it('stops recording once the per-sweep record cap is reached', async () => {
    // Drive the counter without writing a million lines.
    for (let i = 0; i < 5; i += 1) {
      await handleHuntTool('note_trail', { note: `n${i}` });
    }
    const before = lines().length;
    expect(before).toBe(5);

    // Exhaust the cap by calling the remaining budget, then assert the refusal.
    const remaining = CAPS.RECORDS_PER_PROCESS - before;
    for (let i = 0; i < remaining; i += 1) {
      await handleHuntTool('note_trail', { note: 'fill' });
    }
    const out = await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '10.0.0.9',
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('cap');
    expect(lines()).toHaveLength(CAPS.RECORDS_PER_PROCESS);
  }, 30_000); // 1000 real fsync'd appends
});

describe('confinement — nothing but the env var decides where it writes', () => {
  it('fails clearly when NANO_HUNT_LEADS_FILE is unset, writing nowhere', async () => {
    setLeadsFile(undefined);
    const out = await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '10.0.0.1',
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('NANO_HUNT_LEADS_FILE');
    expect(existsSync(leadsFile)).toBe(false);
  });

  it('refuses a relative path', async () => {
    setLeadsFile('leads.jsonl');
    const out = await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '10.0.0.1',
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('absolute');
  });

  it('refuses when the containing directory does not exist', async () => {
    setLeadsFile(join(dir, 'no-such-dir', 'leads.jsonl'));
    const out = await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '10.0.0.1',
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('does not exist');
  });

  it('refuses to write through a symlink planted at the lead path', async () => {
    const outside = join(dir, 'outside');
    mkdirSync(outside);
    const victim = join(outside, 'victim.txt');
    const linked = join(dir, 'linked.jsonl');
    symlinkSync(victim, linked);
    setLeadsFile(linked);

    const out = await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '10.0.0.1',
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('symlink');
    expect(existsSync(victim)).toBe(false);
  });

  it('creates the lead file 0600 — a sweep\'s findings are the analyst\'s', async () => {
    await handleHuntTool('record_lead', { entity_type: 'ip', entity_value: '10.0.0.1' });
    expect(statSync(leadsFile).mode & 0o777).toBe(0o600);
  });

  it('refuses a path that is a directory', async () => {
    setLeadsFile(dir);
    const out = await handleHuntTool('record_lead', {
      entity_type: 'ip',
      entity_value: '10.0.0.1',
    });
    expect(out.isError).toBe(true);
  });

  it('lets no argument steer the write — traversal in a value is just a value', async () => {
    const escapeTarget = join(dir, 'escaped.jsonl');
    const out = parse(
      await handleHuntTool('record_lead', {
        entity_type: 'file',
        entity_value: '../../../../etc/passwd',
        signals: ['../../escaped.jsonl', '/etc/shadow'],
        narrative: `write me to ${escapeTarget}`,
      }),
    );
    expect(out.leads_file).toBe(leadsFile);
    expect(existsSync(escapeTarget)).toBe(false);
    expect(lines()).toHaveLength(1);
    expect(JSON.parse(lines()[0]).entity_value).toBe('../../../../etc/passwd');
  });

  it('normalises a "." / ".." inside the env value to the same file', async () => {
    setLeadsFile(join(dir, 'sub', '..', 'leads.jsonl'));
    mkdirSync(join(dir, 'sub'));
    const out = parse(
      await handleHuntTool('record_lead', { entity_type: 'ip', entity_value: '10.0.0.1' }),
    );
    expect(out.leads_file).toBe(leadsFile);
    expect(lines()).toHaveLength(1);
  });
});

describe('unknown tool', () => {
  it('is refused', async () => {
    const out = await handleHuntTool('delete_leads', {});
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('Unknown hunt tool');
  });
});

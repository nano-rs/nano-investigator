import { describe, it, expect } from 'vitest';
import { OCSF_SCHEMA_CONTENT, OCSF_SCHEMA_RESOURCE } from './ocsf-schema.js';
import {
  OCSF_CLASSES,
  OCSF_DETAILED_CLASSES,
  OCSF_VERSION,
} from './ocsf-catalog.generated.js';

describe('OCSF catalog', () => {
  it('targets OCSF 1.9', () => {
    expect(OCSF_VERSION).toBe('1.9.0');
  });

  it('covers every class nano parsers emit', () => {
    // These are the class_uids nano's shipped OCSF parsers actually set. If the
    // catalog stops carrying one, the reference silently loses the class an
    // author most needs.
    const emitted = [1001, 1005, 1007, 3002, 4001, 4002, 4003, 6003, 201001, 201002];
    const known = new Set(OCSF_CLASSES.map((c) => c.uid));
    expect(emitted.filter((uid) => !known.has(uid))).toEqual([]);
  });

  it('keeps deprecated classes and names their replacement', () => {
    // OCSF 1.9 retired Account Change (3001) in favour of User Management.
    // Dropping deprecated classes would leave an author with no way to discover
    // that the class their 1.8-era parser emits is no longer current.
    const accountChange = OCSF_CLASSES.find((c) => c.uid === 3001);
    expect(accountChange?.deprecated?.since).toBe('1.9.0');
    expect(accountChange?.deprecated?.supersededBy).toContain('user_management');
    expect(OCSF_CLASSES.some((c) => c.uid === 3007)).toBe(true);
  });

  it('carries activity enums for the detailed classes', () => {
    const processActivity = OCSF_DETAILED_CLASSES.find((c) => c.uid === 1007);
    expect(processActivity?.activities).toEqual(
      expect.arrayContaining([
        { id: 1, caption: 'Launch' },
        { id: 2, caption: 'Terminate' },
      ]),
    );
  });

  it('strips the HTML that upstream descriptions carry', () => {
    for (const cls of OCSF_DETAILED_CLASSES) {
      expect(cls.description).not.toMatch(/<[^>]+>/);
    }
  });
});

describe('OCSF reference resource', () => {
  it('is addressable and describes itself as OCSF-deployment guidance', () => {
    expect(OCSF_SCHEMA_RESOURCE.uri).toBe('nanosiem://reference/ocsf');
    expect(OCSF_SCHEMA_RESOURCE.name).toContain('1.9.0');
  });

  it('teaches the two row shapes, which is the most common consumer mistake', () => {
    expect(OCSF_SCHEMA_CONTENT).toContain('row["actor.user.name"]');
    expect(OCSF_SCHEMA_CONTENT).toContain('event.actor.user.name');
  });

  it('warns that a search row is a pruned projection', () => {
    expect(OCSF_SCHEMA_CONTENT).toContain('unprojected, not empty');
  });

  it('explains the unknown-canonical-field rejection and its two causes', () => {
    expect(OCSF_SCHEMA_CONTENT).toContain('Unknown canonical OCSF field');
    expect(OCSF_SCHEMA_CONTENT).toContain('unmapped.src_ip');
  });

  it('documents the identity/time/source paths that replace UDM columns', () => {
    for (const path of ['metadata.uid', 'metadata.log_source', 'raw_data']) {
      expect(OCSF_SCHEMA_CONTENT).toContain(path);
    }
  });

  it('gives the type_uid rule parsers must satisfy', () => {
    expect(OCSF_SCHEMA_CONTENT).toContain('class_uid * 100 + activity_id');
  });

  it('renders the class catalog rather than only linking to it', () => {
    expect(OCSF_SCHEMA_CONTENT).toContain('| 1007 | Process Activity |');
    expect(OCSF_SCHEMA_CONTENT).toContain('DEPRECATED');
  });

  it("does not tell an author to emit `.udm.*` on an OCSF deployment", () => {
    expect(OCSF_SCHEMA_CONTENT).not.toContain('.udm.timestamp');
  });
});

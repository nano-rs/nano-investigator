import { describe, it, expect } from 'vitest';

import {
  TOOLS,
  handleReconTool,
  validateFingerprint,
  validateActorWeighting,
  validateDrafts,
  looksLikeCron,
  unwrapCensus,
  unwrapSurface,
} from './recon.js';
import { TOOL_PERMISSION_REQUIREMENTS, withPermissionRequirements } from '../tool-permissions.js';

/**
 * Recon's primitives are deterministic and server-owned; the fingerprint and
 * the drafts are the model's. These tests cover the seam between those two
 * halves — the places where a plausible-looking payload stores with a 200 and
 * renders as an empty card, or creates a hunt nobody can run.
 */

const fingerprint = () => ({
  summary: '~2k-person org, AWS-primary with Okta identity, Windows-majority fleet, EU+US hours.',
  planes: {
    identity: 'Okta is the only IdP reporting; MFA on ~87% of auth events.',
    compute: 'Windows-majority endpoint fleet, ~1.4k hosts reporting Sysmon.',
  },
});

/** What `hunt_build_census` answers — the envelope, as a model would hand it on. */
const censusReport = () => ({
  observed_at: '2026-07-31T00:00:00Z',
  window_hours: 168,
  census: [{ source_type: 'okta', events_per_day: 12_000 }],
  degraded: false,
  source_types: ['okta'],
  source_types_complete: true,
});

/** The pre-NAN-2243 full envelope, still accepted when a caller sends it. */
const surfaceReport = () => ({
  observed_at: '2026-07-31T00:00:00Z',
  huntable_surface: { tactics: [], covered: 4, gaps: 9, blind: 2, unmapped: 1 },
  live_source_types: ['okta'],
  degraded: false,
});

/** What `hunt_huntable_surface` answers NOW — the bounded summary. */
const surfaceSummaryReport = () => ({
  observed_at: '2026-07-31T00:00:00Z',
  detail: 'summary',
  surface_summary: {
    covered: 4,
    gaps: 9,
    blind: 615,
    unmapped: 82,
    gap_techniques: [],
    blind_missing_source_types: [{ source_type: 'linux_auditd', blind_techniques: 542 }],
    unmapped_technique_ids: [],
    regressed_to_blind: [],
    truncated: false,
    truncation_detail: null,
  },
  live_source_types: ['okta'],
  degraded: false,
});

const draft = () => ({
  title: 'Rare service-account logons from new source hosts',
  category: 'identity',
  doc: '## What\nService accounts authenticating from hosts they have never used.\n## Why here\nOkta is live and nothing watches this.\n## Judging a hit\nCheck for a matching change ticket.',
  sweep_query: 'source_type=okta auth_result=success | stats count by user, src_host | where count < 3',
  required_source_types: ['okta'],
  mitre_tactic: 'TA0008',
  mitre_technique: 'T1078.004',
  suggested_cadence: 'weekly',
});

// ---------------------------------------------------------------------------
// Fingerprint — the one shape this module asserts
// ---------------------------------------------------------------------------

describe('validateFingerprint — accepts what an agent honestly wrote', () => {
  it('passes a well-formed fingerprint', () => {
    expect(validateFingerprint(fingerprint())).toEqual([]);
  });

  it('accepts no planes at all — saying nothing beats guessing', () => {
    expect(validateFingerprint({ summary: 'Nothing but firewall logs are reaching nano.' })).toEqual([]);
  });

  it('accepts a missing summary when the agent says why', () => {
    expect(
      validateFingerprint({
        planes: {},
        model_unavailable_reason: 'Every volume probe timed out; there was nothing to characterise.',
      }),
    ).toEqual([]);
  });

  it('accepts probe notes — an unresolved ambiguity belongs on the record', () => {
    expect(
      validateFingerprint({ ...fingerprint(), probe_notes: ['could not classify source_type "vendor_x"'] }),
    ).toEqual([]);
  });
});

describe('validateFingerprint — catches what the server would 400 or the page would drop', () => {
  it('rejects planes given as a LIST — the server takes a map', () => {
    // The single easiest thing to get wrong here: `ProfileFingerprint.planes`
    // is `BTreeMap<String, String>`, so a list of {label, value} is a 400.
    const errors = validateFingerprint({
      summary: 'ok',
      planes: [{ label: 'identity', value: 'Okta' }],
    });
    expect(errors.join(' ')).toContain('is a MAP of plane name to sentence, not a list');
  });

  it('rejects a plane whose sentence is empty', () => {
    const errors = validateFingerprint({ summary: 'ok', planes: { identity: '' } });
    expect(errors.join(' ')).toContain('planes["identity"]');
  });

  it('rejects a fingerprint with neither a summary nor a reason for its absence', () => {
    const fp = fingerprint() as Record<string, unknown>;
    delete fp.summary;
    expect(validateFingerprint(fp).join(' ')).toContain('model_unavailable_reason');
  });

  it('rejects a summary past the stored-sentence ceiling', () => {
    const errors = validateFingerprint({ summary: 'x'.repeat(2001) });
    expect(errors.join(' ')).toContain('2000-byte ceiling');
  });

  it('rejects more planes than the server keeps', () => {
    const planes = Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`plane${i}`, 'a sentence']));
    expect(validateFingerprint({ summary: 'ok', planes }).join(' ')).toContain('caps it at 24');
  });

  it('rejects provenance smuggled onto the fingerprint', () => {
    const errors = validateFingerprint({ ...fingerprint(), source_types: ['okta'] });
    expect(errors.join(' ')).toContain('server stamps provenance');
  });

  it('rejects a non-object fingerprint outright', () => {
    expect(validateFingerprint('an org that uses AWS').length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Envelope unwrapping — the seam that has broken this feature before
// ---------------------------------------------------------------------------

describe('unwrapCensus', () => {
  it('takes the rows out of a CensusReport envelope', () => {
    const report = { observed_at: 'now', window_hours: 168, census: [{ source_type: 'okta' }], degraded: false };
    expect(unwrapCensus(report).rows).toEqual([{ source_type: 'okta' }]);
  });

  it('accepts a bare row array unchanged', () => {
    expect(unwrapCensus([{ source_type: 'okta' }]).rows).toEqual([{ source_type: 'okta' }]);
  });

  it('refuses anything that is neither', () => {
    expect(unwrapCensus({ rows: [] }).error).toBeDefined();
  });
});

describe('unwrapSurface', () => {
  it('takes the surface out of a SurfaceReport envelope', () => {
    const report = { observed_at: 'now', huntable_surface: { tactics: [], gaps: 2 }, live_source_types: ['okta'] };
    expect(unwrapSurface(report).surface).toEqual({ tactics: [], gaps: 2 });
  });

  it('accepts a bare surface unchanged', () => {
    expect(unwrapSurface({ tactics: [], gaps: 2 }).surface).toEqual({ tactics: [], gaps: 2 });
  });

  it('refuses anything that is neither', () => {
    expect(unwrapSurface({ covered: 1 }).error).toBeDefined();
  });

  // NAN-2243. The summary has no `tactics`, so storing it would leave the
  // Profile page empty and the rail badge counting nothing. The generic "got
  // neither" would send a model looking for a reshaping it must not perform, so
  // this case names itself and says what to do instead.
  it('names the bounded summary rather than asking a model to reshape it', () => {
    const error = unwrapSurface(surfaceSummaryReport()).error ?? '';
    expect(error).toContain('SUMMARY');
    expect(error).toContain('Omit `huntable_surface`');
  });
});

// ---------------------------------------------------------------------------
// Actor weighting
// ---------------------------------------------------------------------------

describe('validateActorWeighting', () => {
  const actor = () => ({ name: 'FIN7', rationale: 'Finance-adjacent SaaS estate matches their targeting.', fit: 0.7 });

  it('accepts omission — an unevidenced actor list is worse than none', () => {
    expect(validateActorWeighting(undefined)).toEqual([]);
  });

  it('accepts a well-formed weighting', () => {
    expect(validateActorWeighting([actor()])).toEqual([]);
  });

  it('rejects a non-array', () => {
    expect(validateActorWeighting({ name: 'FIN7' }).join(' ')).toContain('must be an array');
  });

  it('rejects a non-finite fit — it is a 500 on an otherwise valid save', () => {
    expect(validateActorWeighting([{ ...actor(), fit: Number.POSITIVE_INFINITY }]).join(' ')).toContain('finite number');
  });

  it('rejects a fit outside 0..1', () => {
    expect(validateActorWeighting([{ ...actor(), fit: 7 }]).join(' ')).toContain('between 0 and 1');
  });

  it('rejects an actor with no rationale', () => {
    expect(validateActorWeighting([{ ...actor(), rationale: '' }]).join(' ')).toContain('why this actor fits');
  });
});

// ---------------------------------------------------------------------------
// Drafts — nothing generated ever schedules itself
// ---------------------------------------------------------------------------

describe('validateDrafts — accepts a hunt a human can pick up', () => {
  it('passes a well-formed draft', () => {
    expect(validateDrafts([draft()])).toEqual([]);
  });
});

describe('validateDrafts — refuses to let a proposal schedule itself', () => {
  it('rejects an explicit cron field', () => {
    const errors = validateDrafts([{ ...draft(), schedule_cron: '0 6 * * 1' }]);
    expect(errors.join(' ')).toContain('lands DISABLED with no cron');
  });

  it('rejects an attempt to enable the hunt', () => {
    const errors = validateDrafts([{ ...draft(), enabled: true }]);
    expect(errors.join(' ')).toContain('lands DISABLED with no cron');
  });

  it('rejects a cron expression smuggled into the prose cadence field', () => {
    const errors = validateDrafts([{ ...draft(), suggested_cadence: '0 6 * * 1' }]);
    expect(errors.join(' ')).toContain('reads as a cron expression');
  });

  it('still accepts prose that merely contains a number', () => {
    expect(validateDrafts([{ ...draft(), suggested_cadence: 'twice weekly, 2 sweeps' }])).toEqual([]);
  });
});

describe('validateDrafts — refuses hunts the estate cannot run', () => {
  it('rejects a draft with no required source types', () => {
    const errors = validateDrafts([{ ...draft(), required_source_types: [] }]);
    expect(errors.join(' ')).toContain('blind spot, not a hunt gap');
  });

  it('rejects a category the database CHECK constraint would reject', () => {
    const errors = validateDrafts([{ ...draft(), category: 'lateral_movement' }]);
    expect(errors.join(' ')).toContain('is not one of');
  });

  it('rejects a draft with no MITRE technique to tie it to a gap', () => {
    const bad = draft() as Record<string, unknown>;
    delete bad.mitre_technique;
    expect(validateDrafts([bad]).join(' ')).toContain('mitre_technique is required');
  });

  it('rejects a draft with no doc — nobody can judge or edit it', () => {
    expect(validateDrafts([{ ...draft(), doc: '' }]).join(' ')).toContain('.doc must be');
  });

  it('flags the same hunt proposed twice in one call', () => {
    expect(validateDrafts([draft(), draft()]).join(' ')).toContain('proposed twice');
  });

  it('rejects more drafts than the server caps a run at', () => {
    const many = Array.from({ length: 26 }, (_, i) => ({ ...draft(), title: `Hunt ${i}` }));
    expect(validateDrafts(many).join(' ')).toContain('caps a request at 25');
  });

  it('rejects an empty proposal list rather than making an empty call', () => {
    expect(validateDrafts([]).join(' ')).toContain('Propose nothing');
  });
});

describe('looksLikeCron', () => {
  it.each(['0 6 * * 1', '*/15 * * * *', '0 0 1 * * *'])('treats %s as a cron expression', (value) => {
    expect(looksLikeCron(value)).toBe(true);
  });

  it.each(['weekly', 'daily during business hours', 'every 6 hours', 'twice weekly, 2 sweeps'])(
    'treats %s as prose',
    (value) => {
      expect(looksLikeCron(value)).toBe(false);
    },
  );
});

// ---------------------------------------------------------------------------
// Handler — what never leaves this process
// ---------------------------------------------------------------------------

/** A client that records the last call and answers success. */
function stubClient() {
  const calls: Array<{ method: string; body: unknown }> = [];
  return {
    calls,
    client: {
      buildHuntCensus: async () => {
        calls.push({ method: 'census', body: undefined });
        return { success: true, data: { census: [{ source_type: 'okta' }], degraded: false } };
      },
      huntHuntableSurface: async (detail?: unknown) => {
        calls.push({ method: 'surface', body: detail });
        return { success: true, data: surfaceSummaryReport() };
      },
      saveHuntProfile: async (body: unknown) => {
        calls.push({ method: 'profile', body });
        return { success: true, data: { id: 'hunt_profile_123' } };
      },
      proposeHuntDrafts: async (body: unknown) => {
        calls.push({ method: 'drafts', body });
        return { success: true, data: { created: 1, skipped: 0 } };
      },
    },
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const asClient = (c: unknown) => c as any;

describe('handleReconTool — huntable_surface', () => {
  // NAN-2243. The bounded shape is the server's default too, so this asserts
  // INTENT: the call states what it wants, and stays bounded if that default
  // ever moves.
  it('asks for the bounded summary explicitly', async () => {
    const { calls, client } = stubClient();
    const result = await handleReconTool('hunt_huntable_surface', {}, asClient(client));

    expect(result.isError).toBeFalsy();
    expect(calls).toEqual([{ method: 'surface', body: 'summary' }]);
  });

  it('tells the model why blind techniques are aggregated and where the leverage is', () => {
    const surface = TOOLS.find((t) => t.name === 'hunt_huntable_surface');
    const description = surface?.description ?? '';
    // The claim that buys the size reduction, stated rather than assumed.
    expect(description).toContain('not huntable by definition');
    // And the thing that replaces the rows it drops.
    expect(description).toContain('WHERE THE LEVERAGE IS');
    expect(description).toContain('blind_missing_source_types');
    // A model must not hand this back to the save.
    expect(description).toContain('DO NOT pass this result to `hunt_save_profile`');
  });
});

describe('handleReconTool — save_profile', () => {
  it('unwraps the report envelopes the primitives return', async () => {
    // `POST /api/hunts/profile` wants `census: Vec<CensusRow>` and the bare
    // surface object — handing it the envelopes is a 400, and handing it the
    // envelopes is exactly what a model does.
    const { calls, client } = stubClient();

    await handleReconTool(
      'hunt_save_profile',
      { census: censusReport(), fingerprint: fingerprint(), huntable_surface: surfaceReport() },
      asClient(client),
    );

    const body = calls[0].body as Record<string, unknown>;
    expect(body.census).toEqual(censusReport().census);
    expect(body.huntable_surface).toEqual(surfaceReport().huntable_surface);
  });

  it('accepts the already-unwrapped forms too', async () => {
    const { calls, client } = stubClient();

    await handleReconTool(
      'hunt_save_profile',
      {
        census: censusReport().census,
        fingerprint: fingerprint(),
        huntable_surface: surfaceReport().huntable_surface,
      },
      asClient(client),
    );

    const body = calls[0].body as Record<string, unknown>;
    expect(body.census).toEqual(censusReport().census);
    expect(body.huntable_surface).toEqual(surfaceReport().huntable_surface);
  });

  it('rebuilds the fingerprint field by field rather than forwarding it', async () => {
    const { calls, client } = stubClient();

    await handleReconTool(
      'hunt_save_profile',
      {
        census: censusReport(),
        huntable_surface: surfaceReport(),
        fingerprint: { ...fingerprint(), invented_field: 'should not survive' },
      },
      asClient(client),
    );

    const sent = (calls[0].body as { fingerprint: Record<string, unknown> }).fingerprint;
    expect(sent).not.toHaveProperty('invented_field');
    expect(sent.planes).toEqual(fingerprint().planes);
  });

  it('refuses provenance the model invents rather than silently dropping it', async () => {
    const { calls, client } = stubClient();

    const result = await handleReconTool(
      'hunt_save_profile',
      {
        census: censusReport(),
        fingerprint: fingerprint(),
        huntable_surface: surfaceReport(),
        // `source_types` is an AUTHORIZATION input — every source-scoped reader
        // of this profile is judged against it — so a caller-supplied manifest
        // would let the caller choose its own audience. Dropping it quietly
        // would leave the model believing it had been honoured.
        source_types: ['okta', 'windows', 'aws_cloudtrail'],
        source_types_complete: true,
      },
      asClient(client),
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('server stamps provenance');
    expect(calls).toHaveLength(0);
  });

  it('refuses an actor_weighting that is not an array — it would break the render', async () => {
    const { calls, client } = stubClient();
    const result = await handleReconTool(
      'hunt_save_profile',
      {
        census: censusReport(),
        fingerprint: fingerprint(),
        huntable_surface: surfaceReport(),
        actor_weighting: { name: 'FIN7' },
      },
      asClient(client),
    );
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it('refuses a degraded profile with no stated reason', async () => {
    const { calls, client } = stubClient();
    const result = await handleReconTool(
      'hunt_save_profile',
      { census: censusReport(), fingerprint: fingerprint(), huntable_surface: surfaceReport(), degraded: true },
      asClient(client),
    );
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });

  // NAN-2243 — the reason recon was unusable from an agent. Requiring the two
  // deterministic halves made the agent hold 371 KB of server-computed
  // structure purely to hand it back. Sending only the fingerprint must work,
  // and must send NEITHER key rather than sending an empty one: an explicit
  // `census: []` would store a profile claiming the estate ingests nothing.
  it('saves a fingerprint alone, carrying neither deterministic half', async () => {
    const { calls, client } = stubClient();
    const result = await handleReconTool(
      'hunt_save_profile',
      { fingerprint: fingerprint() },
      asClient(client),
    );

    expect(result.isError).toBeFalsy();
    expect(calls).toHaveLength(1);
    const body = calls[0].body as Record<string, unknown>;
    expect(body.census).toBeUndefined();
    expect(body.huntable_surface).toBeUndefined();
    expect((body.fingerprint as Record<string, unknown>).summary).toBe(fingerprint().summary);
  });

  it('does not ask the model for the deterministic halves', () => {
    const save = TOOLS.find((t) => t.name === 'hunt_save_profile');
    expect(save?.inputSchema.required).toEqual(['fingerprint']);
    expect(Object.keys(save?.inputSchema.properties ?? {})).not.toContain('census');
    expect(Object.keys(save?.inputSchema.properties ?? {})).not.toContain('huntable_surface');
    // And it says so, so a model reading the description alone does not go
    // looking for the fields it used to be told to copy.
    expect(save?.description).toContain('Do NOT send the census or the huntable surface back');
  });

  it('does not send a fingerprint that would render blank', async () => {
    const { calls, client } = stubClient();
    const result = await handleReconTool(
      'hunt_save_profile',
      { census: censusReport(), huntable_surface: surfaceReport(), fingerprint: { planes: [] } },
      asClient(client),
    );
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });
});

describe('handleReconTool — propose_drafts', () => {
  it('sends only contract fields, never a schedule', async () => {
    const { calls, client } = stubClient();
    await handleReconTool('hunt_propose_drafts', { drafts: [draft()] }, asClient(client));

    const sent = (calls[0].body as { drafts: Record<string, unknown>[] }).drafts[0];
    expect(sent).not.toHaveProperty('schedule_cron');
    expect(sent).not.toHaveProperty('enabled');
    expect(sent.suggested_cadence).toBe('weekly');
    expect(sent.mitre_technique).toBe('T1078.004');
  });

  it('makes no call at all when a proposal is invalid', async () => {
    const { calls, client } = stubClient();
    const result = await handleReconTool(
      'hunt_propose_drafts',
      { drafts: [{ ...draft(), required_source_types: [] }] },
      asClient(client),
    );
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });
});

describe('handleReconTool — errors an agent can act on', () => {
  it('explains a 404 as "this nano has no recon", not as a bad tool name', async () => {
    const client = {
      buildHuntCensus: async () => ({
        success: false,
        error: { code: 'HTTP_404', message: 'Not Found' },
      }),
    };
    const result = await handleReconTool('hunt_build_census', {}, asClient(client));
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('does not expose the recon endpoints');
  });

  it('explains a 405 the same way — POST /api/hunts/profile hits the GET-only route on a build without recon', async () => {
    const client = {
      saveHuntProfile: async () => ({
        success: false,
        error: { code: 'HTTP_405', message: 'Method Not Allowed' },
      }),
    };
    const result = await handleReconTool(
      'hunt_save_profile',
      { census: censusReport(), huntable_surface: surfaceReport(), fingerprint: fingerprint() },
      asClient(client),
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('does not expose the recon endpoints');
  });

  it('names the permission behind a 403', async () => {
    const client = {
      huntHuntableSurface: async () => ({
        success: false,
        error: { code: 'HTTP_403', message: 'Forbidden' },
      }),
    };
    const result = await handleReconTool('hunt_huntable_surface', {}, asClient(client));
    // The NARROW scope must be named first: an agent relaying this to an
    // operator should be asking for `hunts:profile_write`, not for authority
    // over the whole hunt library.
    expect(result.content[0].text).toContain('hunts:profile_write');
    expect(result.content[0].text).toContain('hunts:manage');
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe('recon tool registration', () => {
  it('exposes exactly the four recon primitives', () => {
    expect(TOOLS.map((t) => t.name).sort()).toEqual([
      'hunt_build_census',
      'hunt_huntable_surface',
      'hunt_propose_drafts',
      'hunt_save_profile',
    ]);
  });

  it('declares a permission contract for every tool', () => {
    // `withPermissionRequirements` throws on a missing entry, so this is the
    // guard that a new tool cannot ship without declaring what it needs.
    expect(() => withPermissionRequirements(TOOLS)).not.toThrow();
    for (const tool of TOOLS) {
      const { alternatives } = TOOL_PERMISSION_REQUIREMENTS[tool.name];
      // Two paths, narrow FIRST. A client renders the head of this list as
      // "what this tool needs", so ordering is contract, not cosmetics — and
      // `hunts:manage` at the head would send an operator to ask for authority
      // over the entire hunt library to run one survey.
      expect(alternatives.map((a) => a.allOf)).toEqual([
        ['hunts:profile_write'],
        ['hunts:manage'],
      ]);
      // Never collapsed into one path: that would claim a call needs BOTH.
      expect(alternatives.every((a) => a.allOf.length === 1)).toBe(true);
    }
  });

  it('marks the two read-only primitives as read-only, and the two writes not', () => {
    const byName = Object.fromEntries(TOOLS.map((t) => [t.name, t]));
    expect(byName.hunt_build_census.annotations?.readOnlyHint).toBe(true);
    expect(byName.hunt_huntable_surface.annotations?.readOnlyHint).toBe(true);
    expect(byName.hunt_save_profile.annotations).toBeUndefined();
    expect(byName.hunt_propose_drafts.annotations).toBeUndefined();
  });

  it('tells the model the order of operations on every tool, not just the first', () => {
    // A model reads one description at a time and may reach any of these first.
    for (const tool of TOOLS) {
      expect(tool.description).toContain('hunt_build_census');
      expect(tool.description).toContain('hunt_save_profile');
    }
  });

  it('says plainly on the drafts tool that nothing schedules itself', () => {
    const drafts = TOOLS.find((t) => t.name === 'hunt_propose_drafts')!;
    expect(drafts.description).toContain('NOTHING YOU PROPOSE HERE WILL EVER SCHEDULE ITSELF');
  });

  it('tells the model not to supply provenance on save', () => {
    const save = TOOLS.find((t) => t.name === 'hunt_save_profile')!;
    expect(save.description).toContain('THERE IS NO PROVENANCE FIELD');
    expect(save.inputSchema.properties).not.toHaveProperty('source_types');
  });
});

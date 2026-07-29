import { describe, it, expect, vi } from 'vitest';
import type { NanosiemClient } from '@nano-rs/investigator-core';

import { handleCasesTool, TOOLS } from './cases.js';

/**
 * `merge_notebook_into_case` is what an analyst gets when they say "merge these
 * notes into case X". Two things make it worth pinning down:
 *
 *  - The case-side merge endpoint 404s BOTH for an invisible case and for a case
 *    that simply has no notebook yet. Only the second is recoverable (by linking
 *    the source in place), so the tool asks for the case notebook first instead
 *    of pattern-matching an error string.
 *  - The merge archives the source as `merged` but nothing enforces the archive —
 *    it still accepts writes. A client that keeps recording into the old id
 *    silently drops entries on the floor, so `active_notebook_id` has to name the
 *    notebook the investigation continues in, on BOTH paths.
 */

function makeMockClient(overrides: Partial<NanosiemClient> = {}): NanosiemClient {
  return overrides as unknown as NanosiemClient;
}

const CASE = 'case_3janytjhng9j29wtp7gzbz5776';
const SESSION_NB = 'nb_01j9sessionnotebook00000000';
const CASE_NB = 'nb_01j9casenotebook0000000000';

function parse(result: { content: Array<{ text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe('merge_notebook_into_case registration', () => {
  it('is registered and requires both ids', () => {
    const tool = TOOLS.find((t) => t.name === 'merge_notebook_into_case');
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toEqual(['case_id', 'source_notebook_id']);
  });

  it('is not marked read-only — it mutates both notebooks', () => {
    const tool = TOOLS.find((t) => t.name === 'merge_notebook_into_case')!;
    expect(
      (tool as { annotations?: { readOnlyHint?: boolean } }).annotations?.readOnlyHint,
    ).toBeUndefined();
  });

  it('steers "merge my notes" away from the case wall', () => {
    const wall = TOOLS.find((t) => t.name === 'add_case_wall_entry')!;
    expect(wall.description).toContain('merge_notebook_into_case');
  });
});

describe('merge_notebook_into_case', () => {
  it('merges into the existing case notebook and reports it as the active one', async () => {
    const mergeNotebookIntoCase = vi.fn().mockResolvedValue({
      success: true,
      data: { message: 'Notebook merged successfully', entries_merged: 12 },
    });
    const linkNotebookToCase = vi.fn();
    const client = makeMockClient({
      getCaseNotebook: vi.fn().mockResolvedValue({ success: true, data: { id: CASE_NB } }),
      mergeNotebookIntoCase,
      linkNotebookToCase,
    });

    const out = parse(
      await handleCasesTool(
        'merge_notebook_into_case',
        { case_id: CASE, source_notebook_id: SESSION_NB },
        client,
      ),
    );

    expect(mergeNotebookIntoCase).toHaveBeenCalledWith(CASE, {
      source_notebook_id: SESSION_NB,
    });
    expect(linkNotebookToCase).not.toHaveBeenCalled();
    expect(out.action).toBe('merged');
    expect(out.entries_merged).toBe(12);
    // The case notebook, NOT the archived source.
    expect(out.active_notebook_id).toBe(CASE_NB);
  });

  it('links the source in place when the case has no notebook yet', async () => {
    const mergeNotebookIntoCase = vi.fn();
    const client = makeMockClient({
      // 200 with a null body: the case is visible, it just has no notebook.
      getCaseNotebook: vi.fn().mockResolvedValue({ success: true, data: null }),
      mergeNotebookIntoCase,
      linkNotebookToCase: vi.fn().mockResolvedValue({ success: true, data: undefined }),
    });

    const out = parse(
      await handleCasesTool(
        'merge_notebook_into_case',
        { case_id: CASE, source_notebook_id: SESSION_NB },
        client,
      ),
    );

    expect(mergeNotebookIntoCase).not.toHaveBeenCalled();
    expect(out.action).toBe('linked');
    // Linking preserves the source in place, so it stays the live notebook.
    expect(out.active_notebook_id).toBe(SESSION_NB);
    // Nothing was copied — a `0` here reads as "merged nothing" on a success.
    expect(out).not.toHaveProperty('entries_merged');
    // Linking flips the notebook to case visibility; the analyst has to be told.
    expect(out.message).toMatch(/no longer private/i);
  });

  it('does not attempt a merge when the case is not visible', async () => {
    const mergeNotebookIntoCase = vi.fn();
    const linkNotebookToCase = vi.fn();
    const client = makeMockClient({
      getCaseNotebook: vi.fn().mockResolvedValue({
        success: false,
        error: { code: 'HTTP_404', message: 'Case not found' },
      }),
      mergeNotebookIntoCase,
      linkNotebookToCase,
    });

    const result = await handleCasesTool(
      'merge_notebook_into_case',
      { case_id: CASE, source_notebook_id: SESSION_NB },
      client,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Case not found');
    expect(mergeNotebookIntoCase).not.toHaveBeenCalled();
    expect(linkNotebookToCase).not.toHaveBeenCalled();
  });

  it('surfaces a merge failure instead of reporting success', async () => {
    const client = makeMockClient({
      getCaseNotebook: vi.fn().mockResolvedValue({ success: true, data: { id: CASE_NB } }),
      mergeNotebookIntoCase: vi.fn().mockResolvedValue({
        success: false,
        error: { code: 'HTTP_403', message: 'Missing permission: notebooks:edit' },
      }),
    });

    const result = await handleCasesTool(
      'merge_notebook_into_case',
      { case_id: CASE, source_notebook_id: SESSION_NB },
      client,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('notebooks:edit');
  });

  it('rejects a missing source_notebook_id before calling the API', async () => {
    const getCaseNotebook = vi.fn();
    const client = makeMockClient({ getCaseNotebook });

    const result = await handleCasesTool('merge_notebook_into_case', { case_id: CASE }, client);

    expect(result.isError).toBe(true);
    expect(getCaseNotebook).not.toHaveBeenCalled();
  });
});

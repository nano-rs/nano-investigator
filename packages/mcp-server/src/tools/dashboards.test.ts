import { describe, it, expect } from 'vitest';

import { validateDashboard } from './dashboards.js';

/**
 * The validator is the only thing standing between an agent's guess and a
 * dashboard that saves with a 200 and renders as a grid of broken boxes — the
 * server stores `panels`/`layout` as opaque JSON and checks nothing.
 */

const valid = () => ({
  name: 'Firewall',
  visibility: 'private',
  layout: {
    columns: 12,
    rowHeight: 80,
    autoRun: true,
    variables: [{ name: 'host', label: 'Host', type: 'text', defaultValue: '' }],
    items: [
      { i: 'total', x: 0, y: 0, w: 3, h: 2 },
      { i: 'by-port', x: 3, y: 0, w: 6, h: 3 },
    ],
  },
  panels: [
    {
      id: 'total',
      title: 'Denied events',
      query: 'source_type="firewall" host=$host | stats count',
      queryMode: 'piped',
      visualizationType: 'single_value',
      visualizationConfig: {},
      timeRangeMode: 'dashboard',
      drilldownEnabled: true,
    },
    {
      id: 'by-port',
      title: 'By port',
      query: 'source_type="firewall" | stats count by dest_port',
      queryMode: 'piped',
      visualizationType: 'bar',
      visualizationConfig: {},
      timeRangeMode: 'dashboard',
      drilldownEnabled: true,
    },
  ],
});

describe('validateDashboard — accepts a good dashboard', () => {
  it('passes the worked example with no errors', () => {
    const result = validateDashboard(valid());
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });
});

describe('validateDashboard — catches what actually breaks a dashboard', () => {
  it('rejects a visualization the backend blocks', () => {
    const board = valid();
    board.panels[0].visualizationType = 'tree';
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors[0].message).toContain('not an authorable visualization');
  });

  it('rejects a query containing a command the endpoint 400s on', () => {
    const board = valid();
    // `| tree` is rejected outright — the panel would fail on every refresh.
    board.panels[1].query = 'source_type="firewall" | tree src_ip dest_ip';
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('HTTP 400'))).toBe(true);
  });

  it('rejects a layout item that matches no panel', () => {
    const board = valid();
    board.layout.items[1].i = 'does-not-exist';
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('matches no panel id'))).toBe(true);
  });

  it('rejects a panel with no layout item — it would never be rendered', () => {
    const board = valid();
    board.layout.items = [board.layout.items[0]];
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('no layout item'))).toBe(true);
  });

  it('rejects overlapping panels', () => {
    const board = valid();
    board.layout.items[1] = { i: 'by-port', x: 1, y: 0, w: 6, h: 3 }; // overlaps `total`
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('overlap'))).toBe(true);
  });

  it('rejects a panel that runs off the 12-column grid', () => {
    const board = valid();
    board.layout.items[1] = { i: 'by-port', x: 8, y: 0, w: 6, h: 3 }; // 8 + 6 = 14
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('runs off the grid'))).toBe(true);
  });

  it('rejects a panel below the minimum size', () => {
    const board = valid();
    board.layout.items[0] = { i: 'total', x: 0, y: 0, w: 1, h: 1 };
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('minimum is 2x2'))).toBe(true);
  });

  it('rejects duplicate panel ids', () => {
    const board = valid();
    board.panels[1].id = 'total';
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('Duplicate panel id'))).toBe(true);
  });
});

describe('validateDashboard — warns about what merely disappoints', () => {
  it('warns when a SQL panel has no time filter, so it scans all retention', () => {
    const board = valid();
    board.panels[1].queryMode = 'sql';
    board.panels[1].query = 'SELECT count() FROM logs';
    const result = validateDashboard(board);
    // Not an error — it runs. It just runs over everything.
    expect(result.valid).toBe(true);
    expect(result.warnings.some((w) => w.message.includes('scans ALL retention'))).toBe(true);
  });

  it('accepts a SQL panel that uses the time macro', () => {
    const board = valid();
    board.panels[1].queryMode = 'sql';
    board.panels[1].query = 'SELECT count() FROM logs WHERE $__timeFilter(timestamp)';
    const result = validateDashboard(board);
    expect(result.warnings.some((w) => w.message.includes('scans ALL retention'))).toBe(false);
  });

  it('warns about a $variable nothing declares — the panel would quietly return nothing', () => {
    const board = valid();
    board.panels[1].query = 'source_type="firewall" user=$who | stats count by dest_port';
    const result = validateDashboard(board);
    expect(result.valid).toBe(true);
    expect(result.warnings.some((w) => w.message.includes('$who is not declared'))).toBe(true);
  });

  it('does not mistake a SQL time macro for an undeclared variable', () => {
    const board = valid();
    board.panels[1].queryMode = 'sql';
    board.panels[1].query = 'SELECT count() FROM logs WHERE $__timeFilter(timestamp)';
    const result = validateDashboard(board);
    expect(result.warnings.some((w) => w.message.includes('__timeFilter is not declared'))).toBe(
      false
    );
  });

  it('warns when autoRun is off, because the dashboard opens empty', () => {
    const board = valid();
    board.layout.autoRun = false;
    const result = validateDashboard(board);
    expect(result.warnings.some((w) => w.message.includes('open empty'))).toBe(true);
  });

  it('warns when a chart panel has no aggregate', () => {
    const board = valid();
    board.panels[1].query = 'source_type="firewall"';
    const result = validateDashboard(board);
    expect(result.warnings.some((w) => w.message.includes('wants an aggregate'))).toBe(true);
  });
});

describe('validateDashboard — does not reject queries the backend runs fine', () => {
  // The backend applies its command blocklist to the PARSED query, so a `|` that
  // is data — inside a regex or a quoted string — is not a pipe. A naive text scan
  // rejected these, and because create_dashboard refuses on any error, the agent
  // could not save a perfectly good dashboard.
  it('allows a regex alternation containing a blocked command name', () => {
    const board = valid();
    board.panels[1].query = 'process_name=/(chrome|ai)/ | stats count by process_name';
    const result = validateDashboard(board);
    expect(result.errors).toEqual([]);
  });

  it('allows a quoted string containing a blocked command name', () => {
    const board = valid();
    board.panels[1].query = 'message="failed|tree" | stats count by host';
    const result = validateDashboard(board);
    expect(result.errors).toEqual([]);
  });

  it('does not apply the piped blocklist to SQL, where the backend never applies it', () => {
    const board = valid();
    board.panels[1].queryMode = 'sql';
    board.panels[1].query =
      "SELECT count() FROM logs WHERE $__timeFilter(timestamp) AND match(msg, 'a|asset')";
    const result = validateDashboard(board);
    expect(result.errors).toEqual([]);
  });

  it('still catches a genuine forbidden command', () => {
    const board = valid();
    board.panels[1].query = 'source_type="firewall" | tree src_ip dest_ip';
    expect(validateDashboard(board).valid).toBe(false);
  });

  it('does not treat a field named after a command as a command', () => {
    const board = valid();
    board.panels[1].query = 'tree_depth>3 | stats count by cloud_account';
    expect(validateDashboard(board).errors).toEqual([]);
  });
});

describe('validateDashboard — editing a dashboard it did not author', () => {
  // Real dashboards contain viz types an agent must not AUTHOR but must be able to
  // LEAVE ALONE. Holding pre-existing panels to the authoring whitelist made every
  // such dashboard permanently un-editable.
  it('tolerates a pre-existing tree/obs_metric panel when editing', () => {
    const board = valid();
    board.panels.push({
      id: 'legacy',
      title: 'Metric widget',
      query: '', // obs_metric panels carry an empty query BY DESIGN
      queryMode: 'piped',
      visualizationType: 'obs_metric',
      visualizationConfig: {},
      timeRangeMode: 'dashboard',
      drilldownEnabled: false,
    } as never);
    board.layout.items.push({ i: 'legacy', x: 0, y: 4, w: 6, h: 3 } as never);

    const editing = validateDashboard(board, { existingPanelIds: new Set(['legacy']) });
    expect(editing.errors).toEqual([]);

    // But authoring one fresh is still refused.
    const authoring = validateDashboard(board);
    expect(authoring.valid).toBe(false);
  });
});

describe('validateDashboard — the limits the server actually enforces', () => {
  it('catches a name past the server limit before the round trip', () => {
    const board = valid();
    board.name = 'x'.repeat(201);
    expect(validateDashboard(board).valid).toBe(false);
  });

  it('catches more panels than the server accepts', () => {
    const board = valid();
    board.panels = Array.from({ length: 51 }, (_, index) => ({
      ...valid().panels[0],
      id: `p${index}`,
    }));
    board.layout.items = board.panels.map((panel, index) => ({
      i: panel.id,
      x: 0,
      y: index * 2,
      w: 3,
      h: 2,
    }));
    expect(validateDashboard(board).valid).toBe(false);
  });

  it('warns that an unset visibility publishes the dashboard to everyone', () => {
    const board = valid() as Record<string, unknown>;
    delete board.visibility;
    const result = validateDashboard(board);
    expect(result.warnings.some((w) => w.message.includes('defaults to "public"'))).toBe(true);
  });

  it('rejects a visibility the server does not accept', () => {
    const board = { ...valid(), visibility: 'shared' };
    expect(validateDashboard(board).valid).toBe(false);
  });

  it('rejects non-array layout.variables, which the server 400s on', () => {
    const board = valid();
    (board.layout as Record<string, unknown>).variables = { host: 'web-01' };
    expect(validateDashboard(board).valid).toBe(false);
  });
});

describe('validateDashboard — survives malformed LLM output rather than throwing', () => {
  // This function's whole job is describing bad input. A throw escapes the handler
  // and becomes a JSON-RPC internal error, which the agent cannot act on.
  it('does not throw on null array elements', () => {
    const board = valid() as Record<string, unknown>;
    (board.panels as unknown[]).push(null);
    expect(() => validateDashboard(board)).not.toThrow();
    expect(validateDashboard(board).valid).toBe(false);
  });

  it('does not throw on a null layout item or a null variable', () => {
    const board = valid() as Record<string, unknown>;
    ((board.layout as Record<string, unknown>).items as unknown[]).push(null);
    ((board.layout as Record<string, unknown>).variables as unknown[]).push(null);
    expect(() => validateDashboard(board)).not.toThrow();
  });

  it('rejects string grid coordinates instead of coercing them', () => {
    // The server stores what it is sent, and react-grid-layout then evaluates
    // `x + w` as string concatenation.
    const board = valid();
    board.layout.items[0] = { i: 'total', x: '0', y: '0', w: '3', h: '2' } as never;
    const result = validateDashboard(board);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes('not strings'))).toBe(true);
  });
});

describe('validateDashboard — degenerate input', () => {
  it('rejects a non-object', () => {
    expect(validateDashboard(null).valid).toBe(false);
    expect(validateDashboard('a dashboard').valid).toBe(false);
  });

  it('rejects a dashboard with no name', () => {
    const board = valid() as Record<string, unknown>;
    delete board.name;
    expect(validateDashboard(board).valid).toBe(false);
  });

  it('reports both problems when panels and layout are missing, rather than throwing', () => {
    const result = validateDashboard({ name: 'x' });
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(2);
  });
});

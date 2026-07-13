import type { NanosiemClient } from '@nano-investigator/core';
import { type ToolResult, ok, err } from './utils.js';
import { parseRelativeTime } from './search.js';

/**
 * Dashboards: build one, prove it works, save it.
 *
 * WHAT THE SERVER ALREADY CHECKS (DSH14/DSH43, `handlers/dashboards/export.rs`):
 * name and description length, panel count, panel ids present and unique, panel
 * title/query length, the visualization-type and query-mode whitelists, and that
 * `layout.items` is an array of objects carrying i/x/y/w/h. Those come back as a
 * 400, so they are not this module's job — though it checks them anyway, because
 * catching them locally costs nothing and saves a round trip.
 *
 * WHAT NOTHING CHECKS — and what actually breaks a dashboard:
 *   - a layout item whose `i` matches no panel (the panel renders nowhere)
 *   - a panel with no layout item (same)
 *   - panels that overlap, or run off the 12-column grid
 *   - a query the panel-query endpoint will reject at RENDER time (`| tree` et al)
 *   - a $variable nothing declares, so the panel silently returns nothing
 *   - a SQL panel with no time filter, which quietly scans all retention
 *   - autoRun off, so the dashboard opens empty
 * Every one of those saves with a cheerful 200 and disappoints later. That is
 * what `validate_dashboard` is for, and why the authoring loop is:
 *
 *   get_dashboard_schema  → learn the contract (don't guess it)
 *   validate_dashboard    → catch what the server won't, locally, for free
 *   dashboard_panel_query → prove each panel actually returns rows
 *   create/update         → only then persist
 */

/**
 * The viz types an agent should AUTHOR.
 *
 * The backend accepts three more — `tree`, `flow`, `obs_metric` — and they exist
 * on real dashboards, so they are tolerated on panels that already exist (see
 * `SERVER_VIZ`). But they must not be authored: the backend rejects the commands
 * `tree`/`flow` need at panel-query time, and `obs_metric` is fed by the metrics
 * endpoint rather than the panel-query path. Authoring one produces a panel that
 * is broken by construction.
 */
const AUTHORABLE_VIZ = [
  'bar',
  'line',
  'area',
  'pie',
  'table',
  'single_value',
  'timeline',
  'ranked_bar',
  'transaction',
] as const;

/** Everything the backend's whitelist accepts — what an EXISTING panel may be. */
const SERVER_VIZ = [...AUTHORABLE_VIZ, 'tree', 'flow', 'obs_metric'];

/**
 * Commands the panel-query endpoint hard-rejects (HTTP 400). A panel containing
 * one of these fails on every refresh, forever.
 */
const FORBIDDEN_COMMANDS = ['tree', 'asset', 'cloud', 'ai', 'lateral', 'funnel'];

/** The grid the web app renders on. */
const GRID_COLUMNS = 12;
const MIN_PANEL_W = 2;
const MIN_PANEL_H = 2;

/** The server's own limits (`handlers/dashboards/types.rs`). Exceeding one is a 400. */
const MAX_NAME_LENGTH = 200;
const MAX_DESCRIPTION_LENGTH = 2000;
const MAX_PANELS = 50;
const MAX_QUERY_LENGTH = 10_000;
const MAX_PANEL_TITLE_LENGTH = 200;

const VISIBILITIES = ['public', 'group', 'private'];

/**
 * Strip the parts of a query where a `|` is DATA, not a pipe: quoted strings and
 * regex literals. The backend applies its command blocklist to the parsed AST, so
 * a raw text scan over the whole query rejects things it runs perfectly well —
 * `process_name=/(chrome|ai)/` and `message="failed|tree"` are both legitimate,
 * and both look like a forbidden command to a naive scan.
 */
function stripLiterals(query: string): string {
  return query
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/\/(?:[^/\\\n]|\\.)*\//g, '//');
}

/**
 * The commands a piped query actually invokes: the first token after each top-level
 * `|`, once the literals are gone.
 */
function pipedCommands(query: string): string[] {
  return stripLiterals(query)
    .split('|')
    .slice(1)
    .map((segment) => segment.trim().split(/[\s(]/, 1)[0].toLowerCase())
    .filter(Boolean);
}

/** Sizes that make each viz readable, from the web app's own `getIdealSize`. */
const IDEAL_SIZE: Record<string, { w: number; h: number }> = {
  single_value: { w: 3, h: 2 },
  pie: { w: 4, h: 3 },
  bar: { w: 6, h: 3 },
  ranked_bar: { w: 6, h: 3 },
  line: { w: 6, h: 3 },
  area: { w: 6, h: 3 },
  timeline: { w: 6, h: 3 },
  table: { w: 6, h: 4 },
  transaction: { w: 6, h: 4 },
};

/**
 * The authoring contract, returned as data.
 *
 * This exists because a model that guesses panel JSON gets it subtly wrong — a
 * `visualizationType` the backend blocks, a layout item whose `i` matches no
 * panel, a SQL panel with no time filter that quietly scans all retention. Handing
 * over the rules is cheaper than debugging the guesses.
 */
const SCHEMA_GUIDE = {
  overview:
    'A dashboard is { name, description?, visibility?, layout, panels[] }. The server checks ' +
    'field limits and basic structure (name/title/query length, panel count, unique ids, the ' +
    'visualization whitelist, layout.items shape) and 400s on those. It does NOT check the ' +
    'things that make a dashboard actually WORK: that every layout item points at a real panel, ' +
    'that panels fit the grid and do not overlap, or that a query is one the panel-query endpoint ' +
    'will run. Those save cleanly and disappoint later — so run validate_dashboard, then ' +
    'dashboard_panel_query on each panel, BEFORE create_dashboard.',

  visibilityDefault:
    'IMPORTANT: `visibility` defaults to "public" server-side — visible to every user in the ' +
    'tenant. Set it explicitly. Use "private" unless the user asked for a shared dashboard.',

  serverLimits: {
    name: `<= ${MAX_NAME_LENGTH} chars`,
    description: `<= ${MAX_DESCRIPTION_LENGTH} chars`,
    panels: `<= ${MAX_PANELS}`,
    panelTitle: `<= ${MAX_PANEL_TITLE_LENGTH} chars`,
    panelQuery: `<= ${MAX_QUERY_LENGTH} chars`,
    panelIds: 'must be present, non-empty, and unique',
  },

  casing:
    'Dashboard-level fields are snake_case (refresh_interval, created_at). Everything ' +
    'INSIDE panels and layout is camelCase (queryMode, visualizationType, rowHeight). This ' +
    'is not a typo — the two blobs are owned by the frontend.',

  panel: {
    id: 'string, unique within the dashboard. Must match exactly one layout.items[].i',
    title: 'string',
    query: 'nPL (piped) or ClickHouse SQL — see queryMode',
    queryMode: "'piped' | 'sql'",
    visualizationType: AUTHORABLE_VIZ,
    visualizationConfig: 'object; see visualizationConfig below. {} is valid.',
    timeRangeMode: "'dashboard' (inherit the dashboard's picker) | 'custom'",
    customTimeRange: "only when timeRangeMode === 'custom': { start, end } ISO 8601",
    drilldownEnabled: 'boolean',
  },

  visualizationConfig: {
    bar: 'orientation: horizontal|vertical (default vertical), stacked: boolean',
    line: 'showPoints: boolean (default true), smooth: boolean',
    area: 'smooth: boolean, fillOpacity: number (default 0.3)',
    pie: 'showLabels: boolean — note the renderer ALWAYS draws a donut',
    table: 'pageSize: number (default 10, 5–100), columns?: [{field,label,sortable,width?}]',
    single_value:
      'unit: string, showTrend: boolean, thresholds?: [{value,color,label?}] (sorted desc, ' +
      'first value >= threshold wins)',
    timeline: 'renders as an area chart; smooth (default true), fillOpacity (default 0.5)',
    ranked_bar: 'orientation (default horizontal), showPercent: boolean',
    transaction: 'maxEventsShown: number (default 20)',
  },

  layout: {
    columns: `${GRID_COLUMNS} (the grid is always 12 wide)`,
    rowHeight: '80',
    items: `[{ i, x, y, w, h, minW?, minH? }] — react-grid-layout coords. i MUST equal a panel id. ` +
      `w >= ${MIN_PANEL_W}, h >= ${MIN_PANEL_H}, x >= 0, x + w <= ${GRID_COLUMNS}. Items must not overlap.`,
    autoRun: 'boolean — when true the panels run on open. Set it, or the dashboard opens empty.',
    defaultTimeRange: "{ type: 'preset', preset: 'Last 24 hours' } | { type: 'custom', start, end }",
    variables:
      "[{ name, label, type: 'dropdown'|'text'|'query', defaultValue?, options?, query?, queryField? }] " +
      '— NOTE: variables live INSIDE layout, not at the dashboard root.',
    idealSizes: IDEAL_SIZE,
  },

  queryRules: {
    forbiddenCommands:
      `A panel query may NEVER contain these commands — the endpoint returns HTTP 400 and the ` +
      `panel fails on every refresh: ${FORBIDDEN_COMMANDS.map((c) => `| ${c}`).join(', ')}`,
    variables:
      'Reference a dashboard variable as $name. It is substituted before the query runs. A $token ' +
      'inside a quoted string is NEVER substituted (so "$RECYCLE.BIN" survives). A defined variable ' +
      'with an empty value removes its whole clause (field=$var disappears) or becomes * if bare.',
    sqlTimeFilter:
      'A SQL panel MUST use $__timeFilter(timestamp) (or $__timeFrom / $__timeTo). WITHOUT one it ' +
      'ignores the dashboard time picker and scans ALL retention — slow, expensive, and wrong.',
    aggregate:
      'Charts want aggregates: `… | stats count by field` or `… | timechart span=1h count`. A raw ' +
      'event list will render as a one-bar chart or an unreadable table.',
    rowCap: 'Panel results are capped at 10,000 rows.',
  },

  permissions: {
    read: 'dashboards:view',
    run: 'dashboards:view + search:execute (piped) or search:sql (SQL)',
    create: 'dashboards:create',
    edit: 'dashboards:edit',
  },

  example: {
    name: 'Firewall — denied traffic',
    description: 'Denies by port and over time',
    visibility: 'private',
    layout: {
      columns: 12,
      rowHeight: 80,
      autoRun: true,
      defaultTimeRange: { type: 'preset', preset: 'Last 24 hours' },
      variables: [{ name: 'host', label: 'Host', type: 'text', defaultValue: '' }],
      items: [
        { i: 'total', x: 0, y: 0, w: 3, h: 2, minW: 2, minH: 2 },
        { i: 'by-port', x: 3, y: 0, w: 6, h: 3, minW: 2, minH: 2 },
      ],
    },
    panels: [
      {
        id: 'total',
        title: 'Denied events',
        query: 'source_type="firewall" action="deny" host=$host | stats count',
        queryMode: 'piped',
        visualizationType: 'single_value',
        visualizationConfig: { unit: 'events', showTrend: true },
        timeRangeMode: 'dashboard',
        drilldownEnabled: true,
      },
      {
        id: 'by-port',
        title: 'Denies by destination port',
        query:
          'source_type="firewall" action="deny" host=$host | stats count by dest_port | sort -count | head 10',
        queryMode: 'piped',
        visualizationType: 'bar',
        visualizationConfig: { orientation: 'vertical' },
        timeRangeMode: 'dashboard',
        drilldownEnabled: true,
      },
    ],
  },
};

interface Issue {
  path: string;
  message: string;
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Check a proposed dashboard against every invariant the renderer and the
 * backend actually enforce. Pure — no API call, so it costs nothing and can be
 * run on every draft.
 *
 * Errors are things that WILL break. Warnings are things that will merely
 * disappoint (an empty dashboard, a query that scans all time).
 */
export function validateDashboard(
  dashboard: unknown,
  options: {
    /**
     * Panels that ALREADY EXIST on the dashboard being edited. They are held to
     * the server's whitelist rather than the stricter authoring one — otherwise
     * an agent could never edit a dashboard that happens to contain a `tree` or
     * `obs_metric` panel it didn't create, which is most real dashboards.
     */
    existingPanelIds?: Set<string>;
  } = {}
): {
  valid: boolean;
  errors: Issue[];
  warnings: Issue[];
} {
  const errors: Issue[] = [];
  const warnings: Issue[] = [];
  const existing = options.existingPanelIds ?? new Set<string>();

  if (typeof dashboard !== 'object' || dashboard === null || Array.isArray(dashboard)) {
    return { valid: false, errors: [{ path: '', message: 'Dashboard must be an object.' }], warnings };
  }
  const board = dashboard as Record<string, unknown>;

  if (typeof board.name !== 'string' || !board.name.trim()) {
    errors.push({ path: 'name', message: 'A dashboard needs a name.' });
  } else if (board.name.length > MAX_NAME_LENGTH) {
    errors.push({
      path: 'name',
      message: `Name is ${board.name.length} chars; the server rejects anything over ${MAX_NAME_LENGTH}.`,
    });
  }

  if (
    typeof board.description === 'string' &&
    board.description.length > MAX_DESCRIPTION_LENGTH
  ) {
    errors.push({
      path: 'description',
      message: `Description is ${board.description.length} chars; the limit is ${MAX_DESCRIPTION_LENGTH}.`,
    });
  }

  if (board.visibility === undefined) {
    // The server defaults to "public" — i.e. visible to every user in the tenant.
    // An agent that simply omits it has published the dashboard without meaning to.
    warnings.push({
      path: 'visibility',
      message:
        'visibility is not set, and the server defaults to "public" — every user will see this ' +
        'dashboard. Set it explicitly ("private" | "group" | "public").',
    });
  } else if (typeof board.visibility !== 'string' || !VISIBILITIES.includes(board.visibility)) {
    errors.push({
      path: 'visibility',
      message: `visibility must be one of: ${VISIBILITIES.join(', ')}.`,
    });
  }

  const panels = Array.isArray(board.panels) ? (board.panels as unknown[]) : null;
  if (!panels) {
    errors.push({ path: 'panels', message: 'panels must be an array.' });
  } else if (panels.length > MAX_PANELS) {
    errors.push({
      path: 'panels',
      message: `${panels.length} panels; the server rejects more than ${MAX_PANELS}.`,
    });
  }

  const layout = (
    typeof board.layout === 'object' && board.layout !== null && !Array.isArray(board.layout)
      ? board.layout
      : null
  ) as Record<string, unknown> | null;
  if (!layout) {
    errors.push({ path: 'layout', message: 'layout must be an object.' });
  }

  if (!panels || !layout) return { valid: false, errors, warnings };

  if (panels.length === 0) {
    warnings.push({ path: 'panels', message: 'The dashboard has no panels — it will open empty.' });
  }

  if (layout.variables !== undefined && !Array.isArray(layout.variables)) {
    errors.push({
      path: 'layout.variables',
      message: 'layout.variables must be an array — the server rejects anything else.',
    });
  }

  const declaredVariables = new Set(
    (Array.isArray(layout.variables) ? (layout.variables as unknown[]) : [])
      .map((variable) =>
        typeof variable === 'object' && variable !== null
          ? (variable as Record<string, unknown>).name
          : undefined
      )
      .filter((name): name is string => typeof name === 'string')
  );

  // --- panels -------------------------------------------------------------
  const ids = new Set<string>();
  panels.forEach((entry, index) => {
    const at = `panels[${index}]`;

    // An LLM-authored array can contain null. This function's entire job is to
    // survive malformed input and describe it — throwing on it would escape the
    // handler and return a JSON-RPC internal error instead of a fixable message.
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push({ path: at, message: 'Each panel must be an object.' });
      return;
    }
    const panel = entry as Record<string, unknown>;
    const id = panel.id;

    if (typeof id !== 'string' || !id.trim()) {
      errors.push({ path: `${at}.id`, message: 'Every panel needs a non-empty id.' });
    } else if (ids.has(id)) {
      errors.push({ path: `${at}.id`, message: `Duplicate panel id "${id}".` });
    } else {
      ids.add(id);
    }

    if (typeof panel.title !== 'string' || !panel.title.trim()) {
      errors.push({ path: `${at}.title`, message: 'Every panel needs a title.' });
    } else if (panel.title.length > MAX_PANEL_TITLE_LENGTH) {
      errors.push({
        path: `${at}.title`,
        message: `Title is ${panel.title.length} chars; the limit is ${MAX_PANEL_TITLE_LENGTH}.`,
      });
    }

    // A panel that was already on the dashboard is held to the SERVER's whitelist;
    // only a panel being authored now is held to the narrower authorable set.
    const preexisting = typeof id === 'string' && existing.has(id);
    const allowed = preexisting ? SERVER_VIZ : (AUTHORABLE_VIZ as readonly string[]);
    const viz = panel.visualizationType;

    if (typeof viz !== 'string' || !allowed.includes(viz)) {
      errors.push({
        path: `${at}.visualizationType`,
        message: preexisting
          ? `"${String(viz)}" is not a visualization this platform accepts.`
          : `"${String(viz)}" is not an authorable visualization. Use one of: ` +
            `${AUTHORABLE_VIZ.join(', ')}. (tree and flow need commands the backend rejects; ` +
            `obs_metric is fed by the metrics endpoint, not the panel query.)`,
      });
    }

    const mode = panel.queryMode;
    if (mode !== 'piped' && mode !== 'sql') {
      errors.push({ path: `${at}.queryMode`, message: "queryMode must be 'piped' or 'sql'." });
    }

    if (typeof panel.visualizationConfig !== 'object' || panel.visualizationConfig === null) {
      errors.push({
        path: `${at}.visualizationConfig`,
        message: 'visualizationConfig must be an object ({} is fine).',
      });
    }

    if (panel.timeRangeMode !== 'dashboard' && panel.timeRangeMode !== 'custom') {
      errors.push({
        path: `${at}.timeRangeMode`,
        message: "timeRangeMode must be 'dashboard' or 'custom'.",
      });
    }
    if (panel.timeRangeMode === 'custom' && !panel.customTimeRange) {
      errors.push({
        path: `${at}.customTimeRange`,
        message: "timeRangeMode is 'custom' but customTimeRange is missing.",
      });
    }

    const query = panel.query;

    // An `obs_metric` panel carries an EMPTY query by design — its data comes from
    // the metrics endpoint via `metricConfig`, not the panel-query path. Demanding
    // a query from one is how you make an existing dashboard un-editable.
    if (viz === 'obs_metric') return;

    if (typeof query !== 'string' || !query.trim()) {
      errors.push({ path: `${at}.query`, message: 'Every panel needs a query.' });
      return;
    }
    if (query.length > MAX_QUERY_LENGTH) {
      errors.push({
        path: `${at}.query`,
        message: `Query is ${query.length} chars; the server rejects anything over ${MAX_QUERY_LENGTH}.`,
      });
    }

    if (mode === 'sql') {
      if (!/\$__timeFilter\s*\(|\$__timeFrom|\$__timeTo/.test(query)) {
        warnings.push({
          path: `${at}.query`,
          message:
            'A SQL panel with no $__timeFilter(timestamp) ignores the dashboard time picker and ' +
            'scans ALL retention.',
        });
      }
      // The command blocklist below is a PIPED-query rule — the backend only
      // applies it in the piped arm. Scanning SQL for `| asset` would reject
      // `match(msg, 'a|asset')`, which runs fine.
      return;
    }

    // The command blocklist. These don't degrade — they 400 at render time. Checked
    // against the commands the query actually invokes, not a text scan: a `|` inside
    // a quoted string or a regex is data (`process_name=/(chrome|ai)/` is legitimate).
    const invoked = pipedCommands(query);
    for (const command of FORBIDDEN_COMMANDS) {
      if (invoked.includes(command)) {
        errors.push({
          path: `${at}.query`,
          message:
            `"| ${command}" is rejected by the panel-query endpoint (HTTP 400). ` +
            `This panel would fail on every refresh.`,
        });
      }
    }

    const AGGREGATES = ['stats', 'timechart', 'top', 'rare', 'chart'];
    if (!invoked.some((command) => AGGREGATES.includes(command))) {
      warnings.push({
        path: `${at}.query`,
        message:
          `A ${String(viz)} panel usually wants an aggregate (| stats … / | timechart …). ` +
          'A raw event list renders as a single bar or an unreadable table.',
      });
    }

    // $vars that no variable declares are left LITERAL in the query — a silent
    // "no results" rather than an error. Checked outside quoted literals, since a
    // $token inside a string (e.g. "$RECYCLE.BIN") is never substituted either.
    const referenced = stripLiterals(query).match(/\$([A-Za-z_]\w*)/g) ?? [];
    for (const token of referenced) {
      const name = token.slice(1);
      if (name.startsWith('__')) continue; // $__timeFilter and friends
      if (!declaredVariables.has(name)) {
        warnings.push({
          path: `${at}.query`,
          message:
            `$${name} is not declared in layout.variables, so it is left literal in the query ` +
            `(the panel will quietly return nothing).`,
        });
      }
    }
  });

  // --- layout -------------------------------------------------------------
  const columns = typeof layout.columns === 'number' ? layout.columns : GRID_COLUMNS;
  const items = Array.isArray(layout.items) ? (layout.items as Record<string, unknown>[]) : [];

  if (!Array.isArray(layout.items)) {
    errors.push({ path: 'layout.items', message: 'layout.items must be an array.' });
  }
  if (typeof layout.rowHeight !== 'number') {
    warnings.push({ path: 'layout.rowHeight', message: 'layout.rowHeight is usually 80.' });
  }
  if (layout.autoRun !== true) {
    warnings.push({
      path: 'layout.autoRun',
      message: 'autoRun is not true — the dashboard will open empty and wait for a click.',
    });
  }

  const placed = new Set<string>();
  const boxes: { i: string; x: number; y: number; w: number; h: number }[] = [];

  items.forEach((entry, index) => {
    const at = `layout.items[${index}]`;

    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push({ path: at, message: 'Each layout item must be an object.' });
      return;
    }
    const item = entry as Record<string, unknown>;
    const i = item.i;

    if (typeof i !== 'string' || !ids.has(i)) {
      errors.push({
        path: `${at}.i`,
        message: `layout item "${String(i)}" matches no panel id. Every item.i must be a panel id.`,
      });
      return;
    }
    if (placed.has(i)) {
      errors.push({ path: `${at}.i`, message: `Panel "${i}" is placed twice in the layout.` });
      return;
    }
    placed.add(i);

    // Real numbers, not coercible ones. `Number("6")` is 6, but the STRING is what
    // gets persisted — the server only checks the keys are present — and
    // react-grid-layout then evaluates `x + w` as string concatenation.
    const { x, y, w, h } = item;

    if (!isNumber(x) || !isNumber(y) || !isNumber(w) || !isNumber(h)) {
      errors.push({
        path: at,
        message:
          'x, y, w and h must be numbers, not strings. The server stores what you send, and the ' +
          'grid then does arithmetic on it.',
      });
      return;
    }
    if (w < MIN_PANEL_W || h < MIN_PANEL_H) {
      errors.push({
        path: at,
        message: `Panel "${i}" is ${w}x${h}; the minimum is ${MIN_PANEL_W}x${MIN_PANEL_H}.`,
      });
    }
    if (x < 0 || y < 0) {
      errors.push({ path: at, message: `Panel "${i}" has a negative coordinate.` });
    }
    if (x + w > columns) {
      errors.push({
        path: at,
        message: `Panel "${i}" runs off the grid: x(${x}) + w(${w}) > ${columns} columns.`,
      });
    }
    boxes.push({ i, x, y, w, h });
  });

  // Every panel needs somewhere to be.
  for (const id of ids) {
    if (!placed.has(id)) {
      errors.push({
        path: 'layout.items',
        message: `Panel "${id}" has no layout item, so it will not be rendered at all.`,
      });
    }
  }

  // Overlaps: the grid compactor will shove panels around unpredictably.
  for (let a = 0; a < boxes.length; a += 1) {
    for (let b = a + 1; b < boxes.length; b += 1) {
      const first = boxes[a];
      const second = boxes[b];
      const overlaps =
        first.x < second.x + second.w &&
        second.x < first.x + first.w &&
        first.y < second.y + second.h &&
        second.y < first.y + first.h;
      if (overlaps) {
        errors.push({
          path: 'layout.items',
          message: `Panels "${first.i}" and "${second.i}" overlap.`,
        });
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}

export const TOOLS = [
  {
    name: 'get_dashboard_schema',
    description:
      'READ THIS BEFORE AUTHORING A DASHBOARD. Returns the dashboard/panel authoring contract: ' +
      'the visualization types that actually work, the layout grid rules, the panel-query ' +
      'commands that are hard-rejected, how $variables substitute, and a complete worked example.\n' +
      '\n' +
      'The server stores `panels` and `layout` as opaque JSON and validates NOTHING on write, so ' +
      'a guessed panel shape saves happily and then breaks at every render. Do not guess it.',
    inputSchema: { type: 'object' as const, properties: {}, required: [] },
  },
  {
    name: 'validate_dashboard',
    description:
      'Check a dashboard you are about to save against every rule the renderer and backend ' +
      'enforce — panel ids matching layout items, grid bounds, overlaps, blocked commands, ' +
      'undeclared $variables, SQL panels with no time filter. Runs locally: no API call, no cost.\n' +
      '\n' +
      'Returns { valid, errors[], warnings[] }. Errors WILL break the dashboard. Fix them and ' +
      're-validate before calling create_dashboard or update_dashboard.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dashboard: {
          type: 'object',
          description:
            'The full dashboard object: { name, description?, visibility?, layout, panels[] }.',
        },
      },
      required: ['dashboard'],
    },
  },
  {
    name: 'dashboard_panel_query',
    description:
      'Run ONE panel\'s query and return its rows — the way to PROVE a panel works before you save ' +
      'it. A dashboard whose panels were never run is a dashboard of empty boxes.\n' +
      '\n' +
      'Use the same query, query_mode and time range the panel will use. If the query references ' +
      '$variables, pass them in `variables` and let the SERVER substitute them — hand-substituting ' +
      'does not reproduce the platform\'s semantics (an empty value removes its whole clause; a ' +
      'bare $var becomes *; $tokens inside quoted strings are never touched), so a hand-resolved ' +
      'query can return rows here and render differently in the app.\n' +
      '\n' +
      'Results are capped at 10,000 rows. `column_order` in the response tells the renderer which ' +
      'columns are group-bys and which are aggregates — if it comes back, the panel will chart ' +
      'correctly.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: { type: 'string', description: 'The panel query, exactly as the panel will hold it.' },
        variables: {
          type: 'object',
          description:
            'Values for any $variables the query references, e.g. { "host": "web-01" }. Substituted ' +
            'server-side, with the same semantics the dashboard uses.',
        },
        query_mode: {
          type: 'string',
          enum: ['piped', 'sql'],
          description: "'piped' for nPL, 'sql' for ClickHouse SQL.",
        },
        start_time: {
          type: 'string',
          description: 'Start of the window. Relative ("-24h", "-7d") or ISO 8601.',
        },
        end_time: {
          type: 'string',
          description: 'End of the window. Relative, "now", or ISO 8601. Defaults to now.',
        },
        bypass_cache: {
          type: 'boolean',
          description: 'Skip the server-side result cache and recompute live.',
        },
        panel: {
          type: 'object',
          description:
            'The panel this query belongs to: { id?, title?, visualizationType? }. ALWAYS pass ' +
            'this when you are building a dashboard. The nano desktop app watches your tool calls ' +
            'and draws each panel the moment you validate it, so the analyst watches the dashboard ' +
            'assemble itself instead of staring at a spinner. Without it the app knows the rows ' +
            'but not how to draw them.',
          properties: {
            id: { type: 'string' },
            title: { type: 'string' },
            visualizationType: { type: 'string', enum: [...AUTHORABLE_VIZ] },
          },
        },
      },
      required: ['query', 'query_mode', 'start_time'],
    },
  },
  {
    name: 'list_dashboards',
    description:
      'List dashboards. Use this before creating one — the dashboard the user wants may already ' +
      'exist, and editing it beats adding a near-duplicate.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        filter: {
          type: 'string',
          enum: ['my', 'all'],
          description: "'my' (owned by the caller) or 'all' (everything visible to them).",
        },
      },
      required: [],
    },
  },
  {
    name: 'get_dashboard',
    description:
      'Fetch one dashboard in full, including its `panels` and `layout` JSON. This is what you ' +
      'edit: modify the panels/layout you get back and send the whole thing to update_dashboard.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'string', description: 'The dashboard id (typeid, `dashboard_…`).' },
      },
      required: ['id'],
    },
  },
  {
    name: 'create_dashboard',
    description:
      'Save a NEW dashboard. Requires `dashboards:create`.\n' +
      '\n' +
      'Call validate_dashboard first, and dashboard_panel_query on each panel. Nothing on the ' +
      'server checks panel shape, so this endpoint will happily persist a dashboard that renders ' +
      'as a grid of broken boxes.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dashboard: {
          type: 'object',
          description:
            'The full dashboard: { name, description?, visibility?, layout, panels[], ' +
            'refresh_interval? }. See get_dashboard_schema.',
        },
      },
      required: ['dashboard'],
    },
  },
  {
    name: 'update_dashboard',
    description:
      'Update an EXISTING dashboard. Requires `dashboards:edit`.\n' +
      '\n' +
      'PUT replaces `panels` and `layout` wholesale — there is no per-panel endpoint. To add a ' +
      'panel: get_dashboard, append to both arrays, send the whole thing back.\n' +
      '\n' +
      'Pass `expected_updated_at` (the `updated_at` you read) so a concurrent human edit returns ' +
      '409 instead of being silently overwritten. Refusing to clobber someone is worth one retry.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'string', description: 'The dashboard id.' },
        dashboard: {
          type: 'object',
          description:
            'The fields to change: { name?, description?, layout?, panels?, refresh_interval? }. ' +
            'panels/layout are full replacements.',
        },
        expected_updated_at: {
          type: 'string',
          description:
            "The dashboard's `updated_at` as you last read it. Sending it turns a concurrent " +
            'edit into a 409 rather than a silent overwrite.',
        },
      },
      required: ['id', 'dashboard'],
    },
  },
];

/**
 * Relative times (`-24h`, `-7d`), `now`, or ISO 8601 — the same grammar the search
 * tools accept, reused rather than reimplemented.
 *
 * The one addition: a DATE-ONLY string. `parseRelativeTime` passes "2026-07-12"
 * straight through, but the API deserializes into a `DateTime<Utc>` and answers a
 * bare 422 — so widen it to a real instant here instead of letting the agent hit
 * an opaque error.
 */
function resolveTime(time: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(time)) return `${time}T00:00:00Z`;
  return parseRelativeTime(time);
}

export async function handleDashboardsTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  switch (name) {
    case 'get_dashboard_schema':
      return ok(SCHEMA_GUIDE);

    case 'validate_dashboard': {
      if (!args.dashboard) return err('Missing required argument: dashboard');
      const result = validateDashboard(args.dashboard);
      return ok({
        ...result,
        next: result.valid
          ? 'No structural errors. Now run dashboard_panel_query on each panel to prove it returns rows.'
          : 'Fix the errors and validate again. Do not save a dashboard with errors.',
      });
    }

    case 'dashboard_panel_query': {
      const query = args.query as string;
      const queryMode = args.query_mode as 'piped' | 'sql';
      if (!query) return err('Missing required argument: query');
      if (queryMode !== 'piped' && queryMode !== 'sql') {
        return err("query_mode must be 'piped' or 'sql'");
      }
      if (!args.start_time) return err('Missing required argument: start_time');

      let start: string;
      let end: string;
      try {
        start = resolveTime(args.start_time as string);
        end = resolveTime((args.end_time as string) ?? 'now');
      } catch (error) {
        return err((error as Error).message);
      }

      const res = await client.dashboardPanelQuery({
        query,
        query_mode: queryMode,
        time_range: { start, end },
        // Let the server substitute — see the tool description. Its rules are not
        // reproducible by string replacement.
        variables: args.variables as Record<string, string> | undefined,
        bypass_cache: args.bypass_cache as boolean | undefined,
      });
      if (!res.success) return err(`Panel query failed: ${res.error?.message}`);

      const data = res.data;
      return ok({
        ...data,
        // The whole point of running it: say plainly whether this panel has anything to show.
        panel_verdict:
          (data?.results?.length ?? 0) > 0
            ? `Returned ${data?.results?.length} rows — this panel will render.`
            : 'Returned NO rows. This panel would render empty. Widen the window or fix the query.',
      });
    }

    case 'list_dashboards': {
      const res = await client.listDashboards(args.filter as 'my' | 'all' | undefined);
      if (!res.success) return err(`Failed to list dashboards: ${res.error?.message}`);
      // The endpoint already returns summaries carrying `panel_count` — it has no
      // `panels` array at all. Deriving the count from `panels.length` reported
      // every dashboard as empty, which would send an agent off to recreate one
      // that already exists.
      return ok(res.data);
    }

    case 'get_dashboard': {
      const id = args.id as string;
      if (!id) return err('Missing required argument: id');
      const res = await client.getDashboard(id);
      if (!res.success) return err(`Failed to get dashboard: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'create_dashboard': {
      const dashboard = args.dashboard as Record<string, unknown>;
      if (!dashboard) return err('Missing required argument: dashboard');

      // Refuse to persist something we already know is broken. The server won't.
      const check = validateDashboard(dashboard);
      if (!check.valid) {
        return err(
          `This dashboard has ${check.errors.length} error(s) and would render broken. ` +
            `Nothing on the server validates panel shape, so it would save and fail silently. ` +
            `Fix these first:\n${JSON.stringify(check.errors, null, 2)}`
        );
      }

      const res = await client.createDashboard(
        dashboard as unknown as Parameters<typeof client.createDashboard>[0]
      );
      if (!res.success) return err(`Failed to create dashboard: ${res.error?.message}`);
      return ok({ ...res.data, warnings: check.warnings });
    }

    case 'update_dashboard': {
      const id = args.id as string;
      const dashboard = args.dashboard as Record<string, unknown>;
      if (!id) return err('Missing required argument: id');
      if (!dashboard) return err('Missing required argument: dashboard');

      // Only validate when the write actually replaces the structure — a rename
      // shouldn't have to carry a full, valid panel set.
      if (dashboard.panels || dashboard.layout) {
        const current = await client.getDashboard(id);
        if (!current.success) return err(`Failed to read dashboard: ${current.error?.message}`);

        const merged = {
          name: dashboard.name ?? current.data?.name,
          visibility: dashboard.visibility ?? current.data?.visibility,
          layout: dashboard.layout ?? current.data?.layout,
          panels: dashboard.panels ?? current.data?.panels,
        };

        // Panels that were already here are judged by the server's whitelist, not
        // the authoring one. Otherwise a dashboard containing a `tree` or
        // `obs_metric` panel — which the platform stores happily and this agent did
        // not create — could never be edited at all.
        const existingPanelIds = new Set(
          (current.data?.panels ?? [])
            .map((panel) => panel?.id)
            .filter((panelId): panelId is string => typeof panelId === 'string')
        );

        const check = validateDashboard(merged, { existingPanelIds });
        if (!check.valid) {
          return err(
            `This edit would leave the dashboard broken (${check.errors.length} error(s)):\n` +
              `${JSON.stringify(check.errors, null, 2)}`
          );
        }
      }

      const res = await client.updateDashboard(id, {
        ...dashboard,
        expected_updated_at: args.expected_updated_at as string | undefined,
      } as unknown as Parameters<typeof client.updateDashboard>[1]);

      if (!res.success) {
        // The client stamps `HTTP_<status>`; it never surfaces the server's own
        // code string, so matching on 'CONFLICT' silently never fired — and the
        // one path `expected_updated_at` exists to enable was the one that didn't
        // work.
        const code = res.error?.code;
        if (code === 'HTTP_409') {
          return err(
            'Someone else changed this dashboard since you read it, so the write was refused ' +
              'rather than overwriting them. Call get_dashboard again, re-apply your change to ' +
              'the fresh copy, and retry.'
          );
        }
        return err(`Failed to update dashboard: ${res.error?.message}`);
      }
      return ok(res.data);
    }

    default:
      return err(`Unknown dashboards tool: ${name}`);
  }
}

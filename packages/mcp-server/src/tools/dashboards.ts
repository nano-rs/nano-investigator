import type { NanosiemClient } from '@nano-investigator/core';
import { type ToolResult, ok, err } from './utils.js';

/**
 * Dashboards: build one, prove it works, save it.
 *
 * The load-bearing fact about this API: `panels` and `layout` are opaque JSON
 * columns server-side, and NOTHING validates their shape on write. A malformed
 * panel saves with a cheerful 200 and then breaks at every render, in the web app
 * and the desktop app alike. So the honest authoring loop is:
 *
 *   get_dashboard_schema  → learn the contract (don't guess it)
 *   validate_dashboard    → catch the structural mistakes, locally, for free
 *   dashboard_panel_query → prove each panel actually returns rows
 *   create/update         → only then persist
 *
 * Skipping the middle two is how you ship a dashboard of empty boxes.
 */

/**
 * The viz types that can actually be authored.
 *
 * `tree` and `flow` are in the web app's enum but the backend REJECTS the
 * commands they need with HTTP 400 (`validate_panel_query_commands`), and
 * `obs_metric` is fed by the metrics endpoint rather than the panel-query path.
 * Offering any of the three would let an agent author a panel that is broken by
 * construction.
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

/**
 * Commands the panel-query endpoint hard-rejects (HTTP 400). A panel containing
 * one of these fails on every refresh, forever.
 */
const FORBIDDEN_COMMANDS = ['tree', 'asset', 'cloud', 'ai', 'lateral', 'funnel'];

/** The grid the web app renders on. */
const GRID_COLUMNS = 12;
const MIN_PANEL_W = 2;
const MIN_PANEL_H = 2;

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
    'A dashboard is { name, description?, visibility?, layout, panels[] }. `panels` and ' +
    '`layout` are opaque JSON to the server — nothing validates them on write, so a ' +
    'malformed panel saves fine and breaks at render. Always run validate_dashboard, then ' +
    'dashboard_panel_query on each panel, BEFORE create_dashboard.',

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

/**
 * Check a proposed dashboard against every invariant the renderer and the
 * backend actually enforce. Pure — no API call, so it costs nothing and can be
 * run on every draft.
 *
 * Errors are things that WILL break. Warnings are things that will merely
 * disappoint (an empty dashboard, a query that scans all time).
 */
export function validateDashboard(dashboard: unknown): {
  valid: boolean;
  errors: Issue[];
  warnings: Issue[];
} {
  const errors: Issue[] = [];
  const warnings: Issue[] = [];

  if (typeof dashboard !== 'object' || dashboard === null) {
    return { valid: false, errors: [{ path: '', message: 'Dashboard must be an object.' }], warnings };
  }
  const board = dashboard as Record<string, unknown>;

  if (typeof board.name !== 'string' || !board.name.trim()) {
    errors.push({ path: 'name', message: 'A dashboard needs a name.' });
  }

  const panels = Array.isArray(board.panels) ? (board.panels as Record<string, unknown>[]) : null;
  if (!panels) {
    errors.push({ path: 'panels', message: 'panels must be an array.' });
  }

  const layout = (
    typeof board.layout === 'object' && board.layout !== null ? board.layout : null
  ) as Record<string, unknown> | null;
  if (!layout) {
    errors.push({ path: 'layout', message: 'layout must be an object.' });
  }

  if (!panels || !layout) return { valid: false, errors, warnings };

  if (panels.length === 0) {
    warnings.push({ path: 'panels', message: 'The dashboard has no panels — it will open empty.' });
  }

  const declaredVariables = new Set(
    (Array.isArray(layout.variables) ? (layout.variables as Record<string, unknown>[]) : [])
      .map((variable) => variable.name)
      .filter((name): name is string => typeof name === 'string')
  );

  // --- panels -------------------------------------------------------------
  const ids = new Set<string>();
  panels.forEach((panel, index) => {
    const at = `panels[${index}]`;
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
    }

    const viz = panel.visualizationType;
    if (typeof viz !== 'string' || !(AUTHORABLE_VIZ as readonly string[]).includes(viz)) {
      errors.push({
        path: `${at}.visualizationType`,
        message:
          `"${String(viz)}" is not an authorable visualization. Use one of: ` +
          `${AUTHORABLE_VIZ.join(', ')}. (tree and flow are blocked by the backend; ` +
          `obs_metric uses a different data path.)`,
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
    if (typeof query !== 'string' || !query.trim()) {
      errors.push({ path: `${at}.query`, message: 'Every panel needs a query.' });
      return;
    }

    // The command blocklist. These don't degrade — they 400.
    for (const command of FORBIDDEN_COMMANDS) {
      if (new RegExp(`\\|\\s*${command}\\b`, 'i').test(query)) {
        errors.push({
          path: `${at}.query`,
          message:
            `"| ${command}" is rejected by the panel-query endpoint (HTTP 400). ` +
            `This panel would fail on every refresh.`,
        });
      }
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
    } else if (!/\|\s*(stats|timechart|top|rare|chart)\b/i.test(query)) {
      warnings.push({
        path: `${at}.query`,
        message:
          `A ${String(viz)} panel usually wants an aggregate (| stats … / | timechart …). ` +
          'A raw event list renders as a single bar or an unreadable table.',
      });
    }

    // $vars that no variable declares are left LITERAL in the query — a silent
    // "no results" rather than an error.
    const referenced = query.match(/\$([A-Za-z_]\w*)/g) ?? [];
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

  items.forEach((item, index) => {
    const at = `layout.items[${index}]`;
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

    const x = Number(item.x);
    const y = Number(item.y);
    const w = Number(item.w);
    const h = Number(item.h);

    if (![x, y, w, h].every(Number.isFinite)) {
      errors.push({ path: at, message: 'x, y, w and h must all be numbers.' });
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
      'Use the same query, query_mode and time range the panel will use. Substitute any $variables ' +
      'yourself first (send the resolved query). Results are capped at 10,000 rows.\n' +
      '\n' +
      '`column_order` in the response tells the renderer which columns are group-bys and which are ' +
      'aggregates — if it comes back, the panel will chart correctly.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: { type: 'string', description: 'The panel query, with $variables already resolved.' },
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

/** Relative times, matching the search tools (`-24h`, `-7d`, `now`, ISO 8601). */
function resolveTime(time: string): string {
  if (time === 'now') return new Date().toISOString();
  const match = time.match(/^-(\d+)(m|h|d|w)$/);
  if (match) {
    const value = parseInt(match[1], 10);
    const now = new Date();
    if (match[2] === 'm') now.setMinutes(now.getMinutes() - value);
    if (match[2] === 'h') now.setHours(now.getHours() - value);
    if (match[2] === 'd') now.setDate(now.getDate() - value);
    if (match[2] === 'w') now.setDate(now.getDate() - value * 7);
    return now.toISOString();
  }
  if (/^\d{4}-\d{2}-\d{2}/.test(time)) return time;
  throw new Error(
    `Invalid time format: "${time}". Use relative ("-1h", "-7d"), "now", or ISO 8601.`
  );
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
      // The panels blob is large and rarely what you want from a list.
      const summary = (res.data ?? []).map((dashboard) => ({
        id: dashboard.id,
        name: dashboard.name,
        description: dashboard.description,
        visibility: dashboard.visibility,
        panel_count: Array.isArray(dashboard.panels) ? dashboard.panels.length : 0,
        owner_name: dashboard.owner_name,
        updated_at: dashboard.updated_at,
      }));
      return ok(summary);
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
          layout: dashboard.layout ?? current.data?.layout,
          panels: dashboard.panels ?? current.data?.panels,
        };
        const check = validateDashboard(merged);
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
        const code = res.error?.code;
        if (code === 'CONFLICT' || code === 'CONFLICT_ERROR') {
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

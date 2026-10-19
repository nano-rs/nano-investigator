/**
 * Scope-first guard for agent nPL (NAN-4173).
 *
 * A bare `*` search names nothing the lake can prune by: no keyword, no
 * source/class scope and no entity term. Over a long window it reads every
 * part of every source and slows every other tenant query. On lean, nano
 * sends a bare `*` over more than 4h straight to a durable background job
 * (NAN-4163), so an agent that writes `* | stats count by …` over `-7d`
 * gets a job, not an answer.
 *
 * This is a light, client-side mirror of the server's classification
 * (`is_bare_star` in nanosiem-core `lake_candidate_hints.rs`). It is
 * deliberately conservative: anything it cannot classify as bare is treated
 * as scoped, so it never refuses a query the server would run interactively.
 * Plain listing (`*`, `* | head 20`, `* | table …`) is never refused.
 */

/** The longest window a bare `*` aggregation runs interactively. */
export const BARE_STAR_MAX_WINDOW_MS = 4 * 60 * 60 * 1000;

/** Commands that only shape or cap a listing. Anything else does work over every event. */
const LISTING_COMMANDS = new Set(['head', 'tail', 'limit', 'table', 'fields', 'sort', 'rename']);

/**
 * A leading `| where` predicate on one of these fields is hoisted into file
 * selection by the lake compiler (NAN-4155), so `* | where metadata.log_source=x`
 * is scoped. Mirrors the server's source-family / class / entity hint paths.
 */
const SCOPE_PREDICATE =
  /(?:^|[\s(])(?:metadata\.log_source|metadata\.product\.[\w.]+|source_type|sourcetype|log_source|class_uid|category_uid|class_name|type_uid|[\w.]*hostname|[\w.]*\.ip|src_ip|dst_ip|dest_ip|src_host|dest_host|host|[\w.]*user\.name|[\w.]*user_name|user|[\w.]*hash[\w.]*|process\.[\w.]+|process_name)\s*(?:==?(?!=)|\s+(?:in|contains|like)\b)/i;

/** Split an nPL query on top-level pipes, ignoring pipes inside quotes or parentheses. */
export function splitPipeline(query: string): string[] {
  const stages: string[] = [];
  let current = '';
  let quote: string | null = null;
  let depth = 0;
  for (let i = 0; i < query.length; i++) {
    const ch = query[i];
    if (quote) {
      current += ch;
      if (ch === '\\' && i + 1 < query.length) {
        current += query[++i];
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '(') {
      depth++;
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1);
    } else if (ch === '|' && depth === 0) {
      stages.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  stages.push(current.trim());
  return stages;
}

function commandName(stage: string): string {
  return stage.split(/\s+/, 1)[0]?.toLowerCase() ?? '';
}

function isMatchAll(searchStage: string): boolean {
  let stage = searchStage.trim();
  while (stage.startsWith('(') && stage.endsWith(')')) {
    stage = stage.slice(1, -1).trim();
  }
  return stage === '' || stage === '*';
}

export interface QueryScope {
  /** No keyword, source/class scope or entity term before the first non-where command. */
  bare: boolean;
  /** A bare query whose commands do work over every event (stats, eval, where, timechart, …). */
  aggregates: boolean;
}

/** Classify an nPL query the way nano's lake does for bare `*` routing. */
export function classifyQueryScope(query: string): QueryScope {
  const [search = '', ...commands] = splitPipeline(query ?? '');
  if (!isMatchAll(search)) {
    return { bare: false, aggregates: false };
  }
  for (const stage of commands) {
    if (commandName(stage) !== 'where') break;
    if (SCOPE_PREDICATE.test(stage.slice('where'.length))) {
      return { bare: false, aggregates: false };
    }
  }
  const aggregates = commands.some((stage) => !LISTING_COMMANDS.has(commandName(stage)));
  return { bare: true, aggregates };
}

function formatWindow(ms: number): string {
  const hours = ms / 3_600_000;
  return hours >= 48 ? `${Math.round(hours / 24)}d` : `${Math.round(hours * 10) / 10}h`;
}

/** Suggest the same pipeline with a scope placeholder in place of `*`. */
export function scopedRewrite(query: string, scope = 'metadata.log_source=<source>'): string {
  const [, ...commands] = splitPipeline(query);
  return [scope, ...commands].join(' | ');
}

/**
 * Returns an actionable refusal when an agent asks for a bare `*`
 * aggregation over more than 4h, or `null` when the query may run.
 * `options.aggregates` marks a tool that aggregates by itself (top values),
 * so even a plain `*` scope is an aggregation there.
 */
export function bareStarRefusal(
  query: string,
  startIso: string,
  endIso: string,
  toolName: string,
  options: { aggregates?: boolean } = {},
): string | null {
  const windowMs = Date.parse(endIso) - Date.parse(startIso);
  if (!Number.isFinite(windowMs) || windowMs <= BARE_STAR_MAX_WINDOW_MS) return null;
  const scope = classifyQueryScope(query);
  if (!scope.bare || !(scope.aggregates || options.aggregates)) return null;

  return (
    `${toolName} refused a bare \`*\` aggregation over ${formatWindow(windowMs)}: \`${query.trim() || '*'}\` names no source, class, entity or keyword, ` +
    'so it reads every source in the window and slows every other query on this deployment. ' +
    'On lean, nano runs a bare `*` over more than 4h with stats/eval/where/timechart as a background job instead of answering interactively.\n' +
    'Scope it first, for example:\n' +
    `  - by source: \`${scopedRewrite(query)}\` (call get_source_types for real source names)\n` +
    `  - by class: \`${scopedRewrite(query, 'class_uid=<class>')}\`\n` +
    `  - by entity: \`${scopedRewrite(query, 'device.hostname="<host>"')}\` (or actor.user.name, src_endpoint.ip, a file hash)\n` +
    `  - by keyword: \`${scopedRewrite(query, '<keyword>')}\`\n` +
    'If an unscoped aggregate is truly required, narrow the window to 4h or less (for example start_time "-4h"). ' +
    'Only when the analyst explicitly asked for all events across every source, retry with allow_bare_star=true.'
  );
}

#!/usr/bin/env node
/**
 * Generate the OCSF 1.9 reference data that ships inside the MCP server.
 *
 * The MCP server runs on an analyst's machine, often against an air-gapped or
 * firewalled deployment, so it cannot fetch the OCSF schema at runtime. This
 * script pulls the authoritative catalog from schema.ocsf.io once and emits a
 * committed TypeScript module, which keeps the data reviewable in a diff and
 * regenerable when OCSF publishes a new version.
 *
 * Two things are deliberately NOT baked in here:
 *   - The set of fields a given deployment actually promotes. That is
 *     deployment-specific and comes from `/api/schema/fields` at runtime.
 *   - Anything about the query backend. Orthogonal axis.
 *
 * Usage: node scripts/generate-ocsf-reference.mjs [version]
 */

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const VERSION = process.argv[2] ?? '1.9.0';
const BASE = `https://schema.ocsf.io/api/${VERSION}`;

/**
 * Classes worth expanding with their full activity enum.
 *
 * OCSF 1.9 has 87 classes; inlining every attribute of every one would produce
 * a resource too large to be read usefully by a model. These are the classes
 * nano's own OCSF parsers emit, plus the neighbours an analyst reaches for
 * next — they cover what actually shows up in a nano deployment.
 */
const DETAILED_CLASS_UIDS = [
  1001, // File System Activity
  1005, // Module Activity
  1007, // Process Activity
  2004, // Detection Finding
  3001, // Account Change — DEPRECATED in 1.9, superseded by User Management
  3002, // Authentication
  3004, // Entity Management
  3007, // User Management — the 1.9 replacement for 3001/3005
  4001, // Network Activity
  4002, // HTTP Activity
  4003, // DNS Activity
  4004, // DHCP Activity
  6003, // API Activity
  201001, // Registry Key Activity (Windows extension)
  201002, // Registry Value Activity (Windows extension)
];

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} for ${url}`);
  return response.json();
}

/**
 * Upstream descriptions embed HTML (`<br>`, `<strong>`, `<code>`). The resource
 * is rendered as markdown into a model's context, where raw tags are noise.
 */
function stripHtml(text) {
  return String(text ?? '')
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function enumOf(attribute) {
  const values = attribute?.enum ?? {};
  return Object.entries(values)
    .map(([id, meta]) => ({ id: Number(id), caption: meta.caption }))
    .sort((a, b) => a.id - b.id);
}

const classes = await getJson(`${BASE}/classes`);

function deprecation(c) {
  const meta = c['@deprecated'];
  if (!meta) return null;
  return {
    since: meta.since ?? null,
    supersededBy: meta.superseded_by ?? [],
    message: stripHtml(meta.message),
  };
}

// Deprecated classes are KEPT, and marked. Dropping them would leave an author
// with no way to learn that the class their 1.8-era parser emits was retired —
// OCSF 1.9 deprecated Account Change (3001) and User Access Management (3005)
// in favour of User Management (3007), and nano's own shipped parsers predate
// that.
const catalog = classes
  // `base_event` (uid 0) is the abstract parent every class extends, not
  // something a producer emits, and it carries no category. Excluding it keeps
  // the catalog to things a parser can actually set `class_uid` to.
  .filter((c) => c.uid !== 0)
  .map((c) => ({
    uid: c.uid,
    caption: c.caption,
    name: c.name,
    category: c.category_name,
    categoryUid: c.category_uid,
    ...(c.extension ? { extension: c.extension } : {}),
    ...(deprecation(c) ? { deprecated: deprecation(c) } : {}),
  }))
  .sort((a, b) => a.uid - b.uid);

const detailed = [];
for (const uid of DETAILED_CLASS_UIDS) {
  const summary = classes.find((c) => c.uid === uid);
  if (!summary) {
    console.error(`  ! class_uid ${uid} not present in OCSF ${VERSION} — skipped`);
    continue;
  }
  // Extension classes (the Windows registry pair) are addressed by
  // `<extension>/<name>`; core classes by bare name.
  const path = summary.extension ? `${summary.extension}/${summary.name}` : summary.name;
  const full = await getJson(`${BASE}/classes/${path}`);
  detailed.push({
    uid,
    caption: full.caption,
    name: full.name,
    extension: summary.extension ?? null,
    category: full.category_name,
    categoryUid: full.category_uid,
    description: stripHtml(full.description),
    ...(deprecation(summary) ? { deprecated: deprecation(summary) } : {}),
    activities: enumOf(full.attributes?.activity_id),
  });
  console.error(`  + ${uid} ${full.caption} (${detailed.at(-1).activities.length} activities)`);
}

const categories = [...new Map(catalog.map((c) => [c.categoryUid, c.category])).entries()]
  .map(([uid, caption]) => ({ uid, caption }))
  .sort((a, b) => a.uid - b.uid);

const header = `// GENERATED FILE — do not edit by hand.
// Regenerate with: node scripts/generate-ocsf-reference.mjs ${VERSION}
// Source: ${BASE} (OCSF ${VERSION}, fetched at generation time)
//
// Committed rather than fetched at runtime: the MCP server runs next to
// deployments that have no outbound internet, and a schema catalog that
// silently changes underneath a session is worse than one that changes in a
// reviewed diff.

`;

const body = `export const OCSF_VERSION = ${JSON.stringify(VERSION)};

export interface OcsfClassSummary {
  uid: number;
  caption: string;
  name: string;
  category: string;
  categoryUid: number;
  /** Set when the class comes from an OCSF extension (e.g. \`win\`), not core. */
  extension?: string | null;
  /** Present when OCSF retired this class. Do not emit it from a new parser. */
  deprecated?: { since: string | null; supersededBy: string[]; message: string };
}

export interface OcsfActivity {
  id: number;
  caption: string;
}

export interface OcsfClassDetail extends OcsfClassSummary {
  description: string;
  activities: OcsfActivity[];
}

export const OCSF_CATEGORIES: { uid: number; caption: string }[] = ${JSON.stringify(categories, null, 2)};

/** Every class in OCSF ${VERSION}. Retired ones carry a \`deprecated\` marker. */
export const OCSF_CLASSES: OcsfClassSummary[] = ${JSON.stringify(catalog, null, 2)};

/** Classes nano's own parsers emit, expanded with their activity enums. */
export const OCSF_DETAILED_CLASSES: OcsfClassDetail[] = ${JSON.stringify(detailed, null, 2)};
`;

const outPath = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'packages',
  'mcp-server',
  'src',
  'resources',
  'ocsf-catalog.generated.ts',
);
writeFileSync(outPath, header + body);
console.error(
  `\nWrote ${outPath}\n  ${catalog.length} classes (${catalog.filter((c) => c.deprecated).length} deprecated), ` +
    `${detailed.length} detailed, ${categories.length} categories`,
);

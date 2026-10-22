#!/usr/bin/env node
// Refresh the vendored tenant SOAR OpenAPI contract (NAN-4375).
//
//   node scripts/refresh-soar-openapi.mjs <openapi.json path | tenant base URL>
//
// Source: a spec exported from nanosiem with the enterprise feature
// (`cargo run -p nanosiem-api --features enterprise --bin export_openapi`) or a
// hosted tenant's public spec at `<tenant>/api-docs/openapi.json` (no key is
// sent or needed). Keeps only tenant `/api/soar/*` routes and the schemas they
// reference; platform-admin catalog routes are not part of this contract.
import { readFileSync, writeFileSync } from 'node:fs';

const source = process.argv[2];
if (!source) {
  console.error('usage: refresh-soar-openapi.mjs <openapi.json | https://<host>/t/<tenant>>');
  process.exit(2);
}
let spec;
if (/^https:\/\//.test(source)) {
  const url = new URL(source.replace(/\/$/, '') + '/api-docs/openapi.json');
  const response = await fetch(url, { redirect: 'error' });
  if (!response.ok) throw new Error(`spec fetch failed: HTTP ${response.status}`);
  spec = await response.json();
} else {
  spec = JSON.parse(readFileSync(source, 'utf8'));
}

const paths = Object.fromEntries(
  Object.entries(spec.paths).filter(([path]) => path.startsWith('/api/soar/')).sort(([a], [b]) => a.localeCompare(b)),
);
if (!Object.keys(paths).length) throw new Error('spec has no /api/soar routes (enterprise feature missing?)');
const needed = new Set();
const walk = (value) => {
  if (Array.isArray(value)) value.forEach(walk);
  else if (value && typeof value === 'object')
    for (const [key, item] of Object.entries(value)) key === '$ref' ? needed.add(String(item).split('/').pop()) : walk(item);
};
walk(paths);
const schemas = {};
for (let pending = [...needed]; pending.length; ) {
  const name = pending.pop();
  if (schemas[name]) continue;
  schemas[name] = spec.components.schemas[name];
  if (!schemas[name]) throw new Error(`missing schema ${name}`);
  const before = needed.size;
  walk(schemas[name]);
  if (needed.size !== before) pending = [...needed].filter((entry) => !schemas[entry]);
}
const out = {
  openapi: spec.openapi,
  info: { title: 'nano tenant SOAR API (vendored subset)', version: spec.info.version },
  'x-nano-source': { from: /^https:/.test(source) ? new URL(source).origin + '/t/<tenant>/api-docs/openapi.json' : 'export_openapi', refreshed_at: new Date().toISOString().slice(0, 10) },
  paths,
  components: {
    schemas: Object.fromEntries(Object.entries(schemas).sort(([a], [b]) => a.localeCompare(b))),
    securitySchemes: spec.components.securitySchemes,
  },
};
writeFileSync(new URL('../packages/core/src/fixtures/soar-openapi.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`soar-openapi.json: ${Object.keys(paths).length} paths, ${Object.keys(schemas).length} schemas`);

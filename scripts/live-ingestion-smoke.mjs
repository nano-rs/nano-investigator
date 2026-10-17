#!/usr/bin/env node
// Read-only qualification with the documented SEARCH-ONLY lean tenant key.
// Never emits keys, response bodies, server error text or tenant inventory.
import { readFileSync } from 'node:fs';
import { NanosiemClient } from '../packages/core/dist/index.js';

let apiKey;
try {
  apiKey = JSON.parse(readFileSync('/home/dan/.config/nano-test-tenant/lean-api-key-b12e5ee2.json', 'utf8')).secret;
} catch {
  console.error('BLOCKED: Search-only key file could not be read.');
  process.exit(2);
}
if (typeof apiKey !== 'string' || !apiKey.trim() || /[\r\n]/.test(apiKey)) {
  console.error('BLOCKED: Invalid search-only key format.');
  process.exit(2);
}
const client = new NanosiemClient({
  apiUrl: 'https://us.nano.rs/t/lean-internal-20261004b',
  apiKey, deployment: 'hosted', timeout: 30000,
});
let failed = false;
const end = new Date();
const result = await client.search({
  query: '* | stats count', limit: 1,
  time_range: { start: new Date(end.getTime() - 15 * 60 * 1000).toISOString(), end: end.toISOString() },
});
const searchOk = result.success && Array.isArray(result.data?.results);
console.log(`${searchOk ? 'PASS' : 'FAIL'} bounded lean search with search-only X-API-Key`);
failed ||= !searchOk;
let permitted = 0;
let denied = 0;
for (const path of ['/api/log-sources', '/api/log-sources/pipe-inputs', '/api/source-onboarding',
  '/api/log-sources/ingest-endpoint', '/api/log-sources/ingest-credentials', '/api/pull-sources',
  '/api/marketplace/collectors', '/api/parser-repositories']) {
  const read = await client.readIngestion(path);
  if (read.success) { permitted++; console.log(`PASS GET ${path}`); }
  else if (read.error?.code === 'HTTP_403') { denied++; console.log(`PASS scope denied GET ${path}`); }
  else { failed = true; console.log(`FAIL GET ${path} (${['HTTP_401', 'HTTP_404', 'HTTP_503', 'TIMEOUT', 'NETWORK_ERROR', 'NOT_AVAILABLE'].includes(read.error?.code) ? read.error.code : 'unavailable'})`); }
}
console.log(`Ingestion reads: ${permitted} permitted, ${denied} denied by scope. Denied routes validate authorization only; positive response contracts are fixture-tested.`);
process.exitCode = failed ? 1 : 0;

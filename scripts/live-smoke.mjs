#!/usr/bin/env node
// Coordinator-only, read-only smoke. Never emits response data or credentials.
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { NanosiemClient } from '../packages/core/dist/index.js';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, 'key-file': { type: 'string' }, deployment: { type: 'string' },
} });
if (!values.url || !values['key-file'] || !['hosted', 'open-core'].includes(values.deployment)) {
  console.error('Usage: node scripts/live-smoke.mjs --url <API base including /t/slug for hosted> --key-file <path> --deployment hosted|open-core');
  process.exit(2);
}
let apiKey;
try { apiKey = readFileSync(values['key-file'], 'utf8').trim(); } catch {
  console.error('Cannot read API key file.'); process.exit(2);
}
if (!apiKey || /[\r\n]/.test(apiKey)) { console.error('API key file must contain one nonempty key.'); process.exit(2); }
let client;
try { client = new NanosiemClient({ apiUrl: values.url, apiKey, deployment: values.deployment, timeout: 120000 }); } catch {
  console.error('Invalid API base URL.'); process.exit(2);
}
const end = new Date();
const start = new Date(end.getTime() - 15 * 60 * 1000);
const window = { start: start.toISOString(), end: end.toISOString() };
let failed = false;
async function check(name, action, validate = () => true, unavailable = false) {
  try {
    const result = await action();
    const pass = unavailable ? !result.success && result.error?.code === 'NOT_AVAILABLE' : result.success && validate(result.data);
    console.log(`${pass ? 'PASS' : 'FAIL'} ${name}`);
    if (!pass) failed = true;
  } catch { console.log(`FAIL ${name}`); failed = true; }
}
await check('canonical OCSF schema', () => client.getUdmFields(), (d) => d?.schema === 'ocsf' && d.strict_canonical_fields && Array.isArray(d.fields));
await check('bounded nPL search/job/pages', () => client.search({ query: '* | stats count', time_range: window, limit: 10 }), (d) => Array.isArray(d?.results) && d.results.length <= 10);
await check('alerts page', () => client.listAlerts({ limit: 1, offset: 0 }), Array.isArray);
await check('rules page', () => client.listDetections({ limit: 1, offset: 0 }), Array.isArray);
await check('domain prevalence', () => client.getDomainPrevalence('example.invalid'), (d) => d?.data !== undefined);
await check('IP enrichment', () => client.lookupIp('192.0.2.1'), (d) => d !== null && typeof d === 'object');
if (values.deployment === 'hosted') {
  await check('hosted cases read', () => client.listCases({ limit: 1 }), (d) => Array.isArray(d?.cases));
  await check('hosted entity context', () => client.getEntityContext('ip', '192.0.2.1'), (d) => Array.isArray(d?.alerts));
  await check('hosted raw SQL gate', () => client.searchSql({ sql: 'SELECT 1 LIMIT 1', time_range: window, limit: 1 }), undefined, true);
} else {
  await check('open-core cases unavailable', () => client.listCases(), undefined, true);
  await check('open-core entity context unavailable', () => client.getEntityContext('ip', '192.0.2.1'), undefined, true);
}
process.exitCode = failed ? 1 : 0;

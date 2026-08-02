/**
 * NAN-2295 — the parser tools' client contract.
 *
 * `tsup` inlines `@nano-rs/investigator-core` (its `noExternal` matches every
 * package), and core resolves through its `exports` map to `dist/` — the BUILT
 * artifact, not source. `pnpm --filter @nano-rs/investigator-mcp-server publish` runs
 * only this package's `prepublishOnly`, so nothing rebuilds core on the way
 * past. Publish with a stale `packages/core/dist/` and the bundle carries new
 * tool definitions calling client methods that aren't in it.
 *
 * That is what shipped as 0.1.13: `publish_log_source` registered, dispatch
 * reached the handler, and it threw `client.publishLogSource is not a
 * function`. Visible and unusable — worse than absent, because the tool list
 * says it works.
 *
 * Vitest resolves core through the same `exports` → `dist` path the bundler
 * does, so asserting the methods exist on the prototype turns a stale dist
 * into a red suite. `prepublishOnly` now builds core first; this is the check
 * that the ordering actually held.
 */

import { describe, it, expect } from 'vitest';
import { NanosiemClient } from '@nano-rs/investigator-core';

/**
 * Every client method `handleParsersTool` dispatches to. Keep this in step
 * when a parser tool starts calling a new one — an entry here is cheaper than
 * a burned version number.
 */
const REQUIRED_CLIENT_METHODS = [
  'listLogSources',
  'getLogSource',
  'validateVrl',
  'testVrl',
  'testVrlLive',
  'createLogSource',
  'updateLogSource',
  'publishLogSource',
  'getLogSourceDraftStatus',
  'deployLogSource',
  'undeployLogSource',
  'getLogSourceHealth',
  'getLogSourceDeployments',
  'listSourceConfigTypes',
  'listSourceConfigs',
  'createRoutingRule',
  'checkRoutingRuleReachability',
  'deploySourceConfig',
  'undeploySourceConfig',
  'listParserRepositories',
  'syncParserRepository',
  'listRepositoryParsers',
  'importParser',
] as const;

describe('parser tools client contract', () => {
  it.each(REQUIRED_CLIENT_METHODS)(
    'NanosiemClient implements %s',
    (method) => {
      expect(typeof (NanosiemClient.prototype as unknown as Record<string, unknown>)[method]).toBe('function');
    },
  );

  it('resolves the publish methods NAN-2293 added — the pair 0.1.13 shipped without', () => {
    const proto = NanosiemClient.prototype as unknown as Record<string, unknown>;
    expect(typeof proto.publishLogSource).toBe('function');
    expect(typeof proto.getLogSourceDraftStatus).toBe('function');
  });
});

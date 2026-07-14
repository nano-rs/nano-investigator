/**
 * Prevalence tools — "Is this normal?"
 * The #1 SOC question, answered quantitatively.
 */

import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'get_prevalence',
    description:
      'Check how common an artifact is across the environment. Returns host count, total occurrences, first/last seen, and whether it is considered rare. Works for file hashes, domains, and IP addresses. Critical for determining if something is suspicious — an artifact seen on 1 of 4000 hosts is far more interesting than one seen on 3500.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        type: {
          type: 'string',
          enum: ['hash', 'domain'],
          description: 'Artifact type to check prevalence for',
        },
        value: {
          type: 'string',
          description: 'The artifact value (hash, domain)',
        },
      },
      required: ['type', 'value'],
    },
  },
  {
    name: 'get_rare_artifacts',
    description:
      'Find rare artifacts in the environment — things seen on fewer than the rarity threshold number of hosts. Useful for hunting: rare artifacts are more likely to be suspicious. Returns artifacts sorted by host count (rarest first).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        type: {
          type: 'string',
          enum: ['hash_md5', 'hash_sha256', 'domain', 'ip_address'],
          description: 'Filter by artifact type',
        },
        window: {
          type: 'string',
          description: 'Time window (e.g., "24h", "7d", "30d")',
        },
        limit: {
          type: 'number',
          description: 'Maximum results to return (default: 50)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination',
        },
      },
    },
  },
  {
    name: 'get_new_artifacts',
    description:
      'Find artifacts seen for the first time recently. New artifacts in an environment warrant attention — they may indicate new software, lateral movement, or compromise. Returns artifacts sorted by first_seen (newest first).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        type: {
          type: 'string',
          enum: ['hash_md5', 'hash_sha256', 'domain', 'ip_address'],
          description: 'Filter by artifact type',
        },
        since: {
          type: 'string',
          description: 'Show artifacts first seen after this time (ISO 8601 or relative like "-24h")',
        },
        limit: {
          type: 'number',
          description: 'Maximum results to return (default: 50)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination',
        },
      },
    },
  },
];

export async function handlePrevalenceTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'get_prevalence': {
        const type = args.type as string;
        const value = args.value as string;

        let res;
        if (type === 'hash') {
          res = await client.getHashPrevalence(value);
        } else if (type === 'domain') {
          res = await client.getDomainPrevalence(value);
        } else {
          return err(`Unsupported prevalence type: ${type}. Use "hash" or "domain".`);
        }

        if (!res.success) return err(res.error?.message ?? 'Failed to get prevalence');
        return ok(res.data);
      }

      case 'get_rare_artifacts': {
        const res = await client.getRareArtifacts({
          type: args.type as string | undefined,
          window: args.window as string | undefined,
          limit: (args.limit as number) ?? 50,
          offset: args.offset as number | undefined,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to get rare artifacts');
        return ok(res.data);
      }

      case 'get_new_artifacts': {
        const res = await client.getNewArtifacts({
          type: args.type as string | undefined,
          since: args.since as string | undefined,
          limit: (args.limit as number) ?? 50,
          offset: args.offset as number | undefined,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to get new artifacts');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

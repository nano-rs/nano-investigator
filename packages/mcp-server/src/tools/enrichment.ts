/**
 * Enrichment tools — entity context, IP/IOC lookups
 */

import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'lookup_ioc',
    annotations: { readOnlyHint: true },
    description: 'Look up an indicator using the tenant threat intelligence providers. Provider availability and permissions depend on deployment.',
    inputSchema: {
      type: 'object' as const,
      properties: { artifact: { type: 'string' }, artifact_type: { type: 'string' } },
      required: ['artifact'],
    },
  },
  {
    name: 'get_entity_context',
    annotations: { readOnlyHint: true },
    description:
      'Get hosted enterprise context for an entity (IP, user, host, domain, hash): risk, detection matches, alerts and cases. Requires risk:view, detections:view, alerts:view and cases:view. Open core uses search and prevalence instead.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        entity_type: {
          type: 'string',
          enum: ['ip', 'user', 'host', 'domain', 'hash'],
          description: 'Type of entity to investigate',
        },
        value: {
          type: 'string',
          description: 'Entity value (IP address, username, hostname, domain, or hash)',
        },
      },
      required: ['entity_type', 'value'],
    },
  },
  {
    name: 'lookup_ip',
    annotations: { readOnlyHint: true },
    description:
      'GeoIP + ASN enrichment for an IP address. Returns country, continent, ASN number, AS name, and AS domain. Useful for determining if an IP is from an expected geography or a suspicious location.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ip: {
          type: 'string',
          description: 'IP address to look up',
        },
      },
      required: ['ip'],
    },
  },
];

export async function handleEnrichmentTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'get_entity_context': {
        const res = await client.getEntityContext(args.entity_type as string, args.value as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to get entity context');
        return ok(res.data);
      }

      case 'lookup_ioc': {
        const res = await client.lookupIoc(args.artifact as string, args.artifact_type as string | undefined);
        if (!res.success) return err(res.error?.message ?? 'Threat intelligence unavailable');
        return ok(res.data);
      }

      case 'lookup_ip': {
        const res = await client.lookupIp(args.ip as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to look up IP');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

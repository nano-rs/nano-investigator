/**
 * Enrichment tools — entity context, IP/IOC lookups
 */

import type { NanosiemClient } from '@nano-investigator/core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'get_entity_context',
    description:
      'Get rich context for any entity (IP, user, host, domain, hash). Performs a composite enrichment: searches recent activity, checks risk score, looks up alerts and cases involving this entity. This is the investigation pivot tool — call it when you encounter an entity and need to decide "is this interesting?"',
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
  {
    name: 'lookup_ioc',
    description:
      'Check if a value (domain, IP, or hash) is a known Indicator of Compromise (IOC). Searches threat intelligence feeds including ThreatFox and Tor exit node lists. Returns match status, threat type, malware family, confidence level, and references.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        value: {
          type: 'string',
          description: 'IOC value to check (domain, IP address, or file hash)',
        },
      },
      required: ['value'],
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
        const entityType = args.entity_type as string;
        const value = args.value as string;

        // Composite enrichment: gather multiple data sources in parallel
        const results: Record<string, unknown> = {
          entity_type: entityType,
          value,
        };

        // Run enrichments in parallel where possible
        const promises: Promise<void>[] = [];

        // IP-specific enrichment
        if (entityType === 'ip') {
          promises.push(
            client.lookupIp(value).then((res) => {
              if (res.success) results.geo = res.data;
            })
          );
          promises.push(
            client.lookupIoc(value).then((res) => {
              if (res.success) results.ioc = res.data;
            })
          );
        }

        // Domain/hash IOC check
        if (entityType === 'domain' || entityType === 'hash') {
          promises.push(
            client.lookupIoc(value).then((res) => {
              if (res.success) results.ioc = res.data;
            })
          );
        }

        // Risk score for this specific entity
        promises.push(
          client.getEntityRiskTimeline(value, entityType).then((res) => {
            if (res.success && res.data && res.data.entities.length > 0) {
              const match = res.data.entities[0];
              results.risk = {
                score: match.risk_score,
                level: match.risk_level,
                finding_count: match.finding_count,
                last_finding_at: match.last_finding_at,
              };
            }
          })
        );

        await Promise.allSettled(promises);

        return ok(results);
      }

      case 'lookup_ip': {
        const res = await client.lookupIp(args.ip as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to look up IP');
        return ok(res.data);
      }

      case 'lookup_ioc': {
        const res = await client.lookupIoc(args.value as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to look up IOC');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

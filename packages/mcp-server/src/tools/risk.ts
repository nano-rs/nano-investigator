/**
 * Risk scoring tools — entity-level risk aggregation
 */

import type { NanosiemClient } from '@nano-investigator/core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'get_risky_entities',
    description:
      'Get the top entities by risk score — who or what is most suspicious right now. Returns entities ranked by accumulated risk from detection rule matches. Use this to prioritize investigation: high-risk entities deserve attention first.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        window: {
          type: 'string',
          enum: ['24h', '7d', 'all'],
          description: 'Time window for risk calculation (default: 24h)',
        },
        entity_type: {
          type: 'string',
          description: 'Filter by entity type (e.g., "ip", "user", "host")',
        },
        min_score: {
          type: 'number',
          description: 'Minimum risk score threshold',
        },
        limit: {
          type: 'number',
          description: 'Maximum entities to return (default: 20)',
        },
      },
    },
  },
  {
    name: 'get_risk_overview',
    description:
      'Risk landscape summary: how many entities exceed each risk level (critical/high/medium/low), total findings, and average risk score. Provides both 24-hour and 7-day views. Good for shift briefings and trend assessment.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_entity_risk_timeline',
    description:
      'Get risk score over time for a specific entity. Shows how risk has escalated or decreased, useful for understanding whether a situation is getting worse. Helps distinguish ongoing attacks from one-time events.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        entity: {
          type: 'string',
          description: 'Entity value (IP, username, hostname, etc.)',
        },
        entity_type: {
          type: 'string',
          description: 'Entity type (e.g., "ip", "user", "host")',
        },
      },
      required: ['entity'],
    },
  },
];

export async function handleRiskTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'get_risky_entities': {
        const res = await client.getRiskyEntities({
          window: args.window as '24h' | '7d' | 'all' | undefined,
          entity_type: args.entity_type as string | undefined,
          min_score: args.min_score as number | undefined,
          limit: (args.limit as number) ?? 20,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to get risky entities');
        return ok(res.data);
      }

      case 'get_risk_overview': {
        const res = await client.getRiskOverview();
        if (!res.success) return err(res.error?.message ?? 'Failed to get risk overview');
        return ok(res.data);
      }

      case 'get_entity_risk_timeline': {
        const res = await client.getEntityRiskTimeline(
          args.entity as string,
          args.entity_type as string | undefined
        );
        if (!res.success) return err(res.error?.message ?? 'Failed to get entity risk timeline');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

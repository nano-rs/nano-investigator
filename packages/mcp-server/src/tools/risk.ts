/**
 * Risk scoring tools — entity-level risk aggregation
 */

import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'get_risky_entities',
    annotations: { readOnlyHint: true },
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
    annotations: { readOnlyHint: true },
    description:
      'Risk landscape summary: how many entities exceed each risk level (critical/high/medium/low), total findings, and average risk score. Provides both 24-hour and 7-day views. Good for shift briefings and trend assessment.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_entity_risk_timeline',
    annotations: { readOnlyHint: true },
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
  {
    name: 'get_entity_risk_activity',
    annotations: { readOnlyHint: true },
    description:
      'Daily finding counts per entity over time — the risk "heatmap". Shows WHEN an entity accrued risk (a steady drip vs a sudden burst), which helps tell an ongoing campaign from a one-off spike. Pass the entities you care about; returns a per-day count series for each.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        entities: {
          type: 'array',
          description: 'Entities to fetch activity for.',
          items: {
            type: 'object',
            properties: {
              entity: { type: 'string' },
              entity_type: { type: 'string' },
            },
            required: ['entity', 'entity_type'],
          },
        },
      },
      required: ['entities'],
    },
  },
  {
    name: 'reset_entity_risk',
    description:
      "Reset ONE entity's risk score to baseline after it has been investigated — e.g. a confirmed false positive or sanctioned red-team / IT activity. DESTRUCTIVE: it clears the accumulated score (underlying alerts and cases are untouched) and is audit-logged with your reason. Only reset an entity you have actually reviewed; never reset merely to \"clean up\" the leaderboard. Requires the risk:clear permission — the caller's key may not have it.",
    inputSchema: {
      type: 'object' as const,
      properties: {
        entity: {
          type: 'string',
          description: 'Entity value to reset (IP, username, hostname, …)',
        },
        entity_type: {
          type: 'string',
          description: 'Entity type (e.g., "user", "ip", "host")',
        },
        reason: {
          type: 'string',
          description: 'Why the reset is justified (audited). Be specific — this is the record.',
        },
      },
      required: ['entity', 'reason'],
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

      case 'get_entity_risk_activity': {
        const entities = (args.entities as { entity: string; entity_type: string }[]) ?? [];
        const res = await client.getEntityRiskActivity(entities);
        if (!res.success) return err(res.error?.message ?? 'Failed to get entity risk activity');
        return ok(res.data);
      }

      case 'reset_entity_risk': {
        const res = await client.clearEntityRisk({
          entity: args.entity as string,
          entity_type: args.entity_type as string | undefined,
          reason: args.reason as string | undefined,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to reset entity risk');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

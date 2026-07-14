/**
 * Detection rule inspection tools (read-only)
 * Write operations stay in nanodac — this is the operations/SOC view.
 */

import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'list_detections',
    description:
      'List all detection rules from nano. Returns summary view: id, name, severity, mode, enabled status, match count. Use get_detection for full rule details including query and ai_triage_hints.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'informational'],
          description: 'Filter by severity level',
        },
        mode: {
          type: 'string',
          enum: ['staging', 'live', 'alerting'],
          description: 'Filter by rule mode (staging → live → alerting lifecycle)',
        },
        enabled: {
          type: 'boolean',
          description: 'Filter by enabled/disabled status',
        },
      },
    },
  },
  {
    name: 'get_detection',
    description:
      'Get full detection rule details including the nPL query, MITRE ATT&CK mapping, ai_triage_hints (ignore_when/suspicious_when guidance), schedule, and match statistics. Essential for understanding what triggered an alert.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Detection rule ID (UUID)',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'get_detection_matches',
    description:
      'Get recent matches for a specific detection rule. Shows what the rule has been catching, including matched events. Useful for assessing rule quality and noise level.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Detection rule ID (UUID)',
        },
      },
      required: ['id'],
    },
  },
];

export async function handleDetectionsTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'list_detections': {
        const res = await client.listDetections();
        if (!res.success) return err(res.error?.message ?? 'Failed to list detections');

        let rules = res.data ?? [];

        if (args.severity) {
          rules = rules.filter((r) => r.severity === args.severity);
        }
        if (args.mode) {
          rules = rules.filter((r) => r.mode === args.mode);
        }
        if (args.enabled !== undefined) {
          rules = rules.filter((r) => r.enabled === args.enabled);
        }

        const summary = rules.map((r) => ({
          id: r.id,
          name: r.name,
          severity: r.severity,
          mode: r.mode,
          enabled: r.enabled,
          match_count: r.match_count,
          last_match_at: r.last_match_at,
          mitre_techniques: r.mitre_techniques,
        }));

        return ok(summary);
      }

      case 'get_detection': {
        const res = await client.getDetection(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to get detection');
        return ok(res.data);
      }

      case 'get_detection_matches': {
        const res = await client.getDetectionMatches(args.id as string);
        if (!res.success) return err(res.error?.message ?? 'Failed to get detection matches');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

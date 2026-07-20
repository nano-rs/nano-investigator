/**
 * MITRE ATT&CK tools — technique context and detection coverage
 */

import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'get_mitre_technique',
    annotations: { readOnlyHint: true },
    description:
      'Get MITRE ATT&CK data including all techniques and tactics. Returns the full ATT&CK framework data with technique details, descriptions, and mappings. Use this to understand what adversary behaviors look like and how they map to detection rules.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'MITRE technique ID (e.g., "T1071", "T1059.001") — optional, returns all data if not specified',
        },
      },
    },
  },
  {
    name: 'get_mitre_coverage',
    annotations: { readOnlyHint: true },
    description:
      'Get detection coverage mapped to the MITRE ATT&CK framework. Shows which techniques have detection rules, total vs covered technique counts, and coverage percentage. Identifies gaps in detection coverage.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
];

export async function handleMitreTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'get_mitre_technique': {
        const res = await client.getMitreData();
        if (!res.success) return err(res.error?.message ?? 'Failed to get MITRE data');

        // If a specific technique ID was requested, filter the data
        if (args.id) {
          const techniqueId = (args.id as string).toUpperCase();
          const data = res.data as Record<string, unknown>;

          // Search through the MITRE data for the specific technique
          if (data.techniques && Array.isArray(data.techniques)) {
            const technique = (data.techniques as Array<{ id: string }>).find(
              (t) => t.id === techniqueId
            );
            if (technique) return ok(technique);
          }

          return err(`Technique ${techniqueId} not found`);
        }

        return ok(res.data);
      }

      case 'get_mitre_coverage': {
        const res = await client.getMitreCoverage();
        if (!res.success) return err(res.error?.message ?? 'Failed to get MITRE coverage');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

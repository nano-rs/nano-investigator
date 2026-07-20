/**
 * System context tools — environmental awareness
 */

import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'get_source_types',
    annotations: { readOnlyHint: true },
    description:
      'Get available log source types in the SIEM. Essential for building correct queries — knowing what source types exist (e.g., "windows_security", "sysmon", "firewall_paloalto") determines which fields and events are available. Call this before building queries for unfamiliar data types.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_org_context',
    annotations: { readOnlyHint: true },
    description:
      'Get organizational context: company name, industry, compliance frameworks, internal IP ranges, critical assets, and business hours. This context helps tailor investigations — e.g., activity outside business hours may be more suspicious, internal IP ranges help distinguish internal vs external traffic.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'health_check',
    annotations: { readOnlyHint: true },
    description:
      'Check SIEM health status including ClickHouse and PostgreSQL connectivity. Use this to verify the system is operational before running searches, or to diagnose why queries may be failing.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_audit_trail',
    annotations: { readOnlyHint: true },
    description:
      'Query the SIEM audit trail. Shows all security-relevant actions including searches executed, alerts triaged, cases created/updated, and detection rule changes. Filter by user, action type, resource type, time range, and success/failure. Also tracks Claude\'s own actions through the MCP server.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        user_id: {
          type: 'string',
          description: 'Filter by user ID',
        },
        action: {
          type: 'string',
          description: 'Filter by action type (e.g., "search:execute", "alert:close", "case:create")',
        },
        resource_type: {
          type: 'string',
          description: 'Filter by resource type (e.g., "alert", "case", "detection")',
        },
        start_time: {
          type: 'string',
          description: 'Start time filter (ISO 8601)',
        },
        end_time: {
          type: 'string',
          description: 'End time filter (ISO 8601)',
        },
        limit: {
          type: 'number',
          description: 'Maximum entries to return (default: 50)',
        },
      },
    },
  },
];

export async function handleSystemTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'get_source_types': {
        const res = await client.getSourceTypes();
        if (!res.success) return err(res.error?.message ?? 'Failed to get source types');
        return ok(res.data);
      }

      case 'get_org_context': {
        const res = await client.getOrgContext();
        if (!res.success) return err(res.error?.message ?? 'Failed to get organizational context');
        return ok(res.data);
      }

      case 'health_check': {
        const res = await client.healthCheck();
        if (!res.success) return err(res.error?.message ?? 'Health check failed');
        return ok(res.data);
      }

      case 'get_audit_trail': {
        const res = await client.getAuditTrail({
          user_id: args.user_id as string | undefined,
          action: args.action as string | undefined,
          resource_type: args.resource_type as string | undefined,
          start_time: args.start_time as string | undefined,
          end_time: args.end_time as string | undefined,
          limit: (args.limit as number) ?? 50,
        });
        if (!res.success) return err(res.error?.message ?? 'Failed to get audit trail');
        return ok(res.data);
      }

      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

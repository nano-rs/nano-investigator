import type { NanosiemClient, CaseStatus } from '@nano-investigator/core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'list_cases',
    description:
      'List cases with optional filters for status, severity, assignee, search text, and tags. Returns paginated case list with alert/entity counts.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        status: {
          type: 'array',
          items: { type: 'string', enum: ['open', 'in_progress', 'pending', 'resolved', 'closed'] },
          description: 'Filter by case status(es)',
        },
        severity: {
          type: 'array',
          items: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'informational'] },
          description: 'Filter by severity level(s)',
        },
        assigned_to: {
          type: 'string',
          description: 'Filter by assigned user ID',
        },
        search: {
          type: 'string',
          description: 'Free-text search across case title and description',
        },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'Filter by tag(s)',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of cases to return',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination',
        },
      },
    },
  },
  {
    name: 'get_case',
    description:
      'Get full case detail including linked alerts, extracted entities, related cases, and investigation stats.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Case ID',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'review_case',
    description:
      'Load full investigation context for a case in a single call. Returns the case details, case wall history, and all linked notebooks with their entries. Use this as the FIRST tool call when an analyst wants to review, continue, or investigate an existing case — it loads all prior findings so you can pick up where the investigation left off.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Case ID or case number',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'get_case_stats',
    description:
      'Get case workload overview: counts by status and severity, average resolution time.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_related_cases',
    description:
      'Find historically similar cases based on shared entities, rules, and MITRE techniques. Useful for identifying patterns and prior investigations.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Case ID to find related cases for',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'create_case',
    description:
      'Create a new investigation case. Cases group related alerts and track investigation progress.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        title: {
          type: 'string',
          description: 'Case title describing the investigation',
        },
        description: {
          type: 'string',
          description: 'Detailed description of the case',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'informational'],
          description: 'Case severity level',
        },
        priority: {
          type: 'number',
          description: 'Priority (1 = highest)',
        },
        assigned_to: {
          type: 'string',
          description: 'User ID to assign the case to',
        },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'Tags for categorization',
        },
      },
      required: ['title', 'severity'],
    },
  },
  {
    name: 'update_case',
    description:
      'Update case metadata such as title, description, severity, or tags.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Case ID to update',
        },
        title: {
          type: 'string',
          description: 'New case title',
        },
        description: {
          type: 'string',
          description: 'New case description',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'informational'],
          description: 'New severity level',
        },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'New tags (replaces existing)',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'change_case_status',
    description:
      'Update case status with optional disposition. Use disposition when resolving or closing a case to record the outcome.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Case ID',
        },
        status: {
          type: 'string',
          enum: ['open', 'in_progress', 'pending', 'resolved', 'closed'],
          description: 'New case status',
        },
        disposition: {
          type: 'string',
          enum: ['true_positive', 'false_positive', 'benign', 'inconclusive'],
          description: 'Case disposition (typically set when resolving/closing)',
        },
      },
      required: ['id', 'status'],
    },
  },
  {
    name: 'assign_case',
    description: 'Assign a case to a user for investigation.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Case ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to assign the case to',
        },
      },
      required: ['id', 'user_id'],
    },
  },
  {
    name: 'add_alert_to_case',
    description:
      'Link an alert to a case. Alerts provide the detection evidence for a case investigation.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        case_id: {
          type: 'string',
          description: 'Case ID to add the alert to',
        },
        alert_id: {
          type: 'string',
          description: 'Alert ID to link',
        },
        is_primary: {
          type: 'boolean',
          description: 'Whether this is the primary/triggering alert for the case',
        },
      },
      required: ['case_id', 'alert_id'],
    },
  },
  {
    name: 'add_case_wall_entry',
    description:
      'Add an investigation finding, comment, or action record to the case wall. The case wall is the chronological log of investigation activity.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        case_id: {
          type: 'string',
          description: 'Case ID',
        },
        entry_type: {
          type: 'string',
          enum: ['comment', 'ai_analysis', 'action_taken'],
          description: 'Type of wall entry',
        },
        content: {
          type: 'string',
          description: 'Entry content (markdown supported)',
        },
        is_internal: {
          type: 'boolean',
          description: 'If true, entry is only visible to internal team (not shared externally)',
        },
      },
      required: ['case_id', 'entry_type', 'content'],
    },
  },
  {
    name: 'merge_cases',
    description:
      'Merge duplicate or related cases into a single target case. Source case alerts, entities, and wall entries are moved to the target.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target_case_id: {
          type: 'string',
          description: 'Case ID to merge into (the surviving case)',
        },
        source_case_ids: {
          type: 'array',
          items: { type: 'string' },
          description: 'Case IDs to merge from (these cases will be closed as merged)',
        },
      },
      required: ['target_case_id', 'source_case_ids'],
    },
  },
];

export async function handleCasesTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient,
): Promise<ToolResult> {
  try {
  switch (name) {
    case 'list_cases': {
      const res = await client.listCases({
        status: args.status as CaseStatus[] | undefined,
        severity: args.severity as string[] | undefined,
        assigned_to: args.assigned_to as string | undefined,
        search: args.search as string | undefined,
        tags: args.tags as string[] | undefined,
        limit: args.limit as number | undefined,
        offset: args.offset as number | undefined,
      });
      if (!res.success) return err(`Failed to list cases: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'get_case': {
      const id = args.id as string;
      const res = await client.getCase(id);
      if (!res.success) return err(`Failed to get case ${id}: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'review_case': {
      const id = args.id as string;

      // Fetch case details, wall, and linked notebooks in parallel
      const [caseRes, wallRes, notebooksRes] = await Promise.all([
        client.getCase(id),
        client.getCaseWall(id),
        client.listNotebooks({ case_id: id }),
      ]);

      if (!caseRes.success) return err(`Failed to get case ${id}: ${caseRes.error?.message}`);

      const errors: string[] = [];
      if (!wallRes.success) errors.push(`Case wall: ${wallRes.error?.message}`);
      if (!notebooksRes.success) errors.push(`Notebooks list: ${notebooksRes.error?.message}`);

      // Fetch notebook details in batches of 5 to avoid overwhelming the API
      const notebooks = notebooksRes.success && notebooksRes.data ? notebooksRes.data : [];
      const BATCH_SIZE = 5;
      const notebookDetails: Array<{
        notebook: (typeof notebooks)[number];
        entries: unknown[];
        references: unknown[];
        errors?: string[];
      }> = [];

      for (let i = 0; i < notebooks.length; i += BATCH_SIZE) {
        const batch = notebooks.slice(i, i + BATCH_SIZE);
        const batchResults = await Promise.all(
          batch.map(async (nb) => {
            const [entriesRes, refsRes] = await Promise.all([
              client.getNotebookEntries(nb.id),
              client.getNotebookReferences(nb.id),
            ]);
            const nbErrors: string[] = [];
            if (!entriesRes.success) nbErrors.push(`Entries: ${entriesRes.error?.message}`);
            if (!refsRes.success) nbErrors.push(`References: ${refsRes.error?.message}`);
            return {
              notebook: nb,
              entries: entriesRes.success && entriesRes.data ? entriesRes.data : [],
              references: refsRes.success && refsRes.data ? refsRes.data : [],
              ...(nbErrors.length > 0 ? { errors: nbErrors } : {}),
            };
          })
        );
        notebookDetails.push(...batchResults);
      }

      return ok({
        case: caseRes.data,
        wall: wallRes.success ? wallRes.data : [],
        notebooks: notebookDetails,
        ...(errors.length > 0 ? { errors } : {}),
      });
    }

    case 'get_case_stats': {
      const res = await client.getCaseStats();
      if (!res.success) return err(`Failed to get case stats: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'get_related_cases': {
      const id = args.id as string;
      const res = await client.getRelatedCases(id);
      if (!res.success) return err(`Failed to get related cases for ${id}: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'create_case': {
      const res = await client.createCase({
        title: args.title as string,
        description: args.description as string | undefined,
        severity: args.severity as 'critical' | 'high' | 'medium' | 'low' | 'informational',
        priority: args.priority as number | undefined,
        assigned_to: args.assigned_to as string | undefined,
        tags: args.tags as string[] | undefined,
      });
      if (!res.success) return err(`Failed to create case: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'update_case': {
      const id = args.id as string;
      const req: Record<string, unknown> = {};
      if (args.title !== undefined) req.title = args.title;
      if (args.description !== undefined) req.description = args.description;
      if (args.severity !== undefined) req.severity = args.severity;
      if (args.tags !== undefined) req.tags = args.tags;
      const res = await client.updateCase(id, req as {
        title?: string;
        description?: string;
        severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational';
        tags?: string[];
      });
      if (!res.success) return err(`Failed to update case ${id}: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'change_case_status': {
      const id = args.id as string;
      const res = await client.changeCaseStatus(id, {
        status: args.status as 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed',
        disposition: args.disposition as 'true_positive' | 'false_positive' | 'benign' | 'inconclusive' | undefined,
      });
      if (!res.success) return err(`Failed to change status for case ${id}: ${res.error?.message}`);
      return ok({ success: true, case_id: id, status: args.status, disposition: args.disposition });
    }

    case 'assign_case': {
      const id = args.id as string;
      const userId = args.user_id as string;
      const res = await client.assignCase(id, userId);
      if (!res.success) return err(`Failed to assign case ${id}: ${res.error?.message}`);
      return ok({ success: true, case_id: id, assigned_to: userId });
    }

    case 'add_alert_to_case': {
      const caseId = args.case_id as string;
      const res = await client.addAlertToCase(caseId, {
        alert_id: args.alert_id as string,
        is_primary: args.is_primary as boolean | undefined,
      });
      if (!res.success) return err(`Failed to add alert to case ${caseId}: ${res.error?.message}`);
      return ok({ success: true, case_id: caseId, alert_id: args.alert_id });
    }

    case 'add_case_wall_entry': {
      const caseId = args.case_id as string;
      const res = await client.addCaseWallEntry(caseId, {
        entry_type: args.entry_type as 'comment' | 'ai_analysis' | 'action_taken',
        content: args.content as string,
        is_internal: args.is_internal as boolean | undefined,
      });
      if (!res.success) return err(`Failed to add wall entry to case ${caseId}: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'merge_cases': {
      const targetId = args.target_case_id as string;
      const res = await client.mergeCases(targetId, {
        source_case_ids: args.source_case_ids as string[],
      });
      if (!res.success) return err(`Failed to merge cases into ${targetId}: ${res.error?.message}`);
      return ok({ success: true, target_case_id: targetId, source_case_ids: args.source_case_ids });
    }

    default:
      return err(`Unknown cases tool: ${name}`);
  }
  } catch (error) {
    return err(error instanceof Error ? error.message : String(error));
  }
}

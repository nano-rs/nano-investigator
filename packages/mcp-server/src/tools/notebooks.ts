import type { NanosiemClient } from '@nano-rs/investigator-core';
import { type ToolResult, ok, err } from './utils.js';

export const TOOLS = [
  {
    name: 'list_notebooks',
    annotations: { readOnlyHint: true },
    description:
      'List investigation notebooks with optional filters. Returns notebooks with owner info and entry counts.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        case_id: {
          type: 'string',
          description: 'Filter notebooks linked to a specific case',
        },
        status: {
          type: 'string',
          enum: ['active', 'paused', 'closed', 'merged'],
          description: 'Filter by notebook status',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of notebooks to return',
        },
        offset: {
          type: 'number',
          description: 'Number of notebooks to skip for pagination',
        },
      },
    },
  },
  {
    name: 'get_notebook',
    annotations: { readOnlyHint: true },
    description:
      'Get a single notebook by ID, including metadata, owner info, and entry count.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Notebook ID',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'get_notebook_entries',
    annotations: { readOnlyHint: true },
    description:
      'Read all entries in a notebook. Returns chronological list of notes, searches, AI suggestions, IOC markers, timeline markers, and other entry types.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Notebook ID',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'find_notebooks_by_reference',
    annotations: { readOnlyHint: true },
    description:
      'Find notebooks that reference a specific entity such as an alert, detection rule, saved search, or case. Useful for discovering related investigations.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        reference_type: {
          type: 'string',
          enum: ['alert', 'detection', 'saved_search', 'case'],
          description: 'Type of the referenced entity',
        },
        reference_id: {
          type: 'string',
          description: 'ID of the referenced entity',
        },
      },
      required: ['reference_type', 'reference_id'],
    },
  },
  {
    name: 'create_notebook',
    description:
      'Create a new investigation notebook. Notebooks track the investigative process including searches, findings, and analyst notes.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        title: {
          type: 'string',
          description: 'Title of the notebook',
        },
        visibility: {
          type: 'string',
          enum: ['private', 'shared', 'public'],
          description:
            'Visibility level. Defaults to private if not specified.',
        },
      },
      required: ['title'],
    },
  },
  {
    name: 'add_notebook_entry',
    description:
      'Add an entry to a notebook. Entries capture investigation steps such as manual notes, executed searches, AI suggestions, IOC markers, and timeline events.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        notebook_id: {
          type: 'string',
          description: 'ID of the notebook to add the entry to',
        },
        entry_type: {
          type: 'string',
          enum: [
            'manual_note',
            'search_executed',
            'ai_suggestion',
            'ai_summary',
            'entity_reference',
            'ioc_marker',
            'timeline_marker',
            'investigation_timeline',
          ],
          description: 'Type of notebook entry',
        },
        content: {
          type: 'object',
          description:
            'Entry content. Structure varies by entry_type (e.g. { text: "..." } for manual_note, { query: "...", results_summary: "..." } for search_executed)',
        },
        source_url: {
          type: 'string',
          description:
            'Optional URL linking back to the source of this entry (e.g. a search results page)',
        },
      },
      required: ['notebook_id', 'entry_type', 'content'],
    },
  },
  {
    name: 'add_notebook_reference',
    description:
      'Link an entity or artifact to a notebook for cross-referencing. Creates a bidirectional link between the notebook and an alert, detection, saved search, or case.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        notebook_id: {
          type: 'string',
          description: 'ID of the notebook',
        },
        reference_type: {
          type: 'string',
          enum: ['alert', 'detection', 'saved_search', 'case'],
          description: 'Type of entity being referenced',
        },
        reference_id: {
          type: 'string',
          description: 'ID of the entity being referenced',
        },
        reference_name: {
          type: 'string',
          description:
            'Optional human-readable name for the reference (e.g. rule name, alert title)',
        },
      },
      required: ['notebook_id', 'reference_type', 'reference_id'],
    },
  },
  {
    name: 'update_notebook',
    description:
      'Update notebook metadata such as title, status, or summary. Use this to close notebooks, pause investigations, or update the investigation summary.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Notebook ID',
        },
        title: {
          type: 'string',
          description: 'New title for the notebook',
        },
        status: {
          type: 'string',
          enum: ['active', 'paused', 'closed'],
          description: 'New status for the notebook',
        },
        summary: {
          type: 'string',
          description: 'Investigation summary or conclusion',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'share_notebook',
    description:
      'Change the sharing settings of a notebook. Control who can view the notebook by setting visibility and optionally specifying group access.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'string',
          description: 'Notebook ID',
        },
        visibility: {
          type: 'string',
          enum: ['private', 'shared', 'public'],
          description: 'New visibility level for the notebook',
        },
        group_ids: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Group IDs to share with when visibility is "shared"',
        },
      },
      required: ['id', 'visibility'],
    },
  },
];

export async function handleNotebooksTool(
  name: string,
  args: Record<string, unknown>,
  client: NanosiemClient,
): Promise<ToolResult> {
  switch (name) {
    case 'list_notebooks': {
      const params: Record<string, unknown> = {};
      if (args.case_id !== undefined) params.case_id = args.case_id;
      if (args.status !== undefined) params.status = args.status;
      if (args.limit !== undefined) params.limit = args.limit;
      if (args.offset !== undefined) params.offset = args.offset;

      const res = await client.listNotebooks(
        params as Parameters<typeof client.listNotebooks>[0],
      );
      if (!res.success) return err(`Failed to list notebooks: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'get_notebook': {
      const id = args.id as string;
      if (!id) return err('Missing required argument: id');

      const res = await client.getNotebook(id);
      if (!res.success) return err(`Failed to get notebook: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'get_notebook_entries': {
      const id = args.id as string;
      if (!id) return err('Missing required argument: id');

      const res = await client.getNotebookEntries(id);
      if (!res.success) return err(`Failed to get notebook entries: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'find_notebooks_by_reference': {
      const referenceType = args.reference_type as string;
      const referenceId = args.reference_id as string;
      if (!referenceType) return err('Missing required argument: reference_type');
      if (!referenceId) return err('Missing required argument: reference_id');

      const res = await client.findNotebooksByReference(referenceType, referenceId);
      if (!res.success)
        return err(`Failed to find notebooks by reference: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'create_notebook': {
      const title = args.title as string;
      if (!title) return err('Missing required argument: title');

      const req: Record<string, unknown> = { title };
      if (args.visibility !== undefined) req.visibility = args.visibility;

      const res = await client.createNotebook(
        req as unknown as Parameters<typeof client.createNotebook>[0],
      );
      if (!res.success) return err(`Failed to create notebook: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'add_notebook_entry': {
      const notebookId = args.notebook_id as string;
      const entryType = args.entry_type as string;
      const content = args.content as Record<string, unknown>;
      if (!notebookId) return err('Missing required argument: notebook_id');
      if (!entryType) return err('Missing required argument: entry_type');
      if (!content) return err('Missing required argument: content');

      const req: Record<string, unknown> = {
        entry_type: entryType,
        content,
      };
      if (args.source_url !== undefined) req.source_url = args.source_url;

      const res = await client.addNotebookEntry(
        notebookId,
        req as unknown as Parameters<typeof client.addNotebookEntry>[1],
      );
      if (!res.success) return err(`Failed to add notebook entry: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'add_notebook_reference': {
      const notebookId = args.notebook_id as string;
      const referenceType = args.reference_type as string;
      const referenceId = args.reference_id as string;
      if (!notebookId) return err('Missing required argument: notebook_id');
      if (!referenceType) return err('Missing required argument: reference_type');
      if (!referenceId) return err('Missing required argument: reference_id');

      const req: Record<string, unknown> = {
        reference_type: referenceType,
        reference_id: referenceId,
      };
      if (args.reference_name !== undefined) req.reference_name = args.reference_name;

      const res = await client.addNotebookReference(
        notebookId,
        req as unknown as Parameters<typeof client.addNotebookReference>[1],
      );
      if (!res.success)
        return err(`Failed to add notebook reference: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'update_notebook': {
      const id = args.id as string;
      if (!id) return err('Missing required argument: id');

      const req: Record<string, unknown> = {};
      if (args.title !== undefined) req.title = args.title;
      if (args.status !== undefined) req.status = args.status;
      if (args.summary !== undefined) req.summary = args.summary;

      const res = await client.updateNotebook(
        id,
        req as Parameters<typeof client.updateNotebook>[1],
      );
      if (!res.success) return err(`Failed to update notebook: ${res.error?.message}`);
      return ok(res.data);
    }

    case 'share_notebook': {
      const id = args.id as string;
      const visibility = args.visibility as string;
      if (!id) return err('Missing required argument: id');
      if (!visibility) return err('Missing required argument: visibility');

      const req: Record<string, unknown> = { visibility };
      if (args.group_ids !== undefined) req.group_ids = args.group_ids;

      const res = await client.shareNotebook(
        id,
        req as unknown as Parameters<typeof client.shareNotebook>[1],
      );
      if (!res.success) return err(`Failed to share notebook: ${res.error?.message}`);
      return ok(res.data);
    }

    default:
      return err(`Unknown notebooks tool: ${name}`);
  }
}

/**
 * nano-hunt MCP server — LOCAL lead capture for an unattended hunt sweep.
 *
 * The sweep runs on the analyst's own coding CLI and calls `record_lead` each time
 * it finds something worth an analyst's attention; each call appends one JSONL line
 * to the file named by NANO_HUNT_LEADS_FILE, flushed immediately. A sweep killed at
 * turn 30 keeps every lead it had already recorded — partial capture is the point.
 * `note_trail` and `record_knowledge` write to the same file, discriminated by a
 * `kind` — knowledge goes out this way rather than to the API because recording it
 * server-side needs `hunts:report`, which this agent must never hold.
 *
 * Deliberately minimal and self-contained, modelled on nano-recon / nano-artifacts:
 * NO nano API client, NO API key, NO network, NO subprocesses, NO file reads. It
 * appends to one file and does nothing else — the least privileged component in the
 * system, because the agent holding it has attacker-authored log content in its
 * context. See leads.ts for the confinement and the caps.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { TOOLS, handleHuntTool } from './leads.js';

const server = new Server(
  { name: 'nano-hunt', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return handleHuntTool(name, (args ?? {}) as Record<string, unknown>);
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('nano-hunt MCP server started');
  console.error(`Tools: ${TOOLS.length} (${TOOLS.map((t) => t.name).join(', ')})`);
  // Say it at startup too: a sweep whose runner forgot the env var should be
  // obvious in the CLI's stderr, not only in the first failed tool call.
  console.error(
    process.env.NANO_HUNT_LEADS_FILE
      ? `Leads file: ${process.env.NANO_HUNT_LEADS_FILE}`
      : 'NANO_HUNT_LEADS_FILE is NOT set — every record_lead / note_trail / record_knowledge call will fail.'
  );
}

main().catch((error) => {
  console.error('Fatal:', error);
  process.exit(1);
});

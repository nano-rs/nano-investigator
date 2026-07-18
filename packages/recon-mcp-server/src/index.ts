/**
 * nano-recon MCP server — LOCAL recon tools (whois / DNS / ASN) that pivt can call
 * during an investigation to get live data from the analyst's own machine.
 *
 * Deliberately minimal and self-contained: NO nano API client, NO API key, NO
 * network config. It only shells out to the analyst's local `whois` / `dig` with
 * validated arguments (see recon.ts). Spawned over stdio like any MCP server.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { TOOLS, handleReconTool } from './recon.js';

const server = new Server(
  { name: 'nano-recon', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return handleReconTool(name, (args ?? {}) as Record<string, unknown>);
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('nano-recon MCP server started');
  console.error(`Tools: ${TOOLS.length} (whois, dns_lookup, reverse_dns, asn_lookup)`);
}

main().catch((error) => {
  console.error('Fatal:', error);
  process.exit(1);
});

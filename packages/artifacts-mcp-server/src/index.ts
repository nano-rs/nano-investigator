/**
 * nano-artifacts MCP server — LOCAL static-analysis tools for a file specimen that
 * pivt can call while triaging an Artifact.
 *
 * Deliberately minimal and self-contained, modelled on nano-recon: NO nano API
 * client, NO API key, NO network config. It only reads a LOCAL specimen file (the
 * raw bytes the desktop stashed in a temp dir on the analyst's own machine) and
 * shells out to the analyst's local triage binaries (exiftool / file / yara /
 * olevba / pdfid / python-pefile) with argv-only, validated arguments. The raw
 * bytes never leave the machine; pivt persists only the extracted findings.
 *
 * Because it acts on attacker-controlled specimen bytes, it runs KEY-LESS (like
 * recon) — a specimen that tricks a tool cannot reach the nano API. Every tool is
 * read-only, timed out, and output-capped, and degrades gracefully when the
 * underlying binary is not installed (`capabilities` reports what is available).
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { TOOLS, handleArtifactTool } from './analyze.js';

const server = new Server(
  { name: 'nano-artifacts', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return handleArtifactTool(name, (args ?? {}) as Record<string, unknown>);
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('nano-artifacts MCP server started');
  console.error(`Tools: ${TOOLS.length} (${TOOLS.map((t) => t.name).join(', ')})`);
}

main().catch((error) => {
  console.error('Fatal:', error);
  process.exit(1);
});

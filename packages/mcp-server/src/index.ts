/**
 * nano-investigator MCP Server
 *
 * SOC operations MCP server for nano — search, triage, investigate, hunt.
 */

import { existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';

/**
 * Load environment variables from .env file
 */
function loadEnvFile(startDir: string, maxDepth = 3): void {
  const envFiles = ['.env', '.env.local'];
  let currentDir = startDir;
  let depth = 0;

  while (currentDir !== '/' && depth < maxDepth) {
    for (const envFile of envFiles) {
      const envPath = join(currentDir, envFile);
      if (existsSync(envPath)) {
        try {
          const content = readFileSync(envPath, 'utf-8');
          for (const line of content.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;

            const eqIndex = trimmed.indexOf('=');
            if (eqIndex > 0) {
              const key = trimmed.slice(0, eqIndex).trim();
              let value = trimmed.slice(eqIndex + 1).trim();

              if (
                (value.startsWith('"') && value.endsWith('"')) ||
                (value.startsWith("'") && value.endsWith("'"))
              ) {
                value = value.slice(1, -1);
              }

              if (!process.env[key]) {
                process.env[key] = value;
              }
            }
          }
        } catch {
          // Ignore errors reading .env file
        }
        return;
      }
    }
    currentDir = dirname(currentDir);
    depth++;
  }
}

// Load .env file from cwd
loadEnvFile(process.cwd());

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { NanosiemClient } from '@nano-rs/investigator-core';

// Tools
import { TOOLS as SEARCH_TOOLS, handleSearchTool } from './tools/search.js';
import { TOOLS as ALERTS_TOOLS, handleAlertsTool } from './tools/alerts.js';
import { TOOLS as CASES_TOOLS, handleCasesTool } from './tools/cases.js';
import { TOOLS as NOTEBOOKS_TOOLS, handleNotebooksTool } from './tools/notebooks.js';
import { TOOLS as DETECTIONS_TOOLS, handleDetectionsTool } from './tools/detections.js';
import { TOOLS as PREVALENCE_TOOLS, handlePrevalenceTool } from './tools/prevalence.js';
import { TOOLS as RISK_TOOLS, handleRiskTool } from './tools/risk.js';
import { TOOLS as ENRICHMENT_TOOLS, handleEnrichmentTool } from './tools/enrichment.js';
import { TOOLS as MITRE_TOOLS, handleMitreTool } from './tools/mitre.js';
import { TOOLS as SYSTEM_TOOLS, handleSystemTool } from './tools/system.js';
import { TOOLS as PARSERS_TOOLS, handleParsersTool } from './tools/parsers.js';

// Resources
import { UDM_SCHEMA_RESOURCE, UDM_SCHEMA_CONTENT, UDM_SCHEMA_URI } from './resources/udm-schema.js';
import { NPL_REFERENCE_RESOURCE, NPL_REFERENCE_CONTENT, NPL_REFERENCE_URI } from './resources/npl-reference.js';
import { SQL_GUIDE_RESOURCE, SQL_GUIDE_CONTENT, SQL_GUIDE_URI } from './resources/sql-guide.js';
import { VRL_PARSERS_RESOURCE, VRL_PARSERS_CONTENT, VRL_PARSERS_URI } from './resources/vrl-parsers.js';
import { getPlaybookResources, getPlaybookContent, PLAYBOOK_URI_PREFIX } from './resources/playbooks.js';

// Prompts
import { INVESTIGATE_PROMPT, getInvestigatePrompt } from './prompts/investigate.js';
import { HUNT_ENTITY_PROMPT, HUNT_CAMPAIGN_PROMPT, getHuntEntityPrompt, getHuntCampaignPrompt } from './prompts/hunt.js';
import { MORNING_BRIEFING_PROMPT, getMorningBriefingPrompt } from './prompts/triage.js';
import { BUILD_PARSER_PROMPT, getBuildParserPrompt } from './prompts/build-parser.js';

// ==================== Tool Registry ====================

const ALL_TOOLS = [
  ...SEARCH_TOOLS,
  ...ALERTS_TOOLS,
  ...CASES_TOOLS,
  ...NOTEBOOKS_TOOLS,
  ...DETECTIONS_TOOLS,
  ...PREVALENCE_TOOLS,
  ...RISK_TOOLS,
  ...ENRICHMENT_TOOLS,
  ...MITRE_TOOLS,
  ...SYSTEM_TOOLS,
  ...PARSERS_TOOLS,
];

// Map tool names to their category handler
const SEARCH_TOOL_NAMES = new Set(SEARCH_TOOLS.map((t) => t.name));
const ALERTS_TOOL_NAMES = new Set(ALERTS_TOOLS.map((t) => t.name));
const CASES_TOOL_NAMES = new Set(CASES_TOOLS.map((t) => t.name));
const NOTEBOOKS_TOOL_NAMES = new Set(NOTEBOOKS_TOOLS.map((t) => t.name));
const DETECTIONS_TOOL_NAMES = new Set(DETECTIONS_TOOLS.map((t) => t.name));
const PREVALENCE_TOOL_NAMES = new Set(PREVALENCE_TOOLS.map((t) => t.name));
const RISK_TOOL_NAMES = new Set(RISK_TOOLS.map((t) => t.name));
const ENRICHMENT_TOOL_NAMES = new Set(ENRICHMENT_TOOLS.map((t) => t.name));
const MITRE_TOOL_NAMES = new Set(MITRE_TOOLS.map((t) => t.name));
const SYSTEM_TOOL_NAMES = new Set(SYSTEM_TOOLS.map((t) => t.name));
const PARSERS_TOOL_NAMES = new Set(PARSERS_TOOLS.map((t) => t.name));

// ==================== Client Setup ====================

let _client: NanosiemClient | null = null;

function getClient(): NanosiemClient {
  if (_client) return _client;

  const apiUrl = process.env.NANOSIEM_API_URL;
  const apiKey = process.env.NANOSIEM_API_KEY;
  const searchUrl = process.env.NANOSIEM_SEARCH_URL;

  if (!apiUrl) {
    throw new Error(
      'NANOSIEM_API_URL environment variable is required. Set it to your nano API URL (e.g., https://nanosiem.example.com:3000)'
    );
  }
  if (!apiKey) {
    throw new Error(
      'NANOSIEM_API_KEY environment variable is required. Set it to your nano API key.'
    );
  }

  _client = new NanosiemClient({ apiUrl, searchUrl, apiKey });
  return _client;
}

// ==================== Server Setup ====================

const server = new Server(
  {
    name: 'nano-investigator',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  }
);

// ==================== Tool Handlers ====================

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: ALL_TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const toolArgs = (args || {}) as Record<string, unknown>;
  const client = getClient();

  if (SEARCH_TOOL_NAMES.has(name)) return handleSearchTool(name, toolArgs, client);
  if (ALERTS_TOOL_NAMES.has(name)) return handleAlertsTool(name, toolArgs, client);
  if (CASES_TOOL_NAMES.has(name)) return handleCasesTool(name, toolArgs, client);
  if (NOTEBOOKS_TOOL_NAMES.has(name)) return handleNotebooksTool(name, toolArgs, client);
  if (DETECTIONS_TOOL_NAMES.has(name)) return handleDetectionsTool(name, toolArgs, client);
  if (PREVALENCE_TOOL_NAMES.has(name)) return handlePrevalenceTool(name, toolArgs, client);
  if (RISK_TOOL_NAMES.has(name)) return handleRiskTool(name, toolArgs, client);
  if (ENRICHMENT_TOOL_NAMES.has(name)) return handleEnrichmentTool(name, toolArgs, client);
  if (MITRE_TOOL_NAMES.has(name)) return handleMitreTool(name, toolArgs, client);
  if (SYSTEM_TOOL_NAMES.has(name)) return handleSystemTool(name, toolArgs, client);
  if (PARSERS_TOOL_NAMES.has(name)) return handleParsersTool(name, toolArgs, client);

  return {
    content: [{ type: 'text', text: `Unknown tool: ${name}` }],
    isError: true,
  };
});

// ==================== Resource Handlers ====================

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    SQL_GUIDE_RESOURCE,
    UDM_SCHEMA_RESOURCE,
    NPL_REFERENCE_RESOURCE,
    VRL_PARSERS_RESOURCE,
    ...getPlaybookResources(),
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  if (uri === SQL_GUIDE_URI) {
    return {
      contents: [{ uri, mimeType: 'text/markdown', text: SQL_GUIDE_CONTENT }],
    };
  }

  if (uri === UDM_SCHEMA_URI) {
    return {
      contents: [{ uri, mimeType: 'text/markdown', text: UDM_SCHEMA_CONTENT }],
    };
  }

  if (uri === NPL_REFERENCE_URI) {
    return {
      contents: [{ uri, mimeType: 'text/markdown', text: NPL_REFERENCE_CONTENT }],
    };
  }

  if (uri === VRL_PARSERS_URI) {
    return {
      contents: [{ uri, mimeType: 'text/markdown', text: VRL_PARSERS_CONTENT }],
    };
  }

  if (uri.startsWith(PLAYBOOK_URI_PREFIX + '/')) {
    const type = uri.slice(PLAYBOOK_URI_PREFIX.length + 1);
    const content = getPlaybookContent(type);
    if (content) {
      return {
        contents: [{ uri, mimeType: 'text/markdown', text: content }],
      };
    }
  }

  throw new Error(`Resource not found: ${uri}`);
});

// ==================== Prompt Handlers ====================

const ALL_PROMPTS = [INVESTIGATE_PROMPT, HUNT_ENTITY_PROMPT, HUNT_CAMPAIGN_PROMPT, MORNING_BRIEFING_PROMPT, BUILD_PARSER_PROMPT];

server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: ALL_PROMPTS,
}));

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const promptArgs = (args || {}) as Record<string, string | undefined>;

  switch (name) {
    case 'investigate_alert':
      return getInvestigatePrompt(promptArgs);
    case 'hunt_entity':
      return getHuntEntityPrompt(promptArgs);
    case 'hunt_campaign':
      return getHuntCampaignPrompt(promptArgs);
    case 'morning_briefing':
      return getMorningBriefingPrompt(promptArgs);
    case 'build_parser':
      return getBuildParserPrompt(promptArgs);
    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
});

// ==================== Start Server ====================

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('nano-investigator MCP server started');
  console.error(`Tools: ${ALL_TOOLS.length}`);
  console.error(`Resources: ${4 + getPlaybookResources().length}`);
  console.error(`Prompts: ${ALL_PROMPTS.length}`);
  console.error('');
  console.error('Required environment variables:');
  console.error('  NANOSIEM_API_URL  - nano API URL (port 3000)');
  console.error('  NANOSIEM_API_KEY  - API key for authentication');
  console.error('  NANOSIEM_SEARCH_URL - Search service URL (port 3002, optional)');
}

main().catch((error) => {
  console.error('Failed to start nano-investigator:', error);
  process.exit(1);
});

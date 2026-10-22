import { AGENT_WINDOW_GUIDANCE } from './agent-window.js';
/**
 * Threat hunting prompts — entity hunting and campaign hunting
 */

export const HUNT_ENTITY_PROMPT = {
  name: 'hunt_entity',
  description:
    'Hunt for all activity related to a specific entity (IP, user, host, domain, or hash). Gathers context, assesses risk, and investigates interesting branches.',
  arguments: [
    {
      name: 'entity',
      description: 'The entity value to hunt (e.g., "10.5.2.40", "jsmith", "workstation-01")',
      required: true,
    },
    {
      name: 'entity_type',
      description: 'Entity type: ip, user, host, domain, or hash',
      required: true,
    },
    {
      name: 'time_range',
      description: 'Time range to search (e.g., "-24h", "-7d"). Default: -24h',
      required: false,
    },
  ],
};

export const HUNT_CAMPAIGN_PROMPT = {
  name: 'hunt_campaign',
  description:
    'Proactive threat hunt for a specific TTP, campaign, or attack pattern. Plans the hunt, builds and runs queries, enriches findings, and produces a hunt report.',
  arguments: [
    {
      name: 'description',
      description: 'Description of what to hunt for (e.g., "DNS tunneling", "credential dumping", "living off the land")',
      required: true,
    },
    {
      name: 'time_range',
      description: 'Time range to search (e.g., "-7d", "-30d"). Default: -24h',
      required: false,
    },
  ],
};

export function getHuntEntityPrompt(args: Record<string, string | undefined>): {
  description: string;
  messages: Array<{ role: 'user'; content: { type: 'text'; text: string } }>;
} {
  const entity = args.entity ?? 'unknown';
  const entityType = args.entity_type ?? 'ip';
  const timeRange = args.time_range ?? '-24h';

  return {
    description: `Hunt entity: ${entity} (${entityType})`,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: `${AGENT_WINDOW_GUIDANCE}

You are hunting for activity related to entity: ${entity} (type: ${entityType})
Time range: ${timeRange}

## Phase 1 — Lake candidates and stamps first
- Discover authorized tables using lake_sql without sql; read the source schema.
- Use scoped lake_sql over sealed hours for ${entity}; inspect prevalence at ingest time (stamp) and ingest threat-intel matches. Use search only for recent unsealed hours.
- Only if current counts or unstamped artifacts (65535) matter, use guarded prevalence for the specific candidate (max 10 values), reason and bounded window.
- Use guarded risk_scores, resolve_identity at the event timestamp, or lookup only to answer a specific remaining question, with a one-sentence reason; never fan out cell enrichment across all hits.

## Phase 2 — Assessment
After gathering context, assess:
- Is this entity expected in this environment?
- What's its risk score?
- What source types have data for it?
- Any existing alerts or cases?
- How common is it? (prevalence)

**Present your Phase 2 findings before proceeding to Phase 3.**

## Phase 3 — Deep Dive (only the interesting branches)
Based on entity type:

**Tool choice for Phase 3 queries:** Use search with canonical OCSF fields and bounded time windows. Read get_schema first. Use lake_sql for sealed hours and bounded cell feature tools for enrichment.

${entityType === 'ip' ? `**IP Investigation:**
- What internal hosts communicated with it? What ports/protocols?
- Is it associated with any known threats? (IOC check)
- Temporal pattern: regular intervals (beaconing)? Burst traffic (exfil)?
- Query: \`dst_endpoint.ip="${entity}" | stats count, sum(traffic.bytes_out) as bytes, dc(src_endpoint.ip) as sources by dst_endpoint.port\`
- Query: \`src_endpoint.ip="${entity}" | stats count, dc(dst_endpoint.ip) as targets by dst_endpoint.port\`` : ''}

${entityType === 'user' ? `**User Investigation:**
- What hosts did they access? Any privilege escalation?
- Off-hours activity?
- Query: \`actor.user.name="${entity}" | stats count, values(dst_endpoint.hostname), values(status) by src_endpoint.ip\`
- Query: \`actor.user.name="${entity}" | where activity_name CONTAINS "privilege" OR action CONTAINS "sudo"\`` : ''}

${entityType === 'host' ? `**Host Investigation:**
- What processes ran? Any rare binaries?
- What network connections? Any unusual destinations?
- Query: \`device.hostname="${entity}" | stats count by process.file.name | sort -count\`
- Query: \`device.hostname="${entity}" | where dst_endpoint.port NOT IN (80, 443, 53) | stats count by dst_endpoint.ip, dst_endpoint.port\`` : ''}

${entityType === 'hash' ? `**Hash Investigation:**
- Prevalence across the environment — how many hosts have this hash?
- When was it first seen? Is it new?
- What process name is associated with it?
- Query: \`file.hashes.value="${entity}" | stats count, dc(device.hostname) as hosts by process.file.name\`` : ''}

${entityType === 'domain' ? `**Domain Investigation:**
- Prevalence — how many hosts resolved this domain?
- DNS query patterns — volume, timing, subdomain enumeration
- Query: \`query.hostname CONTAINS "${entity}" | stats count, dc(src_endpoint.ip) as resolvers, dc(query.hostname) as subdomains by rcode\`` : ''}

Ask the analyst which threads to pull further after presenting Phase 3 findings.`,
        },
      },
    ],
  };
}

export function getHuntCampaignPrompt(args: Record<string, string | undefined>): {
  description: string;
  messages: Array<{ role: 'user'; content: { type: 'text'; text: string } }>;
} {
  const description = args.description ?? 'unknown threat';
  const timeRange = args.time_range ?? '-24h';

  return {
    description: `Hunt campaign: ${description}`,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: `${AGENT_WINDOW_GUIDANCE}

You are conducting a proactive threat hunt for: ${description}
Time range: ${timeRange}

## Step 1: PLAN the Hunt
- What MITRE ATT&CK techniques are relevant? Use get_mitre_technique to understand them.
- What log sources do we need? Use get_source_types to confirm availability.
- What specific artifacts, behaviors, or indicators should we look for?
- Design 3-5 targeted searches. Scope every one first: a source (\`metadata.log_source=…\` from get_source_types), a class (\`class_uid=…\`), an entity or a keyword. Never a bare \`*\` across the ${timeRange} window — it reads every source and slows every other query (over 4h nano runs it as a background job and the search tool refuses it). Use \`search\` (nPL) for fresh events and terse \`| stats\` / \`| table\` patterns. For sealed hours use \`lake_sql\`, one source table with \`WHERE {window}\`. Use the bounded \`prevalence\`, \`risk_scores\`, \`resolve_identity\` and \`lookup\` tools for cell features; join their returned values client-side.

## Step 2: BUILD AND RUN QUERIES
- Run each query with the ${timeRange} lookback
- For each query, assess:
  - Any hits? If 0, check field values and adjust. Field values are limited top-value discovery only; use \`| stats count\` for volume rather than summing their counts.
  - False positive rate — are hits expected behavior or suspicious?
  - Volume — manageable for analysis or needs narrowing?

## Step 3: ENRICH FINDINGS
- For any suspicious hits:
  - Read prevalence at ingest time (stamp) via lake_sql first; guarded prevalence only for current counts or unstamped artifacts (65535), with reason and at most 10 known values.
  - Cross-reference threat intel: filter search results on ioc_matched / ioc_threat_type
  - Check for related alerts and cases
  - Use guarded risk_scores, resolve_identity or lookup only for a specific remaining question, with reason and bounded windows.

## Step 4: REPORT
Present a structured hunt report:

### Hunt Summary
- **Objective:** What were we looking for?
- **Scope:** Time range, log sources searched, queries run
- **Methodology:** MITRE techniques targeted, query rationale

### Findings
- For each finding: evidence (specific events), risk assessment, confidence
- Distinguish: confirmed malicious, suspicious requiring investigation, benign

### Recommendations
- **Immediate:** Block, isolate, investigate further
- **Detection:** New detection rules to create (note: use nanodac MCP for rule creation)
- **Prevention:** Policy changes, hardening recommendations
- **Gaps:** What couldn't we check? Missing log sources, visibility gaps?

Present findings progressively — don't wait until the end to share results.`,
        },
      },
    ],
  };
}

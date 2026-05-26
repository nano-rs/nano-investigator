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
      description: 'Time range to search (e.g., "-7d", "-30d"). Default: -7d',
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
          text: `You are hunting for activity related to entity: ${entity} (type: ${entityType})
Time range: ${timeRange}

## Phase 1 — Context (run these in parallel where possible)
- get_entity_context for ${entity}
- ${entityType === 'ip' ? `lookup_ip("${entity}") for GeoIP/ASN` : `lookup_ioc("${entity}") for threat intel`}
- get_prevalence to understand how common this entity is
- search for all activity involving this entity in the last ${timeRange}

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

**Tool choice for Phase 3 queries:** The example queries below are nPL and idiomatic — use them as-is. Reach for \`search_sql\` instead when you need: cross-table joins (logs ↔ signals, ASOF \`identity_observations\` for IP→host resolution), JSON \`ext.*\` column access for source-specific fields, or \`uniqMerge\` aggregates against \`*_prevalence_summary\` tables. Call \`get_schema\` if you're unsure what columns are available.

${entityType === 'ip' ? `**IP Investigation:**
- What internal hosts communicated with it? What ports/protocols?
- Is it associated with any known threats? (IOC check)
- Temporal pattern: regular intervals (beaconing)? Burst traffic (exfil)?
- Query: \`dest_ip="${entity}" | stats count, sum(bytes_out) as bytes, dc(src_ip) as sources by dest_port\`
- Query: \`src_ip="${entity}" | stats count, dc(dest_ip) as targets by dest_port\`` : ''}

${entityType === 'user' ? `**User Investigation:**
- What hosts did they access? Any privilege escalation?
- Off-hours activity?
- Query: \`user="${entity}" | stats count, values(dest_host), values(auth_result) by src_ip\`
- Query: \`user="${entity}" | where action CONTAINS "privilege" OR action CONTAINS "sudo"\`` : ''}

${entityType === 'host' ? `**Host Investigation:**
- What processes ran? Any rare binaries?
- What network connections? Any unusual destinations?
- Query: \`src_host="${entity}" | stats count by process_name | sort -count\`
- Query: \`src_host="${entity}" | where dest_port NOT IN (80, 443, 53) | stats count by dest_ip, dest_port\`` : ''}

${entityType === 'hash' ? `**Hash Investigation:**
- Prevalence across the environment — how many hosts have this hash?
- When was it first seen? Is it new?
- What process name is associated with it?
- Query: \`process_hash="${entity}" | stats count, dc(src_host) as hosts by process_name\`` : ''}

${entityType === 'domain' ? `**Domain Investigation:**
- Prevalence — how many hosts resolved this domain?
- DNS query patterns — volume, timing, subdomain enumeration
- Query: \`dns_query CONTAINS "${entity}" | stats count, dc(src_ip) as resolvers, dc(dns_query) as subdomains by dns_response_code\`` : ''}

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
  const timeRange = args.time_range ?? '-7d';

  return {
    description: `Hunt campaign: ${description}`,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: `You are conducting a proactive threat hunt for: ${description}
Time range: ${timeRange}

## Step 1: PLAN the Hunt
- What MITRE ATT&CK techniques are relevant? Use get_mitre_technique to understand them.
- What log sources do we need? Use get_source_types to confirm availability.
- What specific artifacts, behaviors, or indicators should we look for?
- Design 3-5 targeted searches. Use \`search\` (nPL) for terse \`| stats\` / \`| table\` patterns; reach for \`search_sql\` when the hunt needs joins (logs ↔ signals, ASOF identity), JSON \`ext.*\` access, or \`uniqMerge\` against prevalence summary tables.

## Step 2: BUILD AND RUN QUERIES
- Run each query with the ${timeRange} lookback
- For each query, assess:
  - Any hits? If 0, check field values and adjust.
  - False positive rate — are hits expected behavior or suspicious?
  - Volume — manageable for analysis or needs narrowing?

## Step 3: ENRICH FINDINGS
- For any suspicious hits:
  - Check prevalence (get_prevalence) — is this rare?
  - Cross-reference with IOC feeds (lookup_ioc)
  - Check for related alerts and cases
  - Get entity context for involved entities

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

/**
 * Alert investigation prompt
 */

export const INVESTIGATE_PROMPT = {
  name: 'investigate_alert',
  description:
    'Structured workflow for investigating a nano alert. Guides through reading the alert, understanding the detection rule, enriching entities, searching for related activity, and making a triage recommendation.',
  arguments: [
    {
      name: 'alert_id',
      description: 'The alert ID to investigate',
      required: true,
    },
    {
      name: 'depth',
      description: 'Investigation depth: "quick" (1-2 tool calls), "standard" (3-5), "deep" (5-15)',
      required: false,
    },
  ],
};

export function getInvestigatePrompt(args: Record<string, string | undefined>): {
  description: string;
  messages: Array<{ role: 'user'; content: { type: 'text'; text: string } }>;
} {
  const alertId = args.alert_id ?? 'unknown';
  const depth = args.depth ?? 'standard';

  return {
    description: `Investigate alert ${alertId}`,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: `You are investigating alert ${alertId} from nano.

Investigation depth: ${depth}

Follow this investigation process:

1. **READ** the alert using get_alert(${alertId}) — understand what fired and why. Note the rule_id, severity, matched events, and any triage information.

2. **READ** the detection rule using get_detection(rule_id) — understand the detection logic, MITRE mapping, and critically the ai_triage_hints (ignore_when/suspicious_when guidance the detection author wrote).

3. **ASSESS** based on the ai_triage_hints:
   - Do any ignore_when conditions apply? If so, lean toward false positive.
   - Do any suspicious_when conditions apply? If so, lean toward true positive.
   - What additional context does the hints suggest gathering?

4. **ENRICH** key entities — for each IP, user, or host in the matched events:
   - Call get_entity_context to get risk score, alert history, and activity summary
   - For external IPs, call lookup_ip for GeoIP and lookup_ioc for threat intel
   - For hashes/domains, check prevalence with get_prevalence

5. **SEARCH** for related activity — run 1-2 focused queries to expand context:
   - What else did the alerting entity do around the same time?
   - Are there similar patterns from other entities?
   - Tool choice: prefer \`search\` (nPL) for piped \`| stats\` / \`| table\` patterns scoped to one host or entity. Reach for \`search_sql\` when you need cross-table joins (logs ↔ signals, ASOF identity), JSON \`ext.*\` column access, or aggregates against \`*_prevalence_summary\` (uniqMerge). Call \`get_schema\` first if you're unsure what columns exist.

6. **CHECK HISTORY** — call get_related_cases to see if we've investigated this before:
   - If a related case exists, what was the disposition? Was it FP or TP?
   - This prevents re-investigating known patterns

7. **PRESENT** findings and recommend:
   - **FALSE POSITIVE** → Explain why, recommend closing with specific disposition
   - **NEEDS INVESTIGATION** → Explain concerns, recommend opening a case
   - **TRUE POSITIVE** → Explain impact, recommend immediate actions (block, isolate, escalate)

${depth === 'quick' ? 'QUICK MODE: Limit to steps 1-3 only. Read alert and rule, make a quick assessment.' : ''}
${depth === 'deep' ? 'DEEP MODE: Be thorough. Follow all branches, check prevalence for all artifacts, build a complete timeline.' : ''}

IMPORTANT: Do NOT investigate more than 2 levels deep without presenting findings and asking the analyst for direction on next steps.`,
        },
      },
    ],
  };
}

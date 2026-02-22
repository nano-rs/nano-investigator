/**
 * Triage prompt — SOC shift briefing
 */

export const MORNING_BRIEFING_PROMPT = {
  name: 'morning_briefing',
  description:
    'Generate a SOC shift briefing covering the last 12 hours. Summarizes alert status, case workload, risk landscape, detection health, and environment health. Perfect for shift handoffs.',
  arguments: [
    {
      name: 'hours',
      description: 'Hours to look back (default: 12)',
      required: false,
    },
  ],
};

export function getMorningBriefingPrompt(args: Record<string, string | undefined>): {
  description: string;
  messages: Array<{ role: 'user'; content: { type: 'text'; text: string } }>;
} {
  const hours = args.hours ?? '12';

  return {
    description: `SOC shift briefing (last ${hours}h)`,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: `Generate a SOC shift briefing covering the last ${hours} hours.

Gather data in parallel where possible, then present a concise briefing.

## 1. ALERT SUMMARY
- Call get_alert_counts for severity breakdown
- Call list_alerts for critical and high severity alerts in the last ${hours}h
- How many new vs acknowledged vs closed?
- Any critical/high alerts that haven't been acknowledged?

## 2. CASE STATUS
- Call get_case_stats for open case overview
- Are there cases that need attention? (open but unassigned, stale in_progress)
- Any cases recently escalated or created?

## 3. RISK LANDSCAPE
- Call get_risky_entities(limit=10) for top riskiest entities
- Any entities with rapidly increasing risk scores?
- Any new entities appearing on the risk list?

## 4. DETECTION HEALTH
- Call list_detections to check for rules with unusual match volumes
- Any rules generating an abnormal number of alerts? (possible tuning needed)
- Any alerting rules with zero matches recently? (possible data source issue)

## 5. ENVIRONMENT HEALTH
- Call health_check — is ClickHouse healthy? PostgreSQL healthy?
- Any log source gaps or ingestion issues?

## Present as a Concise Briefing

Format the briefing with clear sections and actionable items highlighted. Example:

---
**SOC Shift Briefing — ${new Date().toISOString().split('T')[0]}**

**Alerts:** X new (Y critical, Z high) | A acknowledged | B closed
**Action needed:** [list any unacknowledged critical/high alerts]

**Cases:** X open | Y in progress | Z unassigned
**Action needed:** [list any cases needing attention]

**Risk:** Top entity: [entity] (score: X) — [brief context]
**Notable:** [any new or escalating risk entities]

**Detection:** [any noisy or silent rules]

**Health:** [system status, any issues]

**Recommended priorities for this shift:**
1. [most important action]
2. [second priority]
3. [third priority]
---`,
        },
      },
    ],
  };
}

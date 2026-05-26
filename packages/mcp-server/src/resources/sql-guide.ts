/**
 * SQL Guide Resource — ClickHouse query patterns and performance rules for the nano SIEM log store.
 *
 * Curated from production code in the nanosiem repo. Use this resource when writing search_sql queries.
 */

export const SQL_GUIDE_URI = 'nano://sql-guide';

export const SQL_GUIDE_RESOURCE = {
  uri: SQL_GUIDE_URI,
  name: 'nano SQL Guide',
  description:
    'ClickHouse SQL patterns for the nano SIEM — performance rules, canonical query recipes (prevalence, top-N, time bucketing, identity ASOF joins, free-text hunt), and anti-patterns to avoid.',
  mimeType: 'text/markdown',
};

export const SQL_GUIDE_CONTENT = `# nano SQL Guide

ClickHouse SQL patterns for hunting through the nano SIEM log store. Examples are lifted from production code in nanosiem-core.

> Pair this with \`get_schema\` (UDM column inventory) and the \`search_sql\` tool.

---

## Tables you can query

| Table | Purpose | Notes |
|-------|---------|-------|
| \`logs\` | Raw normalized events (UDM) | The primary hunt table. ~75 explicit UDM columns + \`ext\` JSON column. |
| \`signals\` | Detection rule matches | Audit trail of when which rule fired on which event. |
| \`hash_prevalence_summary\` | Rolled-up hash prevalence | AggregatingMergeTree. Query with \`uniqMerge(host_count)\`. |
| \`domain_prevalence_summary\` | Rolled-up domain prevalence | Same pattern as hash. |
| \`ip_prevalence_summary\` | Rolled-up IP prevalence | Same pattern. |
| \`*_prevalence_agg\` | Raw per-event prevalence rows | Use the \`_summary\` tables instead unless you need un-aggregated rows. |
| \`identity_observations\` | IP → hostname/user mappings over time | Use ASOF JOIN to enrich logs with closest-in-time identity. |

---

## Performance rules

1. **Always filter \`timestamp\`** — enables daily partition pruning. The single biggest perf knob.
2. **PREWHERE holds time + indexed equality filters.** WHERE holds free-text / regex / complex booleans.
3. **Free-text search**: \`lower(field) iLike '%needle%'\`. Text indexes (splitByNonAlpha tokenizer, granularity 1) on \`lower(message)\`, \`lower(command_line)\`, \`lower(user)\`, \`lower(process_name)\`, \`lower(file_path)\`, \`lower(parent_command_line)\`, \`lower(src_user)\`, \`lower(dest_user)\` keep this fast.
4. **\`lower()\` on both sides** of case-insensitive comparisons (esp. \`source_type\`).
5. **\`ext\` is a ClickHouse JSON column** — \`ext.field\` or \`ext['field']\`, NOT JSONExtract. JSONExtract is only for the legacy \`metadata\` String column.
6. **Direct UDM column access** — \`src_ip\`, \`process_name\`, \`user\`, \`file_hash\`, etc. are real columns. Never go through \`ext\` for UDM data.
7. **Always LIMIT.** Backend caps at 100k. Default 100 unless the user asks otherwise.

### PREWHERE-able fields (bloom_filter indexed)
\`timestamp\`, \`src_ip\`, \`dest_ip\`, \`src_mac\`, \`dest_mac\`, \`user\`, \`src_user\`, \`dest_user\`, \`user_id\`, \`process_name\`, \`process_hash\`, \`process_guid\`, \`command_line\`, \`parent_command_line\`, \`file_hash\`, \`source_type\`, \`event_type\`, \`action\`, \`tags\`.

---

## Canonical query patterns

### 1. Free-text hunt across a source type

\`\`\`sql
SELECT timestamp, src_ip, user, message
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
  AND lower(source_type) = lower('windows')
WHERE lower(message) iLike '%logon failure%'
ORDER BY timestamp DESC
LIMIT 100;
\`\`\`

**Use when:** Hunting for a specific phrase in log lines scoped to one source.

### 2. Top-N by entity

\`\`\`sql
SELECT src_ip, count() AS hits
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
GROUP BY src_ip
ORDER BY hits DESC
LIMIT 20;
\`\`\`

**Use when:** Top talkers, top processes, busiest users — any "show me the N most active X."

### 3. Time bucketing (activity histogram)

\`\`\`sql
SELECT
  toStartOfHour(timestamp) AS hour,
  count() AS event_count
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
GROUP BY hour
ORDER BY hour;
\`\`\`

**Bucket function picks:** \`toStartOfMinute\` (sub-hour spans), \`toStartOfFiveMinutes\` (a few hours), \`toStartOfHour\` (days), \`toStartOfDay\` (weeks+). Prefer these over INTERVAL math — they're faster.

### 4. Failed-auth burst detection

\`\`\`sql
SELECT
  src_ip,
  user,
  count() AS failures,
  min(timestamp) AS first_seen,
  max(timestamp) AS last_seen
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
  AND lower(source_type) = lower('windows')
WHERE lower(action) = 'login_failed'
GROUP BY src_ip, user
HAVING failures >= 10
ORDER BY failures DESC
LIMIT 50;
\`\`\`

**Use when:** Brute-force or password-spray detection. Tune \`HAVING failures >=\` per environment.

### 5. Prevalence: "is this hash rare?"

\`\`\`sql
SELECT
  file_hash,
  uniqMerge(host_count) AS distinct_hosts,
  min(first_seen) AS first_seen,
  max(last_seen) AS last_seen
FROM hash_prevalence_summary
WHERE file_hash IN ('abc123...', 'def456...')
GROUP BY file_hash;
\`\`\`

**Use when:** Checking how widely a hash has been observed. \`distinct_hosts < 5\` is typically "rare." Same pattern for \`domain_prevalence_summary\` (by \`domain\`) and \`ip_prevalence_summary\` (by \`ip\`).

**Key detail:** prevalence summary tables are \`AggregatingMergeTree\` — \`host_count\` is an HLL state, query it with \`uniqMerge()\` not \`SUM()\` or \`COUNT()\`.

### 6. Rare-artifact filter (find unusual things in a window)

\`\`\`sql
SELECT file_hash, process_name, count() AS hits
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
  AND file_hash != ''
WHERE file_hash IN (
  SELECT file_hash
  FROM hash_prevalence_summary
  WHERE file_hash != ''
  GROUP BY file_hash
  HAVING uniqMerge(host_count) < 5
)
GROUP BY file_hash, process_name
ORDER BY hits DESC
LIMIT 100;
\`\`\`

**Use when:** Surfacing hashes seen on fewer than N hosts that fired in this window.

### 7. Identity enrichment with ASOF JOIN

\`\`\`sql
SELECT
  main.timestamp,
  main.src_ip,
  if(main.src_host = '' OR main.src_host IS NULL, i.hostname, main.src_host) AS resolved_host,
  CASE
    WHEN i.observed_at IS NULL THEN 'none'
    WHEN i.observed_at > main.timestamp - INTERVAL 1 HOUR THEN 'high'
    ELSE 'low'
  END AS identity_confidence
FROM logs AS main
ASOF LEFT JOIN identity_observations AS i
  ON main.src_ip = i.ip
  AND main.timestamp >= i.observed_at
PREWHERE main.timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
  AND main.src_ip != ''
WHERE i.observed_at IS NULL OR i.observed_at > main.timestamp - INTERVAL 14400 SECOND
ORDER BY main.timestamp DESC
LIMIT 100;
\`\`\`

**Use when:** Translating IPs to the hostname/user observed closest in time. ASOF avoids O(n²) cross joins.

### 8. logs ↔ signals correlation

\`\`\`sql
SELECT
  l.timestamp,
  l.src_ip,
  l.user,
  l.message,
  s.rule_id,
  s.rule_name,
  s.severity
FROM logs AS l
INNER JOIN signals AS s ON l.id = s.event_id
PREWHERE l.timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
ORDER BY l.timestamp DESC
LIMIT 100;
\`\`\`

**Use when:** "Show me logs that triggered detection rules in this window."

### 9. First-seen entity

\`\`\`sql
SELECT
  src_ip,
  min(timestamp) AS first_seen,
  count() AS total_events
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
GROUP BY src_ip
HAVING first_seen >= '2026-05-26T00:00:00Z'
ORDER BY first_seen ASC
LIMIT 50;
\`\`\`

**Use when:** "What IPs appeared today that I've never seen before in this window?" Adjust \`HAVING\` cutoff for "since when is new."

### 10. JSON ext column access

\`\`\`sql
-- ext is a ClickHouse JSON column. Access fields by name; use [] for keys with special chars.
SELECT
  timestamp,
  src_ip,
  ext.process_path AS process_path,
  ext['custom.field'] AS custom_field
FROM logs
PREWHERE timestamp BETWEEN '2026-05-25T00:00:00Z' AND '2026-05-26T00:00:00Z'
  AND lower(source_type) = lower('sysmon')
WHERE ext.event_id = 1
LIMIT 100;
\`\`\`

**Use when:** Reaching non-UDM source-specific fields. Call \`get_schema\` with \`include_ext: true\` to see observed ext keys.

**Legacy:** Older rows may have data in the \`metadata\` String column instead — that one needs \`JSONExtractString(metadata, 'key')\`. Prefer \`ext\` going forward.

---

## Anti-patterns (do not do)

| Don't | Do | Why |
|-------|----|-----|
| \`hasToken(message, 'error')\` | \`lower(message) iLike '%error%'\` | hasToken silently misses substrings — \`'error'\` won't match \`'anomaly_error'\` boundaries reliably (NAN-1026). |
| \`JSONExtractString(ext, 'foo')\` | \`ext.foo\` or \`ext['foo']\` | \`ext\` is a true JSON column, not a String. JSON column syntax is typed and faster. |
| \`SUM(host_count)\` on prevalence_summary | \`uniqMerge(host_count)\` | host_count is an HLL state, not an integer. SUM gives garbage. |
| \`message LIKE 'Error%'\` (case-sensitive) | \`lower(message) iLike 'error%'\` | Production logs vary case constantly. Always normalize. |
| Free-text in PREWHERE | Put it in WHERE | PREWHERE wants indexed equality predicates. iLike doesn't help granule pruning. |
| Omitting timestamp filter | \`PREWHERE timestamp BETWEEN ... AND ...\` | Without timestamp, ClickHouse can't prune partitions. Scans everything. |

---

## Quick reference: ClickHouse functions worth knowing

| Function | Purpose |
|----------|---------|
| \`toStartOfHour(ts)\` / \`toStartOfFiveMinutes(ts)\` / \`toStartOfDay(ts)\` | Time bucketing |
| \`isIPv4String(s)\` / \`toIPv4OrDefault(s)\` | IP validation/coercion |
| \`uniq(x)\` / \`uniqMerge(state)\` | Cardinality (HLL) |
| \`groupArray(x)\` | Collect values into array |
| \`arrayJoin(arr)\` | Unnest array column to rows |
| \`if(cond, then, else)\` / \`CASE WHEN ... END\` | Conditionals |
| \`dictGetOrDefault('dict_name', 'attr', key, default)\` | Lookup against a dictionary (used internally for IP enrichment) |
| \`hex(cityHash64(...))\` | Cheap stable hash for grouping/de-duping |

---

When in doubt: write the query, run \`search_sql\` with \`limit: 10\` first to sanity-check shape, then widen the limit.
`;

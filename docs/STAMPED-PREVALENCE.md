# Stamped prevalence through lake_sql

Use the row's **prevalence at ingest time (stamp)** first. Cell `prevalence` is only for current counts or an unstamped artifact (65535), after lake_sql identifies a specific suspicious artifact. Supply a one-sentence reason.

`rare-artifacts-by-stamp.sql` flattens the captured scratch query without changing the gateway rules: one SELECT, one FROM, WHERE {window}. It expands the captured positions 3–4 to positions 1–6 and checks provider=nano as well as name=prevalence. Copy the query, choose the authorized source table, and supply start/end. The owner validated the flattened query in Basin on 2026-10-22: 10 rows over 7 days, 917 MB scanned across 152 files.

Basin stores enrichments as LIST<STRUCT>. Indexing is one-based. `enrichments[3]['data']['host_count']` and `cardinality(enrichments)` work. Whole-list `get_field(enrichments,'name')`, `enrichments['name']`, and UNNEST do not. Stamps move between rows; never assume one fixed position. The six-position bound is an explicit limitation: rows with a relevant stamp beyond position six are omitted, not treated as rare. Project raw enrichments to inspect a longer list. The chDB parallel-array/lambda derivation in schema/lake_prevalence.rs cannot be copied to Basin unchanged.

For a specific artifact add its value to each CASE condition, matching lower(trim(value)) to the normalized artifact; another artifact's stamp is not its prevalence. The five canonical scalars cover file SHA256, process SHA256, destination domain, destination public IP and their minimum. Use physical prevalence_* columns only after schema discovery proves they exist. The captures' schema exposes nested stamps instead. Valid scalars: 1–9998 hosts, 9999 common/saturated, 65535 unavailable. NULL/missing stamps must never pass a rare predicate.

Stamp filtering reads the window's enrichments column; it does not prune files by stamp. Narrow by source and time first. The captured seven-day proxy probe scanned 997,140,573 bytes in 167 files; the flattened six-position example scanned 917 MB across 152 files in the owner-run validation.

Fixtures in packages/core/src/fixtures/basin-rows are unmodified Basin responses supplied from the b12 scratch copy on 2026-10-22: schema, rows, successful index/cardinality probes, failed whole-list probes and the rare-artifact result. No live requests are part of tests.

The default example returns the first stamp per row; use the artifact_type variant for IPs vs domains. A proxy row may carry both domain and IP stamps, so the first stamp cannot answer both questions. `rare-ips-by-stamp.sql` adds data.artifact_type='ip_address' to every CASE condition; use ('domain' OR 'subdomain') comparisons for domains. For a known artifact also match value in every condition. Missing/beyond-six matches remain unavailable.

Call lake_sql without sql to discover authorized namespace.table names from the gateway, then replace `<namespace>.<table>` in either example. Metadata listing is bounded to 32 configured tables and reports truncation. No query is executed or charged.

The supplied row capture uses artifact_type=subdomain for domains and ip_address for IPs; some IP stamps have NULL artifact_type. The typed variant omits those NULL entries: match the known artifact value in every CASE when its type is missing, never assume the first stamp belongs to that IP.

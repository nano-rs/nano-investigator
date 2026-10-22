# Stamped prevalence through lake_sql

Use the row's **prevalence at ingest time (stamp)** first. Cell `prevalence` is only for current counts or an unstamped artifact (65535), after lake_sql identifies a specific suspicious artifact. Supply a one-sentence reason.

`rare-artifacts-by-stamp.sql` flattens the captured scratch query without changing the gateway rules: one SELECT, one FROM, WHERE {window}. It expands the captured positions 3–4 to positions 1–6 and checks provider=nano as well as name=prevalence. Copy the query, choose the authorized source table, and supply start/end. This flattening still needs owner validation in Basin; the underlying bracket access and grouped result are real captures, not a claim that this exact new query ran live.

Basin stores enrichments as LIST<STRUCT>. Indexing is one-based. `enrichments[3]['data']['host_count']` and `cardinality(enrichments)` work. Whole-list `get_field(enrichments,'name')`, `enrichments['name']`, and UNNEST do not. Stamps move between rows; never assume one fixed position. The six-position bound is an explicit limitation: rows with a relevant stamp beyond position six are omitted, not treated as rare. Project raw enrichments to inspect a longer list. The chDB parallel-array/lambda derivation in schema/lake_prevalence.rs cannot be copied to Basin unchanged.

For a specific artifact add its value to each CASE condition, matching lower(trim(value)) to the normalized artifact; another artifact's stamp is not its prevalence. The five canonical scalars cover file SHA256, process SHA256, destination domain, destination public IP and their minimum. Use physical prevalence_* columns only after schema discovery proves they exist. The captures' schema exposes nested stamps instead. Valid scalars: 1–9998 hosts, 9999 common/saturated, 65535 unavailable. NULL/missing stamps must never pass a rare predicate.

Stamp filtering reads the window's enrichments column; it does not prune files by stamp. Narrow by source and time first. The captured seven-day proxy probe scanned 997,140,573 bytes in 167 files; the generated six-position example has not been measured.

Fixtures in packages/core/src/fixtures/basin-rows are unmodified Basin responses supplied from the b12 scratch copy on 2026-10-22: schema, rows, successful index/cardinality probes, failed whole-list probes and the rare-artifact result. No live requests are part of tests.

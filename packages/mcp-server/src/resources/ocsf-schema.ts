/**
 * OCSF 1.9 reference for nano deployments.
 *
 * Two layers, deliberately separated:
 *   - `ocsf-catalog.generated.ts` — the class/activity catalog pulled from
 *     schema.ocsf.io. Regenerate with `node scripts/generate-ocsf-reference.mjs`.
 *   - This file — what OCSF means *in nano*: how events are named and queried,
 *     which shapes come back from which tool, and the mapping conventions
 *     nano's own shipped OCSF parsers follow.
 *
 * Deployment-specific facts (which fields THIS deployment promotes) belong to
 * `get_schema` at runtime, not here. This resource is the vocabulary; the field
 * universe is the inventory.
 */

import {
  OCSF_CATEGORIES,
  OCSF_CLASSES,
  OCSF_DETAILED_CLASSES,
  OCSF_VERSION,
} from './ocsf-catalog.generated.js';

export const OCSF_SCHEMA_URI = 'nanosiem://reference/ocsf';

export const OCSF_SCHEMA_RESOURCE = {
  uri: OCSF_SCHEMA_URI,
  name: `OCSF ${OCSF_VERSION} Reference`,
  description:
    'How OCSF works in nano: event classes and their activity enums, the canonical field paths, the enum-int vs label convention, how to query OCSF with nPL, the two row shapes search and get_event return, and the mapping conventions nano OCSF parsers follow. Read this on any deployment where get_schema reports schema=ocsf.',
  mimeType: 'text/markdown',
};

function classTable(): string {
  const byCategory = new Map<number, typeof OCSF_CLASSES>();
  for (const cls of OCSF_CLASSES) {
    const bucket = byCategory.get(cls.categoryUid) ?? [];
    bucket.push(cls);
    byCategory.set(cls.categoryUid, bucket);
  }

  return OCSF_CATEGORIES.map((category) => {
    const rows = (byCategory.get(category.uid) ?? [])
      .map((cls) => {
        const flags = [
          cls.extension ? `\`${cls.extension}\` ext` : null,
          cls.deprecated
            ? `**DEPRECATED${cls.deprecated.since ? ` since ${cls.deprecated.since}` : ''}**${
                cls.deprecated.supersededBy.length
                  ? ` — use \`${cls.deprecated.supersededBy.join('`, `')}\``
                  : ''
              }`
            : null,
        ].filter(Boolean);
        return `| ${cls.uid} | ${cls.caption} | ${flags.join('; ') || ''} |`;
      })
      .join('\n');
    return `### ${category.uid} — ${category.caption}\n\n| class_uid | Class | Notes |\n|---|---|---|\n${rows}`;
  }).join('\n\n');
}

function detailedClasses(): string {
  return OCSF_DETAILED_CLASSES.map((cls) => {
    const activities = cls.activities.map((a) => `\`${a.id}\` ${a.caption}`).join(' · ');
    const deprecated = cls.deprecated
      ? `\n> **Deprecated${cls.deprecated.since ? ` since OCSF ${cls.deprecated.since}` : ''}.** ${cls.deprecated.message}\n`
      : '';
    return `#### ${cls.uid} — ${cls.caption}${cls.extension ? ` (\`${cls.extension}\` extension)` : ''}\n${deprecated}
${cls.description}

**activity_id:** ${activities}

**type_uid** = \`${cls.uid} * 100 + activity_id\`
`;
  }).join('\n');
}

export const OCSF_SCHEMA_CONTENT = `# OCSF ${OCSF_VERSION} in nano

On an OCSF deployment, events are stored as OCSF records — not UDM. The UDM
names (\`src_ip\`, \`dest_ip\`, \`process_name\`, \`command_line\`, \`user\`) **do not
exist**. Everything is addressed by its canonical OCSF path.

> Call \`get_schema\` for the field universe THIS deployment actually promotes.
> This document is the vocabulary and the conventions; \`get_schema\` is the
> inventory. A path that is valid OCSF but not promoted here is not queryable as
> a column — it lives inside the event and is reachable via \`get_event\`.

---

## The two row shapes

This trips up every consumer at least once. Same field names, different nesting:

| Source | Shape | Read a value as |
|---|---|---|
| \`search\` results | **flat, dotted keys**, pruned projection (~25 columns) | \`row["actor.user.name"]\` |
| \`get_event\` | **nested objects**, the complete stored event | \`event.actor.user.name\` |

Two consequences worth internalizing:

1. **A field missing from a search row is usually unprojected, not empty.** The
   search projection carries the common entity columns; most of \`actor.*\`,
   \`cloud.*\`, \`file.*\`, \`http_request.*\` and all of \`unmapped.*\` are absent
   from it. Before concluding "this event has no X", fetch it with \`get_event\`.
2. **nPL field names are the dotted paths either way.** You always *write*
   \`actor.user.name\` in a query; only the way you *read* the result differs.

---

## Identity, time, and source

| Concept | OCSF path | Notes |
|---|---|---|
| Event ID | \`metadata.uid\` | This is the id \`get_event\` takes. There is no \`id\` column. |
| Event time | \`time\` | Epoch millis in storage; rendered as a timestamp string in results. There is no \`timestamp\` column. |
| Log source | \`metadata.log_source\` | The OCSF stand-in for UDM's \`source_type\`. |
| Raw line | \`raw_data\` (and \`message\`) | \`message\` is the human-readable summary; \`raw_data\` the original. |
| Class | \`class_uid\` / \`class_name\` | See the catalog below. |
| Activity | \`activity_id\` / \`activity_name\` | Per-class enum; see below. |

---

## Enum ints and their label siblings

OCSF encodes most taxonomies as an integer plus a sibling label string:

| Int column | Label column |
|---|---|
| \`activity_id\` | \`activity_name\` |
| \`severity_id\` | \`severity\` |
| \`status_id\` | \`status\` |
| \`disposition_id\` | \`disposition\` |
| \`class_uid\` | \`class_name\` |
| \`category_uid\` | \`category_name\` |

Query either. \`activity_name="Launch"\` and \`activity_id=1\` select the same
Process Activity events. Prefer the **label** when writing something a human
will read back, and the **int** when the label may vary by producer.

One sharp edge carried over from the UDM→OCSF migration: numeric range
comparisons must target a numeric column. \`status>=500\` compares against a
label string and is correctly empty; the HTTP status code lives at
\`http_response.code\`.

---

## "Unknown canonical OCSF field" — what it means

A query naming a field this deployment does not promote is REJECTED, not
silently matched:

\`\`\`
src_ip=10.0.0.1
-> Bad request: Unknown canonical OCSF field 'src_ip' in query. Use an exact
   OCSF 1.9 path, or \`unmapped.src_ip\` for an intentionally unmapped source field
\`\`\`

This is a good error — it fails loudly instead of returning a plausible empty
result. Two distinct causes, and they need different fixes:

1. **You used a UDM name** (\`src_ip\`, \`process_name\`, \`user\`). Translate it —
   see the cheat-sheet below.
2. **The path is valid OCSF but nothing on this deployment writes it yet.** The
   promoted set follows what the parsers actually emit, so a legitimate 1.9 path
   can be absent simply because no source populates it. \`get_schema\` is the
   authority on which.

The suggested \`unmapped.<name>\` form is the escape hatch for a source field
that was deliberately left unpromoted — not a way to force a UDM name to work.

---

## Fields with no promoted column: \`unmapped.*\`

Anything a parser emits that has no promoted OCSF column lands under
\`unmapped.*\` — the OCSF equivalent of UDM's \`ext\`. It is part of the stored
event, so \`get_event\` shows it; it is generally not part of the search
projection. \`unmapped\` is a struct of the union of every source's extra keys,
so for any single event most of its members are null. That is expected, not
data loss.

---

## Querying OCSF with nPL

nPL is unchanged — only the field names are. The same intents:

\`\`\`
# Authentication failures by source
class_uid=3002 activity_name="Logon" | stats count by src_endpoint.ip, actor.user.name | sort -count

# PowerShell executions with their command lines
actor.process.name=powershell.exe | table time, device.hostname, actor.user.name, actor.process.cmd_line

# Outbound volume by destination
class_uid=4001 | stats sum(traffic.bytes_out) by dst_endpoint.ip | sort -sum

# One log source over time
metadata.log_source=aws_cloudtrail | timechart span=1h count by activity_name

# Cloud API calls by principal
class_uid=6003 | stats count by actor.user.uid, api.operation | sort -count
\`\`\`

Migration cheat-sheet from UDM habits:

| UDM | OCSF |
|---|---|
| \`src_ip\` | \`src_endpoint.ip\` |
| \`dest_ip\` | \`dst_endpoint.ip\` |
| \`src_port\` / \`dest_port\` | \`src_endpoint.port\` / \`dst_endpoint.port\` |
| \`src_host\` / \`dest_host\` | \`src_endpoint.hostname\` / \`dst_endpoint.hostname\` |
| \`user\` | \`actor.user.name\`, or \`user.name\` on classes where the user is the subject |
| \`process_name\` | \`actor.process.name\` (the acting process); \`process.name\` where the process is the target |
| \`command_line\` | \`actor.process.cmd_line\` |
| \`parent_process_name\` | \`actor.process.name\` on a child-process event — see below |
| \`file_path\` / \`file_hash\` | \`file.path\` / \`file.hashes.value\` (also \`file.hashes.sha256\`) |
| \`source_type\` | \`metadata.log_source\` |
| \`timestamp\` | \`time\` |
| \`ext.foo\` | \`unmapped.foo\` |

**Check the right-hand column against \`get_schema\` before you rely on it.**
OCSF defines far more paths than any deployment promotes to a queryable column,
and the promoted set is what nPL can filter on. A worked example: OCSF has
\`actor.process.parent_process.name\`, but a nano OCSF deployment typically does
**not** promote it — there is no parent-process column to filter on. What you get
instead is the actor/subject split: on a process-create event the new process is
\`process.*\` and the process that launched it is \`actor.process.*\`, so
"what spawned X" is answered by filtering \`process.name=X\` and reading
\`actor.process.name\`, not by a parent field.

**Actor vs subject** is the one genuinely new distinction. \`actor.*\` is who/what
performed the action; the bare object (\`process.*\`, \`user.*\`, \`file.*\`) is what
the action was performed *on*. In Sysmon process-create, the new process is
\`process.*\` and its parent — the thing that launched it — is \`actor.process.*\`.
Which one is populated depends on the class, so check both when hunting.

---

## Writing an OCSF parser

nano's shipped OCSF parsers assign the **whole event object on the root** — they
never touch \`.udm.*\`:

\`\`\`vrl
raw_log = string!(.message)
parsed, err = parse_json(raw_log)

if err != null || !is_object(parsed) {
    # Failure branch still emits a well-formed event. Never abort the whole line.
    . = {
        "class_uid": 6003, "category_uid": 6, "activity_id": 99, "type_uid": 600399,
        "severity_id": 1, "status_id": 0, "time": 0,
        "message": raw_log, "raw_data": raw_log,
        "metadata": {
            "version": "${OCSF_VERSION}", "uid": uuid_v4(), "log_level": "error",
            "product": { "name": "…", "vendor_name": "…" }
        }
    }
} else {
    # …map the parsed fields onto canonical OCSF paths…
}
\`\`\`

Rules that come from nano's validator and from real breakage:

- **\`type_uid = class_uid * 100 + activity_id\`.** Keep the three consistent.
- **\`metadata.version\`** is the OCSF version the parser targets (\`"${OCSF_VERSION}"\`).
- **\`metadata.uid\`** must be a UUID — use \`uuid_v4()\`. Do not call \`string()\` on
  an integer record id; VRL errors on it (this was a real production bug).
- **\`metadata.product.name\` / \`.vendor_name\`** identify the producer.
- **Never assign \`.source_type\`** — ingestion owns it.
- **Preserve the raw line** in \`message\` and \`raw_data\`.
- **One class per event shape, routed by the source's own event type.** A single
  source usually spans several classes: Sysmon alone maps EventID 1/5/10 →
  Process Activity 1007, 7 → Module Activity 1005, 3 → Network Activity 4001,
  11/23 → File System Activity 1001, 22 → DNS Activity 4003, 12/13 → the
  Windows registry classes.
- **Write a generic parser**, not one that handles the sample. Give the
  unrecognized branch \`activity_id: 99\` ("Other") rather than dropping it.

---

## Class catalog (OCSF ${OCSF_VERSION})

${classTable()}

---

## Classes nano parsers emit, in detail

${detailedClasses()}
`;

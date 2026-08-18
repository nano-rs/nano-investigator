/**
 * Deployment profile discovery (NAN-2373).
 *
 * This server used to assume one deployment shape: the UDM schema stored in a
 * ClickHouse `logs` table, with raw SQL always available. Neither half holds
 * any more.
 *
 *   - **Schema** is either `udm` or `ocsf`. On OCSF the queryable names are
 *     dotted OCSF paths (`actor.user.name`, `src_endpoint.ip`), and none of the
 *     UDM column names exist. `/api/schema/fields` answers with the ACTIVE
 *     profile; `/api/udm/fields` answers with UDM regardless.
 *   - **Backend** is either ClickHouse or the Iceberg + chDB lake. The lake
 *     refuses raw SQL outright ("use nPL so Nano can enforce tenant and
 *     byte-scan policy") and escalates budget-exceeding nPL to a durable job.
 *
 * Lake mode requires `NANO_SCHEMA_PROFILE=ocsf`, so lake implies OCSF — but
 * OCSF does NOT imply lake, since a ClickHouse-OCSF deployment still serves raw
 * SQL. The two axes are therefore discovered separately.
 *
 * Discovery is best-effort and cached for the process lifetime: a deployment
 * does not change schema or backend without a restart, and every tool call
 * paying for a re-probe would be pure latency. Nothing here throws — an
 * unreachable or older nano yields `unknown`, and tools degrade to describing
 * what they cannot confirm rather than asserting a wrong answer.
 */

import type { NanosiemClient, SchemaFieldInfo, SchemaId } from '@nano-rs/investigator-core';

export type QueryBackend = 'clickhouse' | 'lake' | 'unknown';
export type RawSqlAvailability = 'available' | 'unavailable' | 'unknown';

export interface DeploymentProfile {
  /** Active schema profile, or `unknown` when discovery failed. */
  schema: SchemaId | 'unknown';
  /** How the schema was determined — so tools can be honest about confidence. */
  schemaSource: 'schema-endpoint' | 'udm-fallback' | 'none';
  backend: QueryBackend;
  rawSql: RawSqlAvailability;
  /** Active-profile field universe. Empty when discovery failed. */
  fields: SchemaFieldInfo[];
  /** Non-fatal discovery problems, surfaced to the agent rather than swallowed. */
  warnings: string[];
}

/**
 * The lake's raw-SQL refusal, matched loosely.
 *
 * Matching on the message is deliberate: the refusal arrives as a generic
 * `QUERY_ERROR` with no machine-readable discriminator, and the alternative —
 * assuming raw SQL works and letting every SQL tool call fail — is worse. The
 * check is a substring on the stable half of the sentence, so rewording the
 * tail does not break it.
 */
const LAKE_RAW_SQL_REFUSAL = /raw sql is not supported by the lake/i;

export function isLakeRawSqlRefusal(message: string | undefined): boolean {
  return message !== undefined && LAKE_RAW_SQL_REFUSAL.test(message);
}

const EMPTY: DeploymentProfile = {
  schema: 'unknown',
  schemaSource: 'none',
  backend: 'unknown',
  rawSql: 'unknown',
  fields: [],
  warnings: [],
};

let cached: DeploymentProfile | null = null;
let inFlight: Promise<DeploymentProfile> | null = null;

/**
 * Resolve (and memoize) the deployment profile.
 *
 * Concurrent callers share one in-flight discovery — several tools calling this
 * on the same turn should not each pay for the round trips.
 */
export async function getDeploymentProfile(client: NanosiemClient): Promise<DeploymentProfile> {
  if (cached) return cached;
  if (inFlight) return inFlight;

  inFlight = discover(client)
    .then((profile) => {
      // Only memoize a profile that actually learned something. A discovery
      // that failed outright — nano briefly unreachable at session start, a
      // token not yet valid — must not be cached, or one bad moment leaves the
      // whole session convinced it has no schema and every field-name answer
      // permanently unavailable. Retry on the next call instead.
      if (profile.schema !== 'unknown') {
        cached = profile;
      }
      return profile;
    })
    .finally(() => {
      inFlight = null;
    });

  return inFlight;
}

async function discover(client: NanosiemClient): Promise<DeploymentProfile> {
  const warnings: string[] = [];
  let schema: SchemaId | 'unknown' = 'unknown';
  let schemaSource: DeploymentProfile['schemaSource'] = 'none';
  let fields: SchemaFieldInfo[] = [];

  const schemaResult = await client.getSchemaFields();
  if (schemaResult.success && schemaResult.data) {
    schema = schemaResult.data.schema;
    schemaSource = 'schema-endpoint';
    fields = schemaResult.data.fields ?? [];
  } else {
    // Older nano: no profile-aware endpoint. Such a build predates OCSF being
    // selectable, so UDM is the correct answer — but say where it came from.
    const udm = await client.getUdmFields();
    if (udm.success && udm.data) {
      schema = 'udm';
      schemaSource = 'udm-fallback';
      fields = (udm.data.fields ?? []).map((f) => ({
        name: f.name,
        type: f.data_type,
        category: f.category,
      }));
      warnings.push(
        '/api/schema/fields is unavailable on this nano build; the field universe came from the ' +
          'UDM-only /api/udm/fields endpoint. Correct for a pre-OCSF deployment, but it cannot ' +
          'report an OCSF profile even if one is active.',
      );
    } else {
      warnings.push(
        `Schema discovery failed: ${schemaResult.error?.message ?? 'unknown error'}. ` +
          'Field names in this session are unverified.',
      );
    }
  }

  let backend: QueryBackend = 'unknown';
  let rawSql: RawSqlAvailability = 'unknown';

  const caps = await client.getCapabilities();
  if (caps.success && caps.data?.logQueryBackend) {
    backend = caps.data.logQueryBackend;
    rawSql = backend === 'lake' ? 'unavailable' : 'available';
  } else if (schema === 'udm') {
    // Lake mode refuses to boot on a UDM profile, so a UDM deployment is
    // ClickHouse by construction.
    backend = 'clickhouse';
    rawSql = 'available';
  }
  // OCSF on a build that does not publish the backend stays `unknown` on both
  // axes. It is resolved the first time a raw-SQL call reveals the answer
  // (`recordRawSqlOutcome`) rather than by firing a speculative probe here that
  // most sessions would never need.

  return { schema, schemaSource, backend, rawSql, fields, warnings };
}

/**
 * Fold what an actual raw-SQL call revealed back into the cached profile.
 *
 * The lake's refusal is definitive: only the lake backend produces it, so one
 * observation settles both axes for the session. A success is equally
 * definitive in the other direction.
 */
export function recordRawSqlOutcome(outcome: 'refused-by-lake' | 'succeeded'): void {
  if (!cached) return;
  if (outcome === 'refused-by-lake') {
    cached = { ...cached, backend: 'lake', rawSql: 'unavailable' };
  } else if (cached.rawSql !== 'available') {
    cached = { ...cached, rawSql: 'available' };
  }
}

/** Test seam: drop the memoized profile. */
export function resetDeploymentProfile(): void {
  cached = null;
  inFlight = null;
}

/** Test seam: install a profile without hitting the network. */
export function setDeploymentProfileForTest(profile: Partial<DeploymentProfile>): void {
  cached = { ...EMPTY, ...profile };
}

/**
 * One-paragraph orientation for the agent, matched to what this deployment
 * actually is. Included in `get_schema` so the model does not have to infer the
 * query model from field names.
 */
export function deploymentGuidance(profile: DeploymentProfile): string {
  const parts: string[] = [];

  if (profile.schema === 'ocsf') {
    parts.push(
      'This deployment stores events in OCSF, not UDM. Queryable field names are dotted OCSF ' +
        'paths — `actor.user.name`, `src_endpoint.ip`, `actor.process.cmd_line`, ' +
        '`http_request.url.path` — and the UDM names (`src_ip`, `process_name`, `user`, ' +
        '`command_line`) DO NOT EXIST here. Use the field list in this response; do not ' +
        'translate from memory.',
    );
    parts.push(
      'TWO ROW SHAPES, same names. `search` returns rows FLAT with dotted keys — read ' +
        '`row["actor.user.name"]`. `get_event` returns the complete stored event NESTED — read ' +
        '`event.actor.user.name`. Do not carry an accessor from one to the other.',
    );
    parts.push(
      '`search` returns a PRUNED projection of about 25 columns, not the whole event. A field ' +
        'missing from a search row is not evidence the field is empty — most of `actor.*`, `cloud.*`, ' +
        '`file.*`, `http_request.*` and all of `unmapped.*` are simply not projected. Use `get_event` ' +
        "with the row's `metadata.uid` before concluding anything from an absence.",
    );
    parts.push(
      'Data with no promoted OCSF column lands under `unmapped.*`, which is the OCSF equivalent ' +
        "of UDM's `ext`. It is only visible via `get_event`.",
    );
    parts.push(
      'Read the `nanosiem://reference/ocsf` resource for the OCSF 1.9 class catalog and activity ' +
        'enums, the UDM->OCSF name cheat-sheet, the enum-int/label convention, and worked nPL ' +
        'examples. A query naming a field this deployment does not promote is rejected outright ' +
        '("Unknown canonical OCSF field") rather than silently matching nothing — that error means ' +
        'either you used a UDM name, or nothing here writes that path yet.',
    );
  } else if (profile.schema === 'udm') {
    parts.push(
      'This deployment stores events in the UDM schema: flat explicit columns (`src_ip`, ' +
        '`process_name`, `user`, `command_line`), with non-UDM data in the `ext` JSON column.',
    );
  }

  if (profile.backend === 'lake') {
    parts.push(
      'The query backend is the Iceberg + chDB security lake. Consequences that change how you ' +
        'work: raw SQL is REFUSED (nPL is the only query language); there is no `logs` ClickHouse ' +
        'table to select from; `explain_query` returns no compiled SQL; and a query that exceeds ' +
        'the scan budget is escalated to a durable background job instead of failing — `search` ' +
        'waits for it and tells you when that happened. Narrow the time window first; on the lake ' +
        'a tight window is dramatically cheaper than a wide one.',
    );
  } else if (profile.backend === 'clickhouse') {
    parts.push('The query backend is ClickHouse. Both nPL (`search`) and raw SQL (`search_sql`) are available.');
  } else {
    parts.push(
      'The query backend could not be determined from this nano build. `search` (nPL) works on ' +
        'every deployment; if `search_sql` is refused as unsupported, the deployment is lake-backed ' +
        'and nPL is the only query language.',
    );
  }

  return parts.join('\n\n');
}

import { TOOLS as AGENT_LANE_TOOLS } from './tools/agent-lane.js';
import { INGESTION_TOOLS } from './tools/ingestion.js';
import { describe, expect, it } from 'vitest';

import { TOOLS as ALERTS_TOOLS } from './tools/alerts.js';
import { TOOLS as CASES_TOOLS } from './tools/cases.js';
import { TOOLS as DASHBOARDS_TOOLS } from './tools/dashboards.js';
import { TOOLS as DETECTIONS_TOOLS } from './tools/detections.js';
import { TOOLS as ENRICHMENT_TOOLS } from './tools/enrichment.js';
import { TOOLS as MITRE_TOOLS } from './tools/mitre.js';
import { TOOLS as NOTEBOOKS_TOOLS } from './tools/notebooks.js';
import { TOOLS as PREVALENCE_TOOLS } from './tools/prevalence.js';
import { TOOLS as RECON_TOOLS } from './tools/recon.js';
import { TOOLS as RISK_TOOLS } from './tools/risk.js';
import { TOOLS as SEARCH_TOOLS } from './tools/search.js';
import { TOOLS as SYSTEM_TOOLS } from './tools/system.js';
import { TOOLS as SOAR_TOOLS } from './tools/soar.js';
import {
  CONFIRMATION_META_KEY,
  PERMISSION_REQUIREMENTS_META_KEY,
  TOOL_CONFIRMATIONS,
  missingConfirmation,
  TOOL_PERMISSION_REQUIREMENTS,
  withPermissionRequirements,
} from './tool-permissions.js';

const ALL_TOOLS = [
  ...SEARCH_TOOLS,
  ...AGENT_LANE_TOOLS,
  ...ALERTS_TOOLS,
  ...CASES_TOOLS,
  ...NOTEBOOKS_TOOLS,
  ...DASHBOARDS_TOOLS,
  ...DETECTIONS_TOOLS,
  ...PREVALENCE_TOOLS,
  ...RISK_TOOLS,
  ...ENRICHMENT_TOOLS,
  ...MITRE_TOOLS,
  ...SYSTEM_TOOLS,
  ...INGESTION_TOOLS,
  ...RECON_TOOLS,
  ...SOAR_TOOLS,
];

describe('tool permission metadata', () => {
  it('covers every exposed tool exactly once', () => {
    const names = ALL_TOOLS.map((tool) => tool.name);
    expect(new Set(names).size).toBe(names.length);
    expect(Object.keys(TOOL_PERMISSION_REQUIREMENTS).sort()).toEqual(
      [...names].sort(),
    );
  });

  it('publishes requirements in each tool _meta object', () => {
    const published = withPermissionRequirements(ALL_TOOLS);

    for (const tool of published) {
      expect(tool._meta[PERMISSION_REQUIREMENTS_META_KEY]).toEqual(
        TOOL_PERMISSION_REQUIREMENTS[tool.name],
      );
    }
  });

  it('keeps nPL and raw SQL as separate permission paths', () => {
    expect(TOOL_PERMISSION_REQUIREMENTS.search).toEqual({
      version: 1,
      alternatives: [{ allOf: ['search:execute'] }],
    });
    expect(TOOL_PERMISSION_REQUIREMENTS.search_sql).toEqual({
      version: 1,
      alternatives: [{ allOf: ['search:sql'] }],
    });
  });

  it('declares permissionless tools explicitly', () => {
    expect(TOOL_PERMISSION_REQUIREMENTS.health_check).toEqual({
      version: 1,
      alternatives: [{ allOf: [] }],
    });
    expect(TOOL_PERMISSION_REQUIREMENTS.validate_dashboard).toEqual({
      version: 1,
      alternatives: [{ allOf: [] }],
    });
  });

  it('keeps organizational context on read-only settings authority', () => {
    expect(TOOL_PERMISSION_REQUIREMENTS.get_org_context).toEqual({
      version: 1,
      alternatives: [
        { allOf: ['settings:view'], when: 'read-only settings authority' },
        { allOf: ['settings:ai'], when: 'legacy AI settings authority' },
      ],
    });
  });

  it('gates exactly the tools that take user_confirmed, and publishes the gate', () => {
    const takesConfirmation = ALL_TOOLS.filter((tool) =>
      Object.hasOwn((tool.inputSchema as { properties?: object }).properties ?? {}, 'user_confirmed'),
    ).map((tool) => tool.name);
    expect(Object.keys(TOOL_CONFIRMATIONS).sort()).toEqual(takesConfirmation.sort());
    for (const tool of withPermissionRequirements(ALL_TOOLS)) {
      expect(tool._meta[CONFIRMATION_META_KEY]).toEqual(TOOL_CONFIRMATIONS[tool.name]);
    }
  });

  it('requires confirmation unless the call is a dry run', () => {
    expect(missingConfirmation('run_soar_action', {})).toMatch(/external system/);
    expect(missingConfirmation('run_soar_action', { dry_run: true })).toBeUndefined();
    expect(missingConfirmation('run_soar_action', { user_confirmed: true })).toBeUndefined();
    expect(missingConfirmation('install_soar_pack', { dry_run: true })).toMatch(/workspace state/);
    expect(missingConfirmation('list_soar_packs', {})).toBeUndefined();
  });

  it('needs case scopes only when a SOAR run links a case', () => {
    expect(TOOL_PERMISSION_REQUIREMENTS.run_soar_action.alternatives).toEqual([
      { allOf: ['soar:run'], when: 'no case_id' },
      { allOf: ['soar:run', 'cases:view', 'cases:comment'], when: 'case_id links the run to a case (results post to its wall)' },
    ]);
  });
});

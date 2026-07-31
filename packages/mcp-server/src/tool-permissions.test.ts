import { describe, expect, it } from 'vitest';

import { TOOLS as ALERTS_TOOLS } from './tools/alerts.js';
import { TOOLS as CASES_TOOLS } from './tools/cases.js';
import { TOOLS as DASHBOARDS_TOOLS } from './tools/dashboards.js';
import { TOOLS as DETECTIONS_TOOLS } from './tools/detections.js';
import { TOOLS as ENRICHMENT_TOOLS } from './tools/enrichment.js';
import { TOOLS as MITRE_TOOLS } from './tools/mitre.js';
import { TOOLS as NOTEBOOKS_TOOLS } from './tools/notebooks.js';
import { TOOLS as ONBOARDING_TOOLS } from './tools/onboarding.js';
import { TOOLS as PARSERS_TOOLS } from './tools/parsers.js';
import { TOOLS as PREVALENCE_TOOLS } from './tools/prevalence.js';
import { TOOLS as RECON_TOOLS } from './tools/recon.js';
import { TOOLS as RISK_TOOLS } from './tools/risk.js';
import { TOOLS as SEARCH_TOOLS } from './tools/search.js';
import { TOOLS as SYSTEM_TOOLS } from './tools/system.js';
import {
  PERMISSION_REQUIREMENTS_META_KEY,
  TOOL_PERMISSION_REQUIREMENTS,
  withPermissionRequirements,
} from './tool-permissions.js';

const ALL_TOOLS = [
  ...SEARCH_TOOLS,
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
  ...PARSERS_TOOLS,
  ...ONBOARDING_TOOLS,
  ...RECON_TOOLS,
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
});

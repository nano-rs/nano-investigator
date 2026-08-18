import { describe, it, expect } from 'vitest';
import { getBuildParserPrompt } from './build-parser.js';

const text = (schema?: 'udm' | 'ocsf' | 'unknown') =>
  getBuildParserPrompt({ source_type: 'okta_system_log' }, schema).messages[0].content.text;

describe('build_parser prompt', () => {
  it('teaches the UDM output contract on a UDM deployment', () => {
    const prompt = text('udm');
    expect(prompt).toContain('.udm.timestamp');
    expect(prompt).toContain('%Y-%m-%d %H:%M:%S');
    expect(prompt).not.toContain('class_uid');
  });

  it('teaches the OCSF output contract on an OCSF deployment', () => {
    const prompt = text('ocsf');
    expect(prompt).toContain('class_uid');
    expect(prompt).toContain('type_uid = class_uid * 100 + activity_id');
    expect(prompt).toContain('uuid_v4()');
    // The whole point: a UDM-shaped parser on an OCSF deployment validates,
    // deploys, and populates nothing.
    expect(prompt).toContain('populates nothing');
  });

  it('does not send an OCSF author down the .udm path', () => {
    expect(text('ocsf')).not.toContain('.udm.timestamp');
  });

  it('makes the model determine the schema when discovery failed', () => {
    const prompt = text('unknown');
    expect(prompt).toContain('DETERMINE THIS FIRST');
    expect(prompt).toContain('get_schema');
    // Both contracts are described so it can act once it knows.
    expect(prompt).toContain('.udm.*');
    expect(prompt).toContain('class_uid');
  });

  it('defaults to the determine-first contract when no schema is passed', () => {
    expect(text()).toContain('DETERMINE THIS FIRST');
  });

  it('keeps the publish-not-deploy rule that makes an edit actually go live', () => {
    // NAN-2293: deploy ships the previously PUBLISHED version, so a saved edit
    // silently never reaches Vector.
    expect(text('ocsf')).toContain('publish_log_source');
    expect(text('ocsf')).toContain('NOT `deploy_log_source`');
  });

  it('still forbids assigning source_type on either schema', () => {
    expect(text('udm')).toContain('Never set `.source_type`');
    expect(text('ocsf')).toContain('Never set `.source_type`');
  });
});

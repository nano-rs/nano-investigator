/**
 * NAN-5271: the agent is taught OCSF paths only.
 *
 * Every prompt, resource, playbook, tool description and shipped skill must use
 * OCSF field paths (actor.user.name, device.hostname, src_endpoint.ip,
 * process.cmd_line, …) and OCSF enums (class_uid / activity_id / status_id /
 * disposition_id / logon_type_id). The legacy UDM short names still resolve on
 * the backend through an alias layer, but teaching them steers agents to
 * columns that are wrong or missing on OCSF classes.
 *
 * This scans the source text rather than the rendered prompts so a new file or
 * a new template branch is covered without registering it here.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SRC = dirname(fileURLToPath(import.meta.url));
const REPO = join(SRC, '..', '..', '..');

/** Short UDM names (and `*_unified`) that must never appear as a field. */
const BANNED_FIELD =
  /(?<![\w.$-])(src_ip|dest_ip|src_host|dest_host|process_name|command_line|parent_command_line|event_type|auth_result|ioc_matched|ioc_threat_type|email_from|email_to|email_subject|file_hash|status_code|bytes_in|bytes_out|[a-z_]+_unified)(?![\w.])/;
/** Bare `user=` / `action=` filters (OCSF: actor.user.name, disposition_id / activity_id). */
const BANNED_FILTER = /(?<![\w.$-])(user|action)\s*!?=(?!=)/;

/**
 * Files that legitimately name legacy fields: query-scope.ts RECOGNIZES them in
 * user-supplied queries (it must keep accepting old saved queries).
 */
const ALLOWED = new Set(['packages/mcp-server/src/tools/query-scope.ts']);

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name === 'fixtures') continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (/\.(ts|md)$/.test(name) && !name.endsWith('.test.ts')) out.push(path);
  }
  return out;
}

function taughtFiles(): string[] {
  const roots = [
    join(SRC, 'prompts'),
    join(SRC, 'resources'),
    join(SRC, 'tools'),
    join(SRC, 'index.ts'),
    join(REPO, 'skills'),
    join(REPO, '.claude', 'skills'),
    join(REPO, 'CLAUDE.md'),
    join(REPO, 'README.md'),
    join(REPO, 'GETTING_STARTED.md'),
  ];
  return roots.flatMap((root) => (statSync(root).isDirectory() ? walk(root) : [root]));
}

describe('OCSF-only guard (NAN-5271)', () => {
  it('covers the prompt, resource and skill sources', () => {
    const files = taughtFiles().map((f) => relative(REPO, f));
    expect(files).toContain('packages/mcp-server/src/prompts/hunt.ts');
    expect(files).toContain('packages/mcp-server/src/resources/playbooks.ts');
    expect(files).toContain('packages/mcp-server/src/resources/ocsf-schema.ts');
    expect(files.some((f) => f.startsWith('skills/'))).toBe(true);
  });

  it('teaches no UDM short names or *_unified fields', () => {
    const hits: string[] = [];
    for (const file of taughtFiles()) {
      const rel = relative(REPO, file);
      if (ALLOWED.has(rel)) continue;
      readFileSync(file, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          const m = line.match(BANNED_FIELD) ?? line.match(BANNED_FILTER);
          if (m) hits.push(`${rel}:${i + 1}: ${m[0]}`);
        });
    }
    expect(hits).toEqual([]);
  });

  it('the patterns catch the legacy forms', () => {
    for (const legacy of ['user="x"', 'src_ip="1.2.3.4"', 'by src_host', 'action=blocked', 'values(email_to)', 'user_unified']) {
      expect(BANNED_FIELD.test(legacy) || BANNED_FILTER.test(legacy), legacy).toBe(true);
    }
    for (const ocsf of ['actor.user.name="x"', 'src_endpoint.ip="1.2.3.4"', 'traffic.bytes_in', 'email.to', 'disposition_id=2', 'user_confirmed=true']) {
      expect(BANNED_FIELD.test(ocsf) || BANNED_FILTER.test(ocsf), ocsf).toBe(false);
    }
  });
});

/**
 * Local recon tools for pivt — whois / DNS / ASN lookups that run the analyst's
 * OWN binaries on the LOCAL machine. The point: live, current data (DNS as it
 * resolves right now, current registration, who routes an IP today) from the
 * analyst's network vantage point — not the SIEM's cached enrichment, and no
 * server round-trip.
 *
 * SAFETY — this is what makes it OK to run in pivt's Locked (injection-exposed)
 * mode instead of behind Full/Bash:
 *   1. Every argument is validated to an IP / domain / record-type shape before
 *      it's used. A `; rm -rf /` smuggled in as an "IP" simply fails validation.
 *   2. Every command is spawned with `execFile` (argv) — NEVER a shell. Even if a
 *      weird value slipped past validation, it is a single literal argument to
 *      `whois`/`dig`, never interpreted by a shell.
 *   3. Read-only lookups only, each timed out and output-capped.
 * There is no code path here that runs an arbitrary command.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

const TIMEOUT_MS = 10_000;
const MAX_OUTPUT = 256 * 1024;

export type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const ok = (text: string): ToolResult => ({ content: [{ type: 'text', text: text || '(no output)' }] });
const fail = (text: string): ToolResult => ({ content: [{ type: 'text', text }], isError: true });

// ── Validators (shell-safe shapes only) ──────────────────────────────────────
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-fA-F:]{2,45}$/; // loose but strictly hex/colon — no shell metacharacters
const DOMAIN = /^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;
const DNS_TYPES = new Set(['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'CAA', 'SRV', 'ANY']);

const isIp = (s: string) => IPV4.test(s) || IPV6.test(s);
const isDomain = (s: string) => DOMAIN.test(s);

// ── Safe runner: argv only, timed out, output-capped ──────────────────────────
async function safeRun(cmd: string, args: string[]): Promise<ToolResult> {
  try {
    const { stdout } = await run(cmd, args, { timeout: TIMEOUT_MS, maxBuffer: MAX_OUTPUT });
    return ok(stdout.trim());
  } catch (e) {
    const anyErr = e as { code?: string; killed?: boolean; stdout?: string; stderr?: string; message?: string };
    if (anyErr.code === 'ENOENT') return fail(`\`${cmd}\` is not installed on this machine.`);
    if (anyErr.killed) return fail(`\`${cmd}\` timed out after ${TIMEOUT_MS / 1000}s.`);
    // whois/dig frequently exit non-zero yet still print useful output.
    const out = (anyErr.stdout || anyErr.stderr || '').trim();
    return out ? ok(out) : fail(anyErr.message ?? String(e));
  }
}

/** Team Cymru DNS TXT lookup (free, no API key) — strips the surrounding quotes. */
async function digTxt(name: string): Promise<string> {
  const { stdout } = await run('dig', ['+short', 'TXT', name], {
    timeout: TIMEOUT_MS,
    maxBuffer: MAX_OUTPUT,
  });
  return stdout.trim().replace(/^"|"$/g, '').replace(/"\s*"/g, '');
}

export const TOOLS = [
  {
    name: 'whois',
    annotations: { readOnlyHint: true },
    description:
      "Live WHOIS registration for a domain or IP — registrar/owner, org, creation/expiry dates, name servers, abuse contact. Runs the LOCAL `whois` against the current registry, so it reflects reality NOW, not the SIEM's cached enrichment. Use to attribute a domain or IP during an investigation.",
    inputSchema: {
      type: 'object' as const,
      properties: {
        target: { type: 'string', description: 'Domain (e.g. example.com) or IP address to look up.' },
      },
      required: ['target'],
    },
  },
  {
    name: 'dns_lookup',
    annotations: { readOnlyHint: true },
    description:
      'Live DNS resolution for a hostname — the CURRENT records: A/AAAA (where it points now), MX (mail), TXT (SPF/DKIM/verification), NS, CNAME, etc. Runs the local `dig`. Use to see where a domain resolves right now, catch fast-flux, or read SPF/TXT.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Hostname / domain to resolve.' },
        type: {
          type: 'string',
          description: 'Record type: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV, ANY (default A).',
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'reverse_dns',
    annotations: { readOnlyHint: true },
    description:
      'Reverse DNS (PTR) for an IP — the hostname it claims. Runs the local `dig -x`. Use to sanity-check an IP\'s identity (e.g. does a "google" IP actually PTR to google).',
    inputSchema: {
      type: 'object' as const,
      properties: { ip: { type: 'string', description: 'IP address to reverse-resolve.' } },
      required: ['ip'],
    },
  },
  {
    name: 'asn_lookup',
    annotations: { readOnlyHint: true },
    description:
      "ASN / BGP origin for an IPv4 — the autonomous system (AS number + name), announced prefix, country, and registry, via Team Cymru's free DNS service (no API key). Use to see who ROUTES an IP (hosting provider / ISP / cloud) and spot traffic from a suspicious network.",
    inputSchema: {
      type: 'object' as const,
      properties: { ip: { type: 'string', description: 'IPv4 address to look up.' } },
      required: ['ip'],
    },
  },
];

export async function handleReconTool(
  name: string,
  args: Record<string, unknown>
): Promise<ToolResult> {
  switch (name) {
    case 'whois': {
      const target = String(args.target ?? '').trim();
      if (!isDomain(target) && !isIp(target)) return fail('`target` must be a domain or IP address.');
      return safeRun('whois', [target]);
    }

    case 'dns_lookup': {
      const host = String(args.name ?? '').trim();
      const type = String(args.type ?? 'A').toUpperCase();
      if (!isDomain(host)) return fail('`name` must be a domain / hostname.');
      if (!DNS_TYPES.has(type)) return fail(`\`type\` must be one of: ${[...DNS_TYPES].join(', ')}.`);
      return safeRun('dig', ['+short', host, type]);
    }

    case 'reverse_dns': {
      const ip = String(args.ip ?? '').trim();
      if (!isIp(ip)) return fail('`ip` must be an IP address.');
      return safeRun('dig', ['+short', '-x', ip]);
    }

    case 'asn_lookup': {
      const ip = String(args.ip ?? '').trim();
      if (!IPV4.test(ip)) return fail('`ip` must be an IPv4 address (the Cymru ASN lookup is IPv4 for now).');
      try {
        const reversed = ip.split('.').reverse().join('.');
        const origin = await digTxt(`${reversed}.origin.asn.cymru.com`);
        if (!origin) return ok(`No ASN / BGP origin found for ${ip}.`);
        // "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
        const [asn, prefix, cc, registry] = origin.split('|').map((s) => s.trim());
        let asName = '';
        // Guard: `asn` comes from the (external) Cymru response, and it's about to
        // become part of the next lookup's name. It's argv (no shell) and Cymru is
        // trusted, but require it to be purely numeric so external data can never
        // shape the arg at all.
        if (/^\d+$/.test(asn)) {
          // "15169 | US | arin | 2000-03-30 | GOOGLE, US"
          const asInfo = await digTxt(`AS${asn}.asn.cymru.com`).catch(() => '');
          asName = asInfo.split('|').pop()?.trim() ?? '';
        }
        return ok(
          [
            `IP:       ${ip}`,
            `ASN:      AS${asn}${asName ? ` (${asName})` : ''}`,
            `Prefix:   ${prefix}`,
            `Country:  ${cc}`,
            `Registry: ${registry}`,
          ].join('\n')
        );
      } catch (e) {
        const anyErr = e as { code?: string; message?: string };
        if (anyErr.code === 'ENOENT')
          return fail('`dig` is not installed on this machine (needed for the Cymru ASN lookup).');
        return fail(anyErr.message ?? String(e));
      }
    }

    default:
      return fail(`Unknown recon tool: ${name}`);
  }
}

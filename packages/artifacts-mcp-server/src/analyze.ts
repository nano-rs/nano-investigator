/**
 * Local static-analysis tools for pivt — malware/file triage that runs the
 * analyst's OWN binaries on a LOCAL specimen file (the raw bytes the desktop
 * stashed in a temp dir). The point: real static analysis (exiftool metadata,
 * YARA matches, Office-macro/PDF/PE structure, fuzzy hashes) to GROUND pivt's
 * verdict — not the LLM guessing from printable strings alone.
 *
 * SAFETY — this is what makes it OK to run in pivt's Locked (injection-exposed)
 * mode, key-less, on attacker-controlled specimen bytes:
 *   1. `path` is resolved to a real regular file and, when NANO_ARTIFACTS_DIR is
 *      set (the desktop sets it), CONFINED to that directory — a prompt cannot
 *      point a tool at `/etc/shadow`. Size-capped.
 *   2. Every command is spawned with `execFile` (argv) — NEVER a shell. A hostile
 *      byte in a filename or a tool's output can never be interpreted by a shell.
 *   3. Read-only inspection only, each timed out and output-capped.
 *   4. Every tool degrades gracefully when its binary is missing (ENOENT → a
 *      clear "install X" note); `capabilities` reports the whole inventory.
 * There is no code path here that runs an arbitrary command or writes the file.
 */

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { promisify } from 'node:util';
import { resolve, sep } from 'node:path';

const run = promisify(execFile);

const TIMEOUT_MS = 30_000;
const MAX_BUFFER = 8 * 1024 * 1024; // hard cap on a tool's stdout before it's killed
const MAX_TEXT = 256 * 1024; // cap on the text we hand back to pivt
const MAX_FILE_BYTES = 64 * 1024 * 1024; // specimen size cap
const MAX_STRINGS = 1500;

// Confinement: when the desktop sets NANO_ARTIFACTS_DIR, every `path` must resolve
// inside it. Unset (standalone/dev) ⇒ any existing regular file is allowed.
let ALLOWED_DIR: string | null = null;
if (process.env.NANO_ARTIFACTS_DIR) {
  try {
    ALLOWED_DIR = realpathSync(resolve(process.env.NANO_ARTIFACTS_DIR));
  } catch {
    ALLOWED_DIR = resolve(process.env.NANO_ARTIFACTS_DIR);
  }
}

export type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

const ok = (text: string): ToolResult => {
  let t = text && text.length ? text : '(no output)';
  if (t.length > MAX_TEXT) t = `${t.slice(0, MAX_TEXT)}\n… [truncated at ${MAX_TEXT} chars]`;
  return { content: [{ type: 'text', text: t }] };
};
const fail = (text: string): ToolResult => ({ content: [{ type: 'text', text }], isError: true });

// ── Specimen path resolution + confinement ────────────────────────────────────
type Resolved = { path: string; size: number };

export async function resolveSpecimen(pathArg: unknown): Promise<Resolved | ToolResult> {
  const raw = String(pathArg ?? '').trim();
  if (!raw) return fail('`path` is required — the local specimen file to inspect.');
  let real: string;
  let size: number;
  try {
    real = await realpath(resolve(raw));
    const st = await stat(real);
    if (!st.isFile()) return fail(`Not a regular file: ${raw}`);
    size = st.size;
  } catch {
    return fail(`No such file: ${raw}`);
  }
  if (ALLOWED_DIR && real !== ALLOWED_DIR && !real.startsWith(ALLOWED_DIR + sep)) {
    return fail('`path` is outside the allowed specimen directory.');
  }
  if (size > MAX_FILE_BYTES) {
    return fail(`File too large (${size} bytes > ${MAX_FILE_BYTES}). Static analysis is skipped.`);
  }
  return { path: real, size };
}

const isResult = (v: Resolved | ToolResult): v is ToolResult =>
  (v as ToolResult).content !== undefined;

// ── Safe runner: argv only, timed out, output-capped ──────────────────────────
type RawRun = { installed: boolean; stdout: string; stderr: string; message?: string; timedOut?: boolean };

async function rawRun(cmd: string, args: string[]): Promise<RawRun> {
  try {
    const { stdout, stderr } = await run(cmd, args, { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER });
    return { installed: true, stdout: stdout ?? '', stderr: stderr ?? '' };
  } catch (e) {
    const err = e as { code?: string; killed?: boolean; stdout?: string; stderr?: string; message?: string };
    if (err.code === 'ENOENT') return { installed: false, stdout: '', stderr: '' };
    return {
      installed: true,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
      message: err.message,
      timedOut: err.killed,
    };
  }
}

/** Run a tool and dump its output; ENOENT → a clear "not installed" note. */
async function safeRun(cmd: string, args: string[], installHint: string): Promise<ToolResult> {
  const r = await rawRun(cmd, args);
  if (!r.installed) return fail(`\`${cmd}\` is not installed on this machine — ${installHint}`);
  if (r.timedOut) return fail(`\`${cmd}\` timed out after ${TIMEOUT_MS / 1000}s.`);
  const out = (r.stdout || r.stderr).trim();
  return out ? ok(out) : r.message ? fail(r.message) : ok('(no output)');
}

/** True when the command EXISTS (any exit but ENOENT), for tools whose version
 *  probe legitimately exits non-zero. */
async function probePresent(cmd: string, args: string[]): Promise<boolean> {
  const r = await rawRun(cmd, args);
  return r.installed;
}

// Python is `python3` on macOS/Linux but `py -3` / `python` on Windows — resolve
// per platform rather than hardcoding, so pe_info works wherever Python is.
const PYTHONS: [string, string[]][] =
  process.platform === 'win32'
    ? [['py', ['-3']], ['python', []], ['python3', []]]
    : [['python3', []], ['python', []]];

/** Run the first Python that EXISTS on this machine with the given trailing args.
 *  `installed:false` only when no Python interpreter is found at all. */
async function runPython(argsAfter: string[]): Promise<RawRun> {
  for (const [cmd, pre] of PYTHONS) {
    const r = await rawRun(cmd, [...pre, ...argsAfter]);
    if (r.installed) return r;
  }
  return { installed: false, stdout: '', stderr: '' };
}

// ── PE analysis via python-pefile (imphash comes free from it) ────────────────
// chr(0)/chr(10) avoid every backslash escape so this survives being a JS string.
const PE_INFO_PY = `
import sys
try:
    import pefile
except Exception:
    print("pefile not installed (pip install pefile) - PE analysis unavailable."); sys.exit(0)
try:
    pe = pefile.PE(sys.argv[1])
except Exception as e:
    print("Not a PE file or parse failed: " + str(e)); sys.exit(0)
import datetime
L = []
try:
    L.append("imphash:   " + pe.get_imphash())
except Exception:
    pass
fh = pe.FILE_HEADER
oh = pe.OPTIONAL_HEADER
L.append("machine:   " + hex(fh.Machine))
try:
    ts = datetime.datetime.utcfromtimestamp(fh.TimeDateStamp).isoformat() + "Z"
except Exception:
    ts = str(fh.TimeDateStamp)
L.append("compiled:  " + ts)
L.append("subsystem: " + str(oh.Subsystem))
L.append("is_dll:    " + str(bool(fh.Characteristics & 0x2000)))
L.append("")
L.append("sections:")
for s in pe.sections:
    name = s.Name.decode("latin-1", "replace").split(chr(0))[0]
    L.append("  %-9s raw=%-8d vsize=%-8d entropy=%.2f" % (name, s.SizeOfRawData, s.Misc_VirtualSize, s.get_entropy()))
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    L.append("")
    L.append("imports:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("latin-1", "replace")
        funcs = [imp.name.decode("latin-1", "replace") for imp in entry.imports if imp.name]
        shown = ", ".join(funcs[:25])
        if len(funcs) > 25:
            shown = shown + (" (+%d more)" % (len(funcs) - 25))
        L.append("  " + dll + ": " + shown)
print(chr(10).join(L))
`;

// ── In-process helpers (always available, no external deps) ───────────────────
function extractStrings(buf: Buffer, minLen: number): { ascii: string[]; wide: string[] } {
  const ascii: string[] = [];
  let cur = '';
  for (let i = 0; i < buf.length && ascii.length < MAX_STRINGS; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) cur += String.fromCharCode(b);
    else {
      if (cur.length >= minLen) ascii.push(cur);
      cur = '';
    }
  }
  if (cur.length >= minLen && ascii.length < MAX_STRINGS) ascii.push(cur);

  const wide: string[] = [];
  cur = '';
  for (let i = 0; i + 1 < buf.length && wide.length < MAX_STRINGS; i += 2) {
    const lo = buf[i];
    const hi = buf[i + 1];
    if (hi === 0 && lo >= 0x20 && lo <= 0x7e) cur += String.fromCharCode(lo);
    else {
      if (cur.length >= minLen) wide.push(cur);
      cur = '';
    }
  }
  if (cur.length >= minLen && wide.length < MAX_STRINGS) wide.push(cur);
  return { ascii, wide };
}

// ── Tool definitions (pivt reads these to decide when to call) ────────────────
const PATH_PROP = {
  path: { type: 'string', description: 'Absolute path to the local specimen file to inspect.' },
};

export const TOOLS = [
  {
    name: 'capabilities',
    annotations: { readOnlyHint: true },
    description:
      'Report which local static-analysis tools are installed on this machine (exiftool, file, yara, olevba, pdfid, ssdeep, python-pefile). Call this FIRST when triaging so you only attempt the tools that are available, and tell the analyst what to install for deeper coverage.',
    inputSchema: { type: 'object' as const, properties: {}, required: [] },
  },
  {
    name: 'hashes',
    annotations: { readOnlyHint: true },
    description:
      'Compute file hashes for a specimen: md5, sha1, sha256 (always), plus the ssdeep fuzzy hash when installed. Use to pivot on prevalence/threat-intel and to cluster near-identical samples. (imphash is PE-specific — see pe_info.)',
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
  {
    name: 'strings',
    annotations: { readOnlyHint: true },
    description:
      'Extract printable ASCII and UTF-16LE strings from the raw specimen bytes (more thorough than the ingest-time preview). Surfaces URLs, IPs, commands, registry keys, mutexes, and embedded scripts. Use to find IOCs and behavioural hints.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ...PATH_PROP,
        min: { type: 'number', description: 'Minimum run length (default 6).' },
      },
      required: ['path'],
    },
  },
  {
    name: 'filetype',
    annotations: { readOnlyHint: true },
    description:
      "Identify the TRUE file type via libmagic (`file`) plus MIME type — regardless of extension. Use to catch a masqueraded file (e.g. a .pdf that is really a PE, or a .jpg that is a script).",
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
  {
    name: 'exiftool',
    annotations: { readOnlyHint: true },
    description:
      'Full metadata dump via exiftool (grouped) — authorship, tooling, timestamps, embedded objects, document properties, and often-telling producer/creator fields. Use for provenance and to spot maldoc / phishing-lure indicators.',
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
  {
    name: 'yara',
    annotations: { readOnlyHint: true },
    description:
      'Scan the specimen with YARA rules and report matches (rule name + matched strings). Provide a rules file/dir via `rules`, or set NANO_YARA_RULES. Use to identify known malware families, packers, capabilities, and toolmarks.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ...PATH_PROP,
        rules: { type: 'string', description: 'Path to a .yar file or a directory of rules. Defaults to $NANO_YARA_RULES.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'olevba',
    annotations: { readOnlyHint: true },
    description:
      'Analyse VBA macros in an OLE / OpenXML Office document (oletools olevba): extracts macro source and flags suspicious patterns (AutoOpen, Shell, PowerShell, downloads, obfuscation). Use on doc/docm/xls/xlsm/ppt specimens.',
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
  {
    name: 'pdfid',
    annotations: { readOnlyHint: true },
    description:
      'Summarise a PDF\'s structure and risk indicators (pdfid): /JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile, /AA counts. Use to triage a suspicious PDF without opening it.',
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
  {
    name: 'pe_info',
    annotations: { readOnlyHint: true },
    description:
      'Parse a Windows PE (exe/dll) via python-pefile: imphash, machine, compile timestamp, subsystem, per-section entropy (packing signal), and imported DLLs/functions (capability signal). Use on PE specimens for structure and imphash pivoting.',
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
  {
    name: 'run_all',
    annotations: { readOnlyHint: true },
    description:
      "Run the full triage set — filetype, hashes, strings, exiftool, pe_info, olevba, pdfid — in one call and return each tool's output. Use this to get a complete static-analysis pass on a specimen at once.",
    inputSchema: { type: 'object' as const, properties: { ...PATH_PROP }, required: ['path'] },
  },
];

// ── Dispatch ──────────────────────────────────────────────────────────────────
export async function handleArtifactTool(
  name: string,
  args: Record<string, unknown>
): Promise<ToolResult> {
  if (name === 'capabilities') return capabilities();

  // Every other tool needs a resolved, confined specimen path.
  const resolved = await resolveSpecimen(args.path);
  if (isResult(resolved)) return resolved;
  const { path } = resolved;

  switch (name) {
    case 'hashes':
      return hashes(path);
    case 'strings':
      return stringsTool(path, Math.max(4, Math.min(64, Number(args.min) || 6)));
    case 'filetype':
      return filetype(path);
    case 'exiftool':
      return exiftoolTool(path);
    case 'yara':
      return yara(path, args.rules);
    case 'olevba':
      return olevbaTool(path);
    case 'pdfid':
      return pdfidTool(path);
    case 'pe_info':
      return peInfo(path);
    case 'run_all': {
      const findings = await runAll(path);
      const text = findings.map((f) => `=== ${f.tool} ===\n${f.output}`).join('\n\n');
      return ok(text);
    }
    default:
      return fail(`Unknown artifacts tool: ${name}`);
  }
}

// ── Named per-tool wrappers so the dispatch and runAll share ONE code path per
//    tool. exiftool/olevba/pdfid are thin argv-only `safeRun` calls; extracting
//    them keeps the install hints in a single place.
async function exiftoolTool(path: string): Promise<ToolResult> {
  return safeRun('exiftool', ['-g1', '-a', '-u', path], 'install: brew install exiftool');
}

async function olevbaTool(path: string): Promise<ToolResult> {
  return safeRun('olevba', [path], 'install: pip install oletools');
}

async function pdfidTool(path: string): Promise<ToolResult> {
  return safeRun('pdfid', [path], 'install: pip install pdfid (Didier Stevens)');
}

// ── Full triage in one pass ───────────────────────────────────────────────────
/** One finding from {@link runAll}: a tool name, whether it succeeded, and its
 *  text output (the tool's `content[0].text`). */
export type ToolFinding = { tool: string; ok: boolean; output: string };

/**
 * Run the whole static-analysis triage set on an ALREADY-resolved specimen path
 * and return a structured finding per tool. YARA is intentionally skipped — it
 * needs external rules. Tools are independent, so they run concurrently.
 */
export async function runAll(path: string): Promise<ToolFinding[]> {
  const jobs: [string, Promise<ToolResult>][] = [
    ['filetype', filetype(path)],
    ['hashes', hashes(path)],
    ['strings', stringsTool(path, 6)],
    ['exiftool', exiftoolTool(path)],
    ['pe_info', peInfo(path)],
    ['olevba', olevbaTool(path)],
    ['pdfid', pdfidTool(path)],
  ];
  const results = await Promise.all(jobs.map(([, p]) => p));
  return jobs.map(([tool], i) => {
    const r = results[i];
    return { tool, ok: !r.isError, output: r.content[0]?.text ?? '' };
  });
}

async function capabilities(): Promise<ToolResult> {
  const checks: [string, Promise<boolean>, string][] = [
    ['exiftool', probePresent('exiftool', ['-ver']), 'brew install exiftool (Windows: exiftool.exe)'],
    ['file', probePresent('file', ['--version']), 'macOS/Linux built-in; Windows via Git Bash/MSYS'],
    ['yara', probePresent('yara', ['--version']), 'brew install yara (Windows: yara64.exe)'],
    ['olevba', probePresent('olevba', ['-h']), 'pip install oletools'],
    ['pdfid', probePresent('pdfid', ['--version']), 'pip install pdfid'],
    ['ssdeep', probePresent('ssdeep', ['-h']), 'brew install ssdeep'],
    ['python+pefile', pythonHasPefile(), 'install Python (win: py) + pip install pefile'],
  ];
  const rows = await Promise.all(
    checks.map(async ([tool, p, hint]) => {
      const present = await p;
      return `  ${present ? '✓' : '✗'} ${tool.padEnd(16)}${present ? 'available' : 'missing — ' + hint}`;
    })
  );
  const note = ALLOWED_DIR
    ? `\nspecimen dir: ${ALLOWED_DIR} (paths confined here)`
    : '\nspecimen dir: (unconfined — NANO_ARTIFACTS_DIR not set)';
  return ok(['static-analysis tool inventory:', ...rows, note].join('\n'));
}

async function hashes(path: string): Promise<ToolResult> {
  const buf = await readFile(path);
  const lines = [
    `md5:    ${createHash('md5').update(buf).digest('hex')}`,
    `sha1:   ${createHash('sha1').update(buf).digest('hex')}`,
    `sha256: ${createHash('sha256').update(buf).digest('hex')}`,
  ];
  const fuzzy = await rawRun('ssdeep', ['-b', '-s', path]);
  if (!fuzzy.installed) {
    lines.push('ssdeep: (not installed — brew install ssdeep)');
  } else {
    // ssdeep output: a header line then "hash,filename"; take the hash field.
    const last = fuzzy.stdout.trim().split('\n').pop() ?? '';
    const h = last.split(',')[0]?.trim();
    lines.push(`ssdeep: ${h && h.includes(':') ? h : '(no hash)'}`);
  }
  lines.push('imphash: (PE only — run pe_info)');
  return ok(lines.join('\n'));
}

async function stringsTool(path: string, minLen: number): Promise<ToolResult> {
  const buf = await readFile(path);
  const { ascii, wide } = extractStrings(buf, minLen);
  const parts: string[] = [];
  parts.push(`ascii (${ascii.length}${ascii.length >= MAX_STRINGS ? '+, capped' : ''}, min ${minLen}):`);
  parts.push(ascii.join('\n'));
  if (wide.length) {
    parts.push('');
    parts.push(`utf-16le (${wide.length}${wide.length >= MAX_STRINGS ? '+, capped' : ''}):`);
    parts.push(wide.join('\n'));
  }
  return ok(parts.join('\n'));
}

async function peInfo(path: string): Promise<ToolResult> {
  const r = await runPython(['-c', PE_INFO_PY, path]);
  if (!r.installed) {
    return fail('Python is not installed on this machine — pe_info needs Python (win: `py`) + pip install pefile.');
  }
  if (r.timedOut) return fail(`pe_info timed out after ${TIMEOUT_MS / 1000}s.`);
  const out = (r.stdout || r.stderr).trim();
  return out ? ok(out) : r.message ? fail(r.message) : ok('(no output)');
}

/** Strict: a Python interpreter exists AND `import pefile` exits cleanly. */
async function pythonHasPefile(): Promise<boolean> {
  const r = await runPython(['-c', 'import pefile']);
  return r.installed && !r.message && !r.timedOut;
}

async function filetype(path: string): Promise<ToolResult> {
  const type = await rawRun('file', ['-b', path]);
  if (!type.installed) {
    return fail('`file` is not installed on this machine — built in on macOS/Linux; on Windows use Git Bash/MSYS or a libmagic port.');
  }
  const mime = await rawRun('file', ['-b', '--mime-type', path]);
  const lines = [`type: ${type.stdout.trim() || '(unknown)'}`];
  if (mime.installed && mime.stdout.trim()) lines.push(`mime: ${mime.stdout.trim()}`);
  return ok(lines.join('\n'));
}

async function yara(path: string, rulesArg: unknown): Promise<ToolResult> {
  const rules = String(rulesArg ?? process.env.NANO_YARA_RULES ?? '').trim();
  if (!rules) {
    return fail(
      'No YARA rules configured. Pass `rules` (a .yar file or directory) or set NANO_YARA_RULES.'
    );
  }
  let rulesReal: string;
  let isDir = false;
  try {
    rulesReal = await realpath(resolve(rules));
    isDir = (await stat(rulesReal)).isDirectory();
  } catch {
    return fail(`YARA rules path not found: ${rules}`);
  }
  const args = isDir ? ['-w', '-r', rulesReal, path] : ['-w', rulesReal, path];
  const r = await rawRun('yara', args);
  if (!r.installed) return fail('`yara` is not installed on this machine — brew install yara.');
  if (r.message && !r.stdout) return fail((r.stderr || r.message).trim());
  const out = r.stdout.trim();
  return ok(out || 'No YARA rules matched.');
}

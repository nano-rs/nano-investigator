/**
 * Output redaction shared by tools that surface tenant configuration
 * (ingestion, SOAR). Drops credential-shaped keys and scrubs secret-shaped
 * text (private keys, key=value secrets, bearer tokens, URL userinfo/query).
 */
export const sensitive = (key: string) =>
  /(?:password|secret|token|apikey|authorization|privatekey|vendorcredentials|revealpublickey)/i.test(
    key.replace(/[^a-z0-9]/gi, ""),
  ) || ["credentials", "credential", "sealed_token", "sealed_payload"].includes(key.toLowerCase());
export function cleanText(value: string): string {
  return value
    .replace(
      /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,
      "[REDACTED PRIVATE KEY]",
    )
    .replace(
      /((?:password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)/gi,
      "$1[REDACTED]",
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+/gi, "Bearer [REDACTED]")
    .replace(/https?:\/\/[^\s"'<>]+/g, (raw) => {
      try {
        const url = new URL(raw);
        url.username = "";
        url.password = "";
        for (const key of [...url.searchParams.keys()])
          if (sensitive(key)) url.searchParams.set(key, "[REDACTED]");
        return url.toString();
      } catch {
        return "[invalid URL]";
      }
    });
}
/**
 * Drop credential-shaped keys and scrub secret-shaped text.
 *
 * `keep` names keys whose subtrees are documents the caller may read back and
 * write again (a SOAR flow definition, a connection's non-secret config):
 * dropping a key or truncating depth there would silently corrupt a
 * read-modify-write. Their keys are preserved; their strings are still scrubbed.
 */
export function redact(value: unknown, depth = 0, keep?: ReadonlySet<string>): unknown {
  if (depth > 16) return "[depth limit]";
  if (typeof value === "string") return cleanText(value);
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1, keep));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => keep?.has(key) || !sensitive(key))
        .map(([key, item]) => [key, keep?.has(key) ? scrubStrings(item) : redact(item, depth + 1, keep)]),
    );
  return value;
}

/** Scrub secret-shaped text in every string, preserving structure. */
export function scrubStrings(value: unknown, depth = 0): unknown {
  if (depth > 256) throw new Error("document nesting exceeds 256 levels");
  if (typeof value === "string") return cleanText(value);
  if (Array.isArray(value)) return value.map((item) => scrubStrings(item, depth + 1));
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrubStrings(item, depth + 1)]));
  return value;
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Best-effort scrub of a password from command output. Covers common
 * encodings (base64 with and without padding, hex, URL-encoded, reversed).
 *
 * This is NOT a security boundary — anyone running a shell command can
 * defeat it with custom encoding, bitwise ops, or network exfiltration.
 * It's defense-in-depth against accidental leaks (e.g. \`env | grep PASS\`,
 * \`echo $PASSWORD\`). See \`docs/threat-model.md\` — \`ap_run\` is a
 * privileged escape hatch.
 */
export function scrubPassword(s: string, password: string): string {
  if (!password) return s;

  const variants = new Set<string>();
  variants.add(password);
  variants.add(password.split("").reverse().join(""));

  try {
    variants.add(Buffer.from(password, "utf-8").toString("base64"));
    // Some encoders strip "=" padding
    variants.add(
      Buffer.from(password, "utf-8").toString("base64").replace(/=+$/, ""),
    );
    variants.add(Buffer.from(password, "utf-8").toString("hex"));
    variants.add(encodeURIComponent(password));
  } catch {
    // Fall back to plain-string replacement if any encoding throws
  }

  // Replace longest first — otherwise we'd partial-match a shorter variant
  // inside a longer one (e.g., raw password inside its base64 string)
  const ordered = [...variants].sort((a, b) => b.length - a.length);
  let out = s;
  for (const v of ordered) {
    if (!v) continue;
    out = out.replace(new RegExp(escapeRegExp(v), "g"), "***REDACTED***");
  }
  return out;
}

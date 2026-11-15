import type { ScanFinding, Severity } from "./types.js";

// When findings compete (same file+line, or same secret), the most specific
// fixId wins. Anything not listed here ranks 0.
const SPECIFICITY: Record<string, number> = {
  SEC_SUPABASE_SERVICE_ROLE_CLIENT: 3,
  SEC_SECRET_CLIENT_EXPOSED: 2,
  SEC_SECRET_HARDCODED: 1,
  SEC_ENV_COMMITTED: 1,
};
export const specificity = (f: ScanFinding) => SPECIFICITY[f.fixId] ?? 0;

/**
 * The secret rules that can flag the same secret on the same line under
 * different fixIds. Only these compete in dedupe; every other rule's findings
 * (other security checks, all privacy rules) are separate problems and stay.
 */
export const SECRET_RULE_IDS = new Set(["leaked-keys", "committed-env", "client-exposed", "service-role-client"]);

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Whether the finding sits on the line that holds the value (a .env line or a hardcoded key), not a read of it. */
// Rules give a value identity only to findings on the value itself; reads of an env var carry just its name.
const holdsValue = (f: ScanFinding) => (f.secretIds ?? []).some((id) => id.startsWith("value:"));

const byLocation = (a: ScanFinding, b: ScanFinding) =>
  (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0);

/** Most important first: worst severity, most specific fixId, the line holding the value, then location. */
function importance(a: ScanFinding, b: ScanFinding): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    specificity(b) - specificity(a) ||
    Number(holdsValue(b)) - Number(holdsValue(a)) ||
    byLocation(a, b)
  );
}

/**
 * Same secret, one finding: findings that share a secret identity (the same
 * value hash or the same env var name) become one finding at the most
 * important location, with the other places in `alsoAt` and the other
 * fixIds' fixes in `alsoFixes`. Findings with no secret identity pass through.
 * The secret identities are dropped from the result, so they can't leak into output.
 */
export function groupSameSecret(findings: ScanFinding[]): ScanFinding[] {
  // Union-find over finding indexes, joined by shared secret identities.
  const parent = findings.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const owner = new Map<string, number>();
  findings.forEach((f, i) => {
    for (const id of f.secretIds ?? []) {
      const other = owner.get(id);
      if (other === undefined) owner.set(id, i);
      else parent[find(i)] = find(other);
    }
  });

  const groups = new Map<number, ScanFinding[]>();
  findings.forEach((f, i) => {
    const root = find(i);
    groups.set(root, [...(groups.get(root) ?? []), f]);
  });

  const result: ScanFinding[] = [];
  for (const members of groups.values()) {
    const [kept, ...others] = [...members].sort(importance);
    const { secretIds: _drop, ...finding } = kept;
    if (others.length > 0) {
      const seen = new Set([`${kept.file}:${kept.line}`]);
      const alsoAt = [...others]
        .sort(byLocation)
        .filter((f) => !seen.has(`${f.file}:${f.line}`) && seen.add(`${f.file}:${f.line}`))
        .map((f) => ({ file: f.file, line: f.line }));
      const fixIds = new Set([kept.fixId]);
      const alsoFixes = others
        .filter((f) => !fixIds.has(f.fixId) && fixIds.add(f.fixId))
        .map((f) => ({ fixId: f.fixId, fix: f.fix }));
      if (alsoAt.length > 0) finding.alsoAt = alsoAt;
      if (alsoFixes.length > 0) finding.alsoFixes = alsoFixes;
    }
    result.push(finding);
  }
  return result;
}

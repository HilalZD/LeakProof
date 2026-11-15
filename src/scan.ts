import { performance } from "node:perf_hooks";
import { groupSameSecret, SECRET_RULE_IDS, specificity } from "./group.js";
import { createProjectContext } from "./lib/files.js";
import { isIgnored, loadIgnoreFile } from "./lib/ignore.js";
import { rules as defaultRules } from "./rules/index.js";
import { CheckSkipped, type Rule, type ScanFinding, type ScannerRule } from "./types.js";

export interface SkippedCheck {
  check: Rule;
  reason: string;
}

/**
 * A check that never gets a ✓: "no-js" didn't run (the project has none of the
 * code it understands), "not-applicable" ran but found nothing to inspect.
 */
export interface NotCheckedCheck {
  check: Rule;
  /** e.g. "no JS/TS code found" or "no Supabase found". */
  reason: string;
  kind: "no-js" | "not-applicable";
}

export const NO_JS_REASON = "no JS/TS code found";

// JS/TS-family source. Config files alone (.json, .yaml) don't count.
const JS_SOURCE = /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro)$/i;

/** JS/TS-only checks: marked jsOnly, plus every privacy rule (they read JS/TS, HTML and SQL only). */
export const isJsOnly = (check: Rule) => (check as ScannerRule).jsOnly === true || check.category === "privacy";

export interface ScanResult {
  projectPath: string;
  checks: Rule[];
  /** Findings to report: deduped, without ignored ones, one per secret (see groupSameSecret). */
  findings: ScanFinding[];
  /** Findings left out by the project's .leakproofignore. They don't affect the score or exit code. */
  ignored: ScanFinding[];
  skipped: SkippedCheck[];
  /** Checks that didn't run (e.g. JS-only checks on a Python project). They never get a ✓. */
  notChecked?: NotCheckedCheck[];
  /** Distinct files read across all rules. */
  filesChecked: number;
  durationMs: number;
  /** Which stack the project uses (yes/no only), for the report and opt-in usage counts. */
  stack?: Stack;
}

export interface Stack {
  vite: boolean;
  next: boolean;
  supabase: boolean;
}

/** Detects Vite, Next.js and Supabase from package.json and well-known files. */
export function detectStack(packageJson: Record<string, any> | undefined, files: string[]): Stack {
  const deps = { ...(packageJson?.dependencies ?? {}), ...(packageJson?.devDependencies ?? {}) } as Record<string, unknown>;
  const has = (name: string) => name in deps;
  const file = (re: RegExp) => files.some((f) => re.test(f));
  return {
    vite: has("vite") || file(/^vite\.config\.[cm]?[jt]s$/),
    next: has("next") || file(/^next\.config\.[cm]?[jt]s$/),
    supabase: has("@supabase/supabase-js") || has("@supabase/ssr") || file(/^supabase\//),
  };
}

// When different rules flag the same file and line, the most specific fixId wins.
const rank = specificity;

/**
 * One leak, one finding: for each file+line flagged by more than one of the
 * secret rules (SECRET_RULE_IDS), keeps only the findings of the rule with the
 * most specific fixId (the first such rule on a tie). Several findings from
 * one rule on a line (two keys) stay. Findings from every other rule, privacy
 * included, are never removed: two of them on one line are two problems.
 */
export function dedupe(findings: ScanFinding[]): ScanFinding[] {
  const winner = new Map<string, ScanFinding>();
  const key = (f: ScanFinding) =>
    SECRET_RULE_IDS.has(f.ruleId) && f.file !== undefined && f.line !== undefined ? `${f.file}:${f.line}` : undefined;
  for (const f of findings) {
    const k = key(f);
    if (k === undefined) continue;
    const best = winner.get(k);
    if (!best || rank(f) > rank(best)) winner.set(k, f);
  }
  return findings.filter((f) => {
    const k = key(f);
    return k === undefined || winner.get(k)!.ruleId === f.ruleId;
  });
}

/** Runs every rule against projectPath and collects all findings. */
export async function runScan(projectPath: string, checks: Rule[] = defaultRules): Promise<ScanResult> {
  const start = performance.now();
  const filesRead = new Set<string>();
  const ctx = await createProjectContext(projectPath, filesRead);
  const findings: ScanFinding[] = [];
  const skipped: SkippedCheck[] = [];
  const hasJs = ctx.files.some((f) => JS_SOURCE.test(f) && !f.endsWith(".d.ts"));
  const notChecked: NotCheckedCheck[] = [];
  for (const check of checks) {
    if (!hasJs && isJsOnly(check)) {
      notChecked.push({ check, reason: NO_JS_REASON, kind: "no-js" });
      continue;
    }
    try {
      const found = await check.run(ctx);
      findings.push(...found);
      // Nothing found: did the check have anything to inspect? If not, it's "Not applicable", never ✓.
      const reason = found.length === 0 ? (check as ScannerRule).notApplicable?.(ctx) : undefined;
      if (reason) notChecked.push({ check, reason, kind: "not-applicable" });
    } catch (error) {
      if (!(error instanceof CheckSkipped)) throw error;
      skipped.push({ check, reason: error.message });
    }
  }
  const ignoreEntries = loadIgnoreFile(projectPath);
  const all = dedupe(findings);
  return {
    projectPath,
    checks,
    findings: groupSameSecret(all.filter((f) => !isIgnored(f, ignoreEntries))),
    ignored: all.filter((f) => isIgnored(f, ignoreEntries)).map(({ secretIds: _drop, ...f }) => f),
    skipped,
    notChecked,
    filesChecked: filesRead.size,
    durationMs: Math.round(performance.now() - start),
    stack: detectStack(ctx.packageJson, ctx.files),
  };
}

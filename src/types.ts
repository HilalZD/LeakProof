import type { Finding, ProjectContext, Rule } from "./contract.js";

export type { Finding, ProjectContext, Rule, Severity } from "./contract.js";

/**
 * A contract Finding plus the fix text the terminal report prints today.
 * `fix` goes away once fixes come from the fix library (Part C).
 */
export interface ScanFinding extends Finding {
  fix?: string;
  /** Other places the same secret was found (set by grouping). */
  alsoAt?: { file?: string; line?: number }[];
  /** Fixes for the other fixIds in the same-secret group (set by grouping). */
  alsoFixes?: { fixId: string; fix?: string }[];
  /**
   * In memory only: identities of the secret(s) behind this finding (hashes or
   * env var names), used to group findings of the same secret. Never output.
   */
  secretIds?: string[];
}

/** A contract Rule with the extras the current terminal report uses. */
export interface ScannerRule extends Rule {
  /** Shown as a ✓ line on clean results, e.g. "No secret keys in code". Falls back to `description`. */
  passedLabel?: string;
  /** Only understands JS/TS code (routes, browser bundles). Not run, and never ✓, on a project with no JS/TS code. */
  jsOnly?: boolean;
  /**
   * Why this check had nothing to inspect (e.g. "no Supabase found"), or
   * undefined when it did inspect something. Only asked when the check
   * returned no findings, so it can never hide one. A check with nothing to
   * inspect is shown as "Not applicable", never as ✓.
   */
  notApplicable?(ctx: ProjectContext): string | undefined;
  run(ctx: ProjectContext): ScanFinding[] | Promise<ScanFinding[]>;
}

/** Thrown by a rule that can't run on this project, e.g. git is missing. */
export class CheckSkipped extends Error {}

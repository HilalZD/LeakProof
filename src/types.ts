/** critical, high and medium are leaks; low is a warning that doesn't fail the scan. */
export type Severity = "critical" | "high" | "medium" | "low";

/** One problem found by a check. */
export interface Finding {
  /** The id of the check that produced this finding. */
  checkId: string;
  severity: Severity;
  /** Path relative to the scanned project folder. */
  file: string;
  /** 1-based line number, if the finding points at a specific line. */
  line?: number;
  message: string;
  /** How the user can fix it. */
  fix: string;
}

/** A single security check. Each check lives in its own file in src/checks/. */
export interface Check {
  /** Stable machine-readable id, e.g. "supabase-service-key". */
  id: string;
  /** Human-readable name shown in the report. */
  name: string;
  /** Shown as a ✓ line on clean results, e.g. "No secret keys in code". */
  passedLabel: string;
  /** Default severity of findings from this check. */
  severity: Severity;
  run(projectPath: string, context?: ScanContext): Promise<Finding[]>;
}

/** Shared by all checks during one scan. */
export interface ScanContext {
  /** Absolute paths of every file a check has read, so the report can count them once. */
  filesRead: Set<string>;
}

/** Thrown by a check that can't run on this project, e.g. git is missing. */
export class CheckSkipped extends Error {}

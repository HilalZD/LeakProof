export type Severity = "critical" | "high" | "medium" | "low" | "info";

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
  /** Default severity of findings from this check. */
  severity: Severity;
  run(projectPath: string): Promise<Finding[]>;
}

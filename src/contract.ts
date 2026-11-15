// Copied exactly from CONTRACT.md (v1, frozen Nov 14, 2026). Do not edit here;
// changes go through CONTRACT.md first.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  ruleId: string;          // which check found it, e.g. "PRIV_NO_PRIVACY_POLICY"
  fixId: string;           // key into the fix library (Part C). Usually the same as ruleId.
  severity: Severity;
  category: "security" | "privacy";
  title: string;           // short, plain English: "No privacy policy found"
  message: string;         // what we found and why it matters, 1–2 sentences
  file?: string;           // path relative to the project root, if known
  line?: number;           // line number, if known
  lawRefs?: string[];      // privacy only, e.g. ["GDPR Art. 13", "PIPEDA Principle 4.8"]
  confidence: "high" | "medium" | "low";  // how sure we are this is real
}

export interface ProjectContext {
  root: string;                  // absolute path to the project being scanned
  files: string[];               // relative paths, excluding node_modules, .git, dist, build
  read(file: string): string;    // returns a file's text contents
  packageJson?: Record<string, any>;
}

export interface Rule {
  id: string;                    // must equal the ruleId of the Findings it produces
  category: "security" | "privacy";
  description: string;
  run(ctx: ProjectContext): Finding[] | Promise<Finding[]>;
}

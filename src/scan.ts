import { checks as defaultChecks } from "./checks/index.js";
import { CheckSkipped, type Check, type Finding } from "./types.js";

export interface SkippedCheck {
  check: Check;
  reason: string;
}

export interface ScanResult {
  projectPath: string;
  checks: Check[];
  findings: Finding[];
  skipped: SkippedCheck[];
}

/** Runs every check against projectPath and collects all findings. */
export async function runScan(
  projectPath: string,
  checks: Check[] = defaultChecks,
): Promise<ScanResult> {
  const findings: Finding[] = [];
  const skipped: SkippedCheck[] = [];
  for (const check of checks) {
    try {
      findings.push(...(await check.run(projectPath)));
    } catch (error) {
      if (!(error instanceof CheckSkipped)) throw error;
      skipped.push({ check, reason: error.message });
    }
  }
  return { projectPath, checks, findings, skipped };
}

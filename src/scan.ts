import { checks as defaultChecks } from "./checks/index.js";
import type { Check, Finding } from "./types.js";

export interface ScanResult {
  projectPath: string;
  checks: Check[];
  findings: Finding[];
}

/** Runs every check against projectPath and collects all findings. */
export async function runScan(
  projectPath: string,
  checks: Check[] = defaultChecks,
): Promise<ScanResult> {
  const findings: Finding[] = [];
  for (const check of checks) {
    findings.push(...(await check.run(projectPath)));
  }
  return { projectPath, checks, findings };
}

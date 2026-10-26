import { readFile } from "node:fs/promises";
import { isCodeFile, toProjectPath, walkFiles } from "../lib/files.js";
import { mask } from "../lib/mask.js";
import { findSecretKeys } from "../lib/patterns.js";
import type { Check, Finding } from "../types.js";

export { mask };

const CHECK_ID = "leaked-keys";

// import.meta.env.VITE_X or import.meta.env["VITE_X"]; the name ends up in group 1 or 2.
const VITE_ENV_REGEX = /import\.meta\.env(?:\.(VITE_\w+)|\[\s*["'](VITE_\w+)["']\s*\])/g;
const SECRET_NAME_PARTS = ["SECRET", "SERVICE_ROLE", "PRIVATE", "PASSWORD"];

export function scanContent(file: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((text, index) => {
    const line = index + 1;

    for (const { pattern, value } of findSecretKeys(text)) {
      findings.push({
        checkId: CHECK_ID,
        severity: pattern.severity,
        file,
        line,
        message: `${pattern.name} hardcoded: ${mask(value)}`,
        fix: pattern.fix,
      });
    }

    for (const match of text.matchAll(VITE_ENV_REGEX)) {
      const name = match[1] ?? match[2];
      if (!SECRET_NAME_PARTS.some((part) => name.toUpperCase().includes(part))) continue;
      findings.push({
        checkId: CHECK_ID,
        severity: "high",
        file,
        line,
        message: `Secret exposed to the browser through Vite: import.meta.env.${name}`,
        fix: `Vite ships every VITE_ variable to the browser: drop the VITE_ prefix, use ${name.slice(5)} only in server-side code, and rotate it.`,
      });
    }
  });

  return findings;
}

export const leakedKeysCheck: Check = {
  id: CHECK_ID,
  name: "Leaked secret keys in code",
  severity: "critical",
  async run(projectPath) {
    const findings: Finding[] = [];
    for await (const filePath of walkFiles(projectPath, isCodeFile)) {
      const file = toProjectPath(projectPath, filePath);
      findings.push(...scanContent(file, await readFile(filePath, "utf8")));
    }
    return findings.sort((a, b) => a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
  },
};

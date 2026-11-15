import { basename } from "node:path";
import { isCodeFile, isSourceFile } from "../lib/files.js";
import { mask } from "../lib/mask.js";
import { findSecretKeys, secretValueId } from "../lib/patterns.js";
import type { ScanFinding, ScannerRule } from "../types.js";

export { mask };

const RULE_ID = "leaked-keys";

// Secrets read through VITE_ / NEXT_PUBLIC_ variables are the client-exposed rule's job.

/**
 * Outside JS/TS there is no "frontend vs server function" split, so the
 * JS-flavoured fixes (move it to a server-side function, use the publishable
 * key in frontend code) are replaced by a language-neutral one.
 */
export const ENV_VAR_FIX = "Move this key out of the code into an environment variable (not committed to git), and rotate it now.";
const fixFor = (file: string, fix: string) =>
  isCodeFile(basename(file)) || !/server-side|frontend/i.test(fix) ? fix : ENV_VAR_FIX;

export function scanContent(file: string, content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((text, index) => {
    const line = index + 1;

    for (const { pattern, value } of findSecretKeys(text)) {
      findings.push({
        ruleId: RULE_ID,
        fixId: "SEC_SECRET_HARDCODED",
        category: "security",
        title: "Secret key hardcoded in code",
        confidence: "high",
        severity: pattern.severity,
        secretIds: [secretValueId(value)],
        file,
        line,
        message: `${pattern.name} hardcoded: ${mask(value)}`,
        fix: fixFor(file, pattern.fix),
      });
    }

  });

  return findings;
}

export const leakedKeysRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Leaked secret keys in code (any language)",
  passedLabel: "No secret keys in code",
  notApplicable: (ctx) => (ctx.files.some((file) => isSourceFile(basename(file))) ? undefined : "no source files found"),
  run(ctx) {
    const findings = ctx.files
      // Every text source file, in any language (isSourceFile), not only JS/TS.
      .filter((file) => isSourceFile(basename(file)))
      .flatMap((file) => scanContent(file, ctx.read(file)));
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
  },
};

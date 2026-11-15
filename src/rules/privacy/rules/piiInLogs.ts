import type { Finding, Rule } from "../../../contract.js";
import { findMatches, makeFinding } from "../utils.js";

/**
 * Rule 6: PRIV_PII_IN_LOGS
 * Law: personal data must be kept secure (GDPR Art. 5(1)(f) integrity and confidentiality,
 * Art. 32 security of processing; PIPEDA Principle 4.7, safeguards).
 *
 * IF   a log call prints a variable named like email, phone, password, address, token or user
 * THEN report a possible gap (one finding per log line).
 */

// Log calls: console.log/info/warn/error/debug, logger.info(...), log.debug(...)
export const LOG_CALL = /\b(console|logger|log)\.(log|info|warn|error|debug|trace)\s*\(/;

// Variable names that suggest personal or secret data (also matches userEmail, accessToken, phoneNumber...).
const SENSITIVE_NAME = /(e-?mail|phone|password|passwd|address|token|\buser\b)/i;

/**
 * Removes text inside quotes, so console.log("Enter your email") is NOT flagged
 * (it prints a sentence, not someone's real email). Keeps ${...} parts of `template strings`,
 * because those DO print real values.
 */
function removeQuotedText(line: string): string {
  return line
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, (template) =>
      (template.match(/\$\{[^}]*\}/g) ?? []).join(" "),
    );
}

export const piiInLogs: Rule = {
  id: "PRIV_PII_IN_LOGS",
  category: "privacy",
  description: "Personal data (email, phone, password...) is printed to logs.",

  run(ctx) {
    const findings: Finding[] = [];

    for (const match of findMatches(ctx, [LOG_CALL])) {
      // Look only at the part of the line from the log call onwards, without quoted text.
      const call = match.text.slice(match.text.search(LOG_CALL));
      const printed = removeQuotedText(call).match(SENSITIVE_NAME);
      if (!printed) continue;

      findings.push(
        makeFinding("PRIV_PII_IN_LOGS", {
          message:
            `Possible gap: this line may print personal or secret data ("${printed[0]}") to the logs, ` +
            `where other people or services could read it. Log an ID or a short message instead.`,
          file: match.file,
          line: match.line,
          confidence: "medium", // a variable called "token" or "user" might not hold personal data
        }),
      );
    }

    return findings;
  },
};

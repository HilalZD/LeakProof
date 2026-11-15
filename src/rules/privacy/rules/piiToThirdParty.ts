import type { Finding, Rule } from "../../../contract.js";
import { isCodeFile, makeFinding, stripComments } from "../utils.js";

/**
 * Rule 3: PRIV_PII_TO_THIRD_PARTY
 * Law: users must be told who receives their data, and outside processors need proper agreements
 * (GDPR Art. 13(1)(e) recipients, Art. 28 processors; PIPEDA Principle 4.1.3).
 *
 * A) An analytics tool is told who the user is, using personal data   → medium confidence
 * B) A file calls an AI service AND uses personal data                 → low confidence
 */

// Words that suggest personal data.
const PERSONAL_DATA = /\b(e-?mail|phone|phone_?number|address|full_?name|first_?name|last_?name|birth_?date|dob|weight)\b/i;

// A) Analytics "identify" calls: they tell the service who the user is.
export const IDENTIFY_CALLS: { service: string; pattern: RegExp }[] = [
  { service: "PostHog", pattern: /\bposthog\.identify\s*\(/ },
  { service: "Mixpanel", pattern: /\bmixpanel\.(identify|people\.set)\s*\(/ },
  { service: "Segment", pattern: /\banalytics\.identify\s*\(/ },
  { service: "Amplitude", pattern: /\bamplitude\.(setUserId|identify)\s*\(/ },
  { service: "Sentry", pattern: /\bSentry\.setUser\s*\(/ },
  { service: "Hotjar", pattern: /\bhj\s*\(\s*["']identify["']/ },
];

// B) Calls to AI services.
export const AI_SERVICES: { service: string; pattern: RegExp }[] = [
  { service: "OpenAI", pattern: /api\.openai\.com|new OpenAI\s*\(|openai\.chat\.completions/i },
  { service: "Anthropic", pattern: /api\.anthropic\.com|new Anthropic\s*\(|anthropic\.messages\.create/i },
  { service: "Google Gemini", pattern: /generativelanguage\.googleapis\.com|GoogleGenerativeAI/ },
];

export const piiToThirdParty: Rule = {
  id: "PRIV_PII_TO_THIRD_PARTY",
  category: "privacy",
  description: "Personal data is sent to an outside service (analytics or AI API).",

  run(ctx) {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (!isCodeFile(file)) continue;
      // Comments are removed first, so notes like "// no email here" can't cause false alarms.
      const lines = ctx.read(file).split(/\r?\n/).map(stripComments);

      // A) identify(...) calls that include personal data (checks the call's line + the next 2 lines).
      for (const { service, pattern } of IDENTIFY_CALLS) {
        const i = lines.findIndex((text) => pattern.test(text));
        if (i === -1) continue;
        const callText = lines.slice(i, i + 3).join(" ");
        if (!PERSONAL_DATA.test(callText)) continue;
        findings.push(
          makeFinding("PRIV_PII_TO_THIRD_PARTY", {
            message:
              `Possible gap: personal data (like an email or name) is sent to ${service} here. ` +
              `Users should be told that ${service} receives their data, and you need a data processing agreement with them.`,
            file,
            line: i + 1,
            confidence: "medium",
          }),
        );
      }

      // B) Files that call an AI service and also use personal data.
      for (const { service, pattern } of AI_SERVICES) {
        const i = lines.findIndex((text) => pattern.test(text));
        if (i === -1) continue;
        if (!lines.some((text) => PERSONAL_DATA.test(text))) continue;
        findings.push(
          makeFinding("PRIV_PII_TO_THIRD_PARTY", {
            message:
              `Possible gap: this file calls ${service} and also uses personal data (like an email or name). ` +
              `If that data is sent to ${service}, users should be told, and you need a data processing agreement.`,
            file,
            line: i + 1,
            confidence: "low", // we only know both appear in the same file
          }),
        );
      }
    }

    return findings;
  },
};

import type { Finding, Rule } from "../../../contract.js";
import { findMatches, makeFinding } from "../utils.js";

/**
 * Rule 2: PRIV_TRACKER_BEFORE_CONSENT
 * Law: trackers may only be placed on a device after the user agrees
 * (ePrivacy Directive Art. 5(3); GDPR Art. 7 conditions for consent; PIPEDA Principle 4.3, consent).
 *
 * IF   the app loads a tracking script
 * AND  there is no consent tool anywhere in the app
 * THEN report one possible gap per tracker.
 */

// Each tracker and the code patterns that show it is being loaded or started.
export const TRACKERS: { name: string; patterns: RegExp[] }[] = [
  { name: "Google Analytics", patterns: [/googletagmanager\.com/i, /google-analytics\.com/i, /\bgtag\s*\(\s*["']config["']/] },
  { name: "Meta Pixel", patterns: [/connect\.facebook\.net/i, /\bfbq\s*\(\s*["']init["']/] },
  { name: "PostHog", patterns: [/\bposthog\.init\s*\(/] },
  { name: "Mixpanel", patterns: [/\bmixpanel\.init\s*\(/, /cdn\.mxpnl\.com/i] },
  { name: "Segment", patterns: [/cdn\.segment\.com/i, /\banalytics\.load\s*\(/] },
  { name: "Hotjar", patterns: [/static\.hotjar\.com/i, /\bhotjar\.initialize\s*\(/i] },
  { name: "TikTok Pixel", patterns: [/analytics\.tiktok\.com/i, /\bttq\.load\s*\(/] },
];

// Signs that the app asks for consent before tracking.
const CONSENT_TOOLS = [
  /cookieconsent|cookie-consent/i,               // CookieConsent, vanilla-cookieconsent, react-cookie-consent
  /\bklaro\b/i,                                  // Klaro
  /onetrust|cookielaw\.org/i,                    // OneTrust
  /cookiebot/i,                                  // Cookiebot
  /\bgtag\s*\(\s*["']consent["']/,               // Google Consent Mode: gtag("consent", ...)
  /opt_out_capturing_by_default\s*:\s*true/,     // PostHog: off until the user opts in
  /\b(hasConsent|consentGiven|cookieConsent|analyticsConsent|acceptedCategory)\b/, // custom consent checks
];

export const trackerBeforeConsent: Rule = {
  id: "PRIV_TRACKER_BEFORE_CONSENT",
  category: "privacy",
  description: "Analytics or ad trackers load with no consent tool in the app.",

  run(ctx) {
    // 1. Is there any consent tool? Check the code and the app's dependencies.
    const dependencies = JSON.stringify({
      ...ctx.packageJson?.dependencies,
      ...ctx.packageJson?.devDependencies,
    });
    const hasConsentTool =
      findMatches(ctx, CONSENT_TOOLS).length > 0 ||
      CONSENT_TOOLS.some((pattern) => pattern.test(dependencies));
    if (hasConsentTool) return [];

    // 2. Report each tracker we find, at the first place it appears.
    const findings: Finding[] = [];
    for (const tracker of TRACKERS) {
      const found = findMatches(ctx, tracker.patterns);
      if (found.length === 0) continue;
      const first = found[0];
      findings.push(
        makeFinding("PRIV_TRACKER_BEFORE_CONSENT", {
          message:
            `Possible gap: ${tracker.name} is loaded here, but we couldn't find a cookie or consent banner. ` +
            `In the EU, trackers should only start after the user agrees.`,
          file: first.file,
          line: first.line,
          confidence: "medium", // the app might use a homemade consent check we don't recognize
        }),
      );
    }
    return findings;
  },
};

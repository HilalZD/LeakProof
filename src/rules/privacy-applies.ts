import type { ProjectContext, Rule } from "../contract.js";
import type { ScannerRule } from "../types.js";
import { LOG_CALL } from "./privacy/rules/piiInLogs.js";
import { AI_SERVICES, IDENTIFY_CALLS } from "./privacy/rules/piiToThirdParty.js";
import { collectionPoints } from "./privacy/rules/noPrivacyPolicy.js";
import { TRACKERS } from "./privacy/rules/trackerBeforeConsent.js";
import { appContains, SELF_SIGNUP } from "./privacy/utils.js";

/**
 * For each privacy rule: why it had nothing to inspect, using the rule's own
 * patterns. Kept out of Serena's rule files so her detection logic is untouched.
 * Only asked when the rule found nothing (see ScannerRule.notApplicable).
 */
const NOT_APPLICABLE: Record<string, (ctx: ProjectContext) => string | undefined> = {
  PRIV_NO_PRIVACY_POLICY: (ctx) => (collectionPoints(ctx).length > 0 ? undefined : "no personal data collection found"),
  PRIV_TRACKER_BEFORE_CONSENT: (ctx) => (appContains(ctx, TRACKERS.flatMap((t) => t.patterns)) ? undefined : "no trackers found"),
  PRIV_PII_TO_THIRD_PARTY: (ctx) =>
    appContains(ctx, [...IDENTIFY_CALLS, ...AI_SERVICES].map((s) => s.pattern)) ? undefined : "no analytics identify or AI API calls found",
  PRIV_NO_ACCOUNT_DELETION: (ctx) => (appContains(ctx, SELF_SIGNUP) ? undefined : "no self sign-up found"),
  PRIV_NO_DATA_EXPORT: (ctx) => (appContains(ctx, SELF_SIGNUP) ? undefined : "no self sign-up found"),
  PRIV_PII_IN_LOGS: (ctx) => (appContains(ctx, [LOG_CALL]) ? undefined : "no log calls found"),
};

/** The privacy rule with its notApplicable check attached (same id, run and description). */
export const withNotApplicable = (rule: Rule): ScannerRule => ({ ...rule, notApplicable: NOT_APPLICABLE[rule.id] });

import type { Severity } from "../../contract.js";

// The privacy table from THE LEAKPROOF CONTRACT (v1), section 5, in one place.
// Rules and tests both read from here. Do NOT change IDs, severities or law references:
// if one looks wrong, write it in NOTES-FOR-HILAL.md instead.

export type PrivacyFixId =
  | "PRIV_NO_PRIVACY_POLICY"
  | "PRIV_TRACKER_BEFORE_CONSENT"
  | "PRIV_PII_TO_THIRD_PARTY"
  | "PRIV_NO_ACCOUNT_DELETION"
  | "PRIV_NO_DATA_EXPORT"
  | "PRIV_PII_IN_LOGS";

export interface PrivacyFix {
  severity: Severity;
  title: string;      // short, plain English (from the contract's "Meaning" column)
  lawRefs: string[];  // exactly as written in the contract
  fix: string;        // one-line fix shown under high/medium findings (added by Hilal, Nov 15, 2026: for Serena's review)
}

export const PRIVACY_FIXES: Record<PrivacyFixId, PrivacyFix> = {
  PRIV_NO_PRIVACY_POLICY: {
    severity: "high",
    title: "No privacy policy found",
    lawRefs: ["GDPR Art. 13", "PIPEDA Principle 4.8"],
    fix: "Add a privacy policy page (e.g. /privacy) that says what you collect, why, who you share it with, how long you keep it, how users can ask for deletion and how to reach you, and link it from your forms and footer.",
  },
  PRIV_TRACKER_BEFORE_CONSENT: {
    severity: "high",
    title: "Trackers load before consent",
    lawRefs: ["ePrivacy Directive Art. 5(3)", "GDPR Art. 7", "PIPEDA Principle 4.3"],
    fix: "Add a consent banner and only load this tracker after the user clicks Accept.",
  },
  PRIV_PII_TO_THIRD_PARTY: {
    severity: "medium",
    title: "Personal data sent to a third party",
    lawRefs: ["GDPR Art. 13(1)(e)", "GDPR Art. 28", "PIPEDA Principle 4.1.3"],
    fix: "Send an anonymous ID instead of the email or name, or name this service in your privacy policy and sign its data processing agreement.",
  },
  PRIV_NO_ACCOUNT_DELETION: {
    severity: "medium",
    title: "Users can't delete their account",
    lawRefs: ["GDPR Art. 17", "PIPEDA Principle 4.3.8", "PIPEDA Principle 4.5.3"],
    fix: "Add a \"Delete my account\" option that removes the user's account and their data on the server.",
  },
  PRIV_NO_DATA_EXPORT: {
    severity: "low",
    title: "Users can't get a copy of their data",
    lawRefs: ["GDPR Art. 15", "GDPR Art. 20", "PIPEDA Principle 4.9"],
    fix: "Add a \"Download my data\" option that gives users their data as a JSON or CSV file.",
  },
  PRIV_PII_IN_LOGS: {
    severity: "medium",
    title: "Personal data printed to logs",
    lawRefs: ["GDPR Art. 5(1)(f)", "GDPR Art. 32", "PIPEDA Principle 4.7"],
    fix: "Log a user ID or a short message instead of the email, phone or password.",
  },
};

export const PRIVACY_FIX_IDS = Object.keys(PRIVACY_FIXES) as PrivacyFixId[];

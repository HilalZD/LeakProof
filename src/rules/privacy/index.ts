import type { Rule } from "../../contract.js";
import { noPrivacyPolicy } from "./rules/noPrivacyPolicy.js";
import { trackerBeforeConsent } from "./rules/trackerBeforeConsent.js";
import { piiToThirdParty } from "./rules/piiToThirdParty.js";
import { noAccountDeletion } from "./rules/noAccountDeletion.js";
import { noDataExport } from "./rules/noDataExport.js";
import { piiInLogs } from "./rules/piiInLogs.js";

// The privacy rule pack: all 6 rules from the CONTRACT.
export const rules: Rule[] = [
  noPrivacyPolicy,
  trackerBeforeConsent,
  piiToThirdParty,
  noAccountDeletion,
  noDataExport,
  piiInLogs,
];

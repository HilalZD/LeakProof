import type { Rule } from "../../../contract.js";
import { findMatches, SELF_SIGNUP, makeFinding } from "../utils.js";

/**
 * Rule 5: PRIV_NO_DATA_EXPORT
 * Law: people have the right to get a copy of their data, in a format they can take elsewhere
 * (GDPR Art. 15 access, Art. 20 portability; PIPEDA Principle 4.9, individual access).
 *
 * IF   users can sign themselves up (SELF_SIGNUP; operator-created accounts don't count, changed Nov 15, 2026)
 * AND  there is no way to download one's data
 * THEN report a possible gap.
 */

// Signs that users can get a copy of their data.
const EXPORT_PATHS = [
  /\bexport[\s_-]?(my[\s_-]?|user[\s_-]?)?data\b/i,           // exportData, exportUserData, /export-data
  /\bdata[\s_-]?export\b/i,                                    // dataExport, /data-export
  /\bdownload[\s_-]?(my[\s_-]?|your[\s_-]?)data\b/i,           // "Download my data", downloadMyData
  /\bcopy\s+of\s+(my|your)\s+(personal\s+)?data\b/i,           // "Request a copy of your data"
];

export const noDataExport: Rule = {
  id: "PRIV_NO_DATA_EXPORT",
  category: "privacy",
  description: "The app has user accounts but no way for users to download their data.",

  run(ctx) {
    const accounts = findMatches(ctx, SELF_SIGNUP);
    if (accounts.length === 0) return [];
    if (findMatches(ctx, EXPORT_PATHS).length > 0) return [];

    const first = accounts[0];
    return [
      makeFinding("PRIV_NO_DATA_EXPORT", {
        message:
          `Possible gap: users can create their own accounts in this app (sign-up in ${first.file}, line ${first.line}) ` +
          `but we couldn't find a way for users to download a copy of their data.`,
        file: first.file,
        line: first.line,
        confidence: "low", // many apps handle copy requests by email, which code can't show
      }),
    ];
  },
};

import type { Rule } from "../../../contract.js";
import { findMatches, SELF_SIGNUP, makeFinding } from "../utils.js";

/**
 * Rule 4: PRIV_NO_ACCOUNT_DELETION
 * Law: people have the right to have their data erased
 * (GDPR Art. 17; PIPEDA Principles 4.3.8 and 4.5).
 *
 * IF   users can sign themselves up (SELF_SIGNUP; operator-created accounts don't count, changed Nov 15, 2026)
 * AND  there is no way to delete an account
 * THEN report a possible gap.
 */

// Signs that users can delete their account.
const DELETION_PATHS = [
  /\bdeleteUser\s*\(/,                                  // Supabase admin / Firebase deleteUser(...)
  /\b(currentUser|user)\.delete\s*\(/,                  // Firebase / Clerk: user.delete()
  /\b(delete|close|remove)[\s_-]?(my[\s_-]?|your[\s_-]?)?account\b/i, // "Delete my account", deleteAccount, close-account
];

export const noAccountDeletion: Rule = {
  id: "PRIV_NO_ACCOUNT_DELETION",
  category: "privacy",
  description: "The app has user accounts but no way for users to delete them.",

  run(ctx) {
    const accounts = findMatches(ctx, SELF_SIGNUP);
    if (accounts.length === 0) return [];
    if (findMatches(ctx, DELETION_PATHS).length > 0) return [];

    const first = accounts[0];
    return [
      makeFinding("PRIV_NO_ACCOUNT_DELETION", {
        message:
          `Possible gap: users can create their own accounts in this app (sign-up in ${first.file}, line ${first.line}) ` +
          `but we couldn't find a way for users to delete their account and data.`,
        file: first.file,
        line: first.line,
        confidence: "medium", // deletion might be handled by email or a support form we can't see
      }),
    ];
  },
};

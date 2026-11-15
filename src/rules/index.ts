import type { Rule } from "../contract.js";
import { apiAuthRule } from "./api-auth.js";
import { clientExposedRule } from "./client-exposed.js";
import { committedEnvRule } from "./committed-env.js";
import { leakedKeysRule } from "./leaked-keys.js";
import { rules as privacyRules } from "./privacy/index.js";
import { withNotApplicable } from "./privacy-applies.js";
import { rateLimitRule } from "./rate-limit.js";
import { serviceRoleClientRule } from "./service-role-client.js";
import { stripeWebhookRule } from "./stripe-webhook.js";
import { supabaseRlsRule } from "./supabase-rls.js";

// Every rule the scanner runs, in the CONTRACT's Rule format. To add a rule
// (security or privacy), create a file in this folder and add it to this list.
export const rules: Rule[] = [
  leakedKeysRule,
  committedEnvRule,
  stripeWebhookRule,
  rateLimitRule,
  clientExposedRule,
  serviceRoleClientRule,
  supabaseRlsRule,
  apiAuthRule,
  // Part B (Serena): the 6 privacy rules, category "privacy".
  // Each one also says when it had nothing to inspect (privacy-applies.ts).
  ...privacyRules.map(withNotApplicable),
];

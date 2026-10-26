import type { Check } from "../types.js";
import { committedEnvCheck } from "./committed-env.js";
import { leakedKeysCheck } from "./leaked-keys.js";
import { stripeWebhookCheck } from "./stripe-webhook.js";

// Every check the scanner runs. To add a check, create a file in this
// folder and add it to this list.
export const checks: Check[] = [leakedKeysCheck, committedEnvCheck, stripeWebhookCheck];

import type { Check } from "../types.js";
import { leakedKeysCheck } from "./leaked-keys.js";

// Every check the scanner runs. To add a check, create a file in this
// folder and add it to this list.
export const checks: Check[] = [leakedKeysCheck];

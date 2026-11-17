// APPEND-ONLY. Never reorder or remove: old links depend on it.
//
// The master list of fix IDs, in the exact order of CONTRACT.md section 5 (security, then privacy).
// Short fix links (<SITE_URL>/fix#<code>) are a bitmask over this list: bit 0 = the first ID.
// The website has the same list in leakproof-site/lib/fix-order.ts: change both together.
// A new ID goes at the END of the list, after it is added to CONTRACT.md.
export const FIX_ORDER = [
  // Security (CONTRACT.md §5, Part A)
  "SEC_SECRET_HARDCODED",
  "SEC_SECRET_CLIENT_EXPOSED",
  "SEC_ENV_COMMITTED",
  "SEC_ENV_COMMITTED_PUBLIC_ONLY",
  "SEC_ENV_NOT_GITIGNORED",
  "SEC_STRIPE_WEBHOOK_UNSIGNED",
  "SEC_SUPABASE_RLS_DISABLED",
  "SEC_SUPABASE_RLS_PERMISSIVE",
  "SEC_SUPABASE_SERVICE_ROLE_CLIENT",
  "SEC_SUPABASE_RLS_UNVERIFIED",
  "SEC_API_ROUTE_NO_AUTH",
  "SEC_API_NO_RATE_LIMIT",
  // Privacy (CONTRACT.md §5, Part B)
  "PRIV_NO_PRIVACY_POLICY",
  "PRIV_TRACKER_BEFORE_CONSENT",
  "PRIV_PII_TO_THIRD_PARTY",
  "PRIV_NO_ACCOUNT_DELETION",
  "PRIV_NO_DATA_EXPORT",
  "PRIV_PII_IN_LOGS",
] as const;

/**
 * Fix IDs → short code: a base36 number with bit i set for FIX_ORDER[i].
 * Undefined when any ID isn't in the list (the caller then uses the long #f= link).
 */
export function encodeShortCode(ids: readonly string[]): string | undefined {
  let n = 0n;
  for (const id of ids) {
    const bit = (FIX_ORDER as readonly string[]).indexOf(id);
    if (bit < 0) return undefined;
    n |= 1n << BigInt(bit);
  }
  return n.toString(36);
}

/** Short code → fix IDs in list order (bits past the list are dropped). For tests and tools. */
export function decodeShortCode(code: string): string[] {
  let n = 0n;
  for (const ch of code.toLowerCase()) n = n * 36n + BigInt(parseInt(ch, 36));
  return FIX_ORDER.filter((_, bit) => (n >> BigInt(bit)) & 1n);
}

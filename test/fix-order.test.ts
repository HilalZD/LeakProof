import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decodeShortCode, encodeShortCode, FIX_ORDER } from "../src/lib/fix-order.js";
import { buildFixLink } from "../src/summary.js";

// The list as of CONTRACT v1.5. If this test fails, someone reordered or removed an ID:
// every short link already printed would point at the wrong fixes. Only APPEND new IDs,
// and then add them to the end of this list too.
const FROZEN = [
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
  "PRIV_NO_PRIVACY_POLICY",
  "PRIV_TRACKER_BEFORE_CONSENT",
  "PRIV_PII_TO_THIRD_PARTY",
  "PRIV_NO_ACCOUNT_DELETION",
  "PRIV_NO_DATA_EXPORT",
  "PRIV_PII_IN_LOGS",
];

describe("FIX_ORDER (APPEND-ONLY)", () => {
  it("starts with the frozen v1.5 list, unchanged and in order", () => {
    expect(FIX_ORDER.slice(0, FROZEN.length)).toEqual(FROZEN);
  });

  const contract = fileURLToPath(new URL("../CONTRACT.md", import.meta.url));
  it("matches the CONTRACT.md master list exactly", () => {
    const ids = [...readFileSync(contract, "utf8").matchAll(/^\| ((?:SEC|PRIV)_[A-Z0-9_]+) \|/gm)].map((m) => m[1]);
    expect([...FIX_ORDER]).toEqual(ids);
  });

  // The website decodes the same codes with its own copy of the list.
  const site = fileURLToPath(new URL("../../leakproof-site/lib/fix-order.ts", import.meta.url));
  it.skipIf(!existsSync(site))("matches the website's lib/fix-order.ts exactly (needs ../leakproof-site)", () => {
    const ids = [...readFileSync(site, "utf8").matchAll(/^\s+"((?:SEC|PRIV)_[A-Z0-9_]+)",/gm)].map((m) => m[1]);
    expect([...FIX_ORDER]).toEqual(ids);
  });
});

describe("short codes", () => {
  it("encodes examples: bit 0 = the first ID", () => {
    expect(encodeShortCode(["SEC_SECRET_HARDCODED"])).toBe("1");
    expect(encodeShortCode(["SEC_SECRET_CLIENT_EXPOSED"])).toBe("2");
    expect(encodeShortCode(["SEC_SECRET_HARDCODED", "SEC_SECRET_CLIENT_EXPOSED"])).toBe("3");
    expect(encodeShortCode(["SEC_SUPABASE_RLS_DISABLED", "PRIV_NO_PRIVACY_POLICY"])).toBe("37k"); // same as the website
    expect(encodeShortCode(["PRIV_NO_PRIVACY_POLICY", "SEC_SUPABASE_RLS_DISABLED"])).toBe("37k"); // order doesn't matter
    expect(encodeShortCode([...FIX_ORDER])!.length).toBeLessThanOrEqual(4);
  });

  it("round-trips every single ID and the full list", () => {
    for (const id of FIX_ORDER) expect(decodeShortCode(encodeShortCode([id])!)).toEqual([id]);
    expect(decodeShortCode(encodeShortCode([...FIX_ORDER])!)).toEqual([...FIX_ORDER]);
  });

  it("can't encode an ID that isn't in the list", () => {
    expect(encodeShortCode(["SEC_SECRET_HARDCODED", "SEC_NOT_IN_LIST"])).toBeUndefined();
  });
});

describe("buildFixLink", () => {
  it("prints the short link", () => {
    const link = buildFixLink([{ fixId: "PRIV_NO_PRIVACY_POLICY", severity: "high" }, { fixId: "SEC_SUPABASE_RLS_DISABLED", severity: "critical" }], "https://site.test");
    expect(link).toBe("https://site.test/fix#37k");
  });

  it("falls back to the long #f= link when an ID isn't in the list yet", () => {
    const link = buildFixLink([{ fixId: "SEC_NOT_IN_LIST", severity: "high" }, { fixId: "SEC_SECRET_HARDCODED", severity: "critical" }], "https://site.test");
    expect(link).toBe("https://site.test/fix#f=SEC_SECRET_HARDCODED,SEC_NOT_IN_LIST");
  });
});

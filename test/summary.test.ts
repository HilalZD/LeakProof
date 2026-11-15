import { describe, expect, it } from "vitest";
import type { Severity } from "../src/contract.js";
import { buildFixLink, gradeFor, scoreFor } from "../src/summary.js";

const many = (severity: Severity, n: number) => Array.from({ length: n }, () => ({ severity }));

describe("scoreFor", () => {
  it("is 100 − (4×medium + 1×low) when there's no critical or high", () => {
    expect(scoreFor([])).toBe(100);
    expect(scoreFor(many("medium", 1))).toBe(96);
    expect(scoreFor(many("low", 1))).toBe(99);
    expect(scoreFor([...many("medium", 5), ...many("low", 3)])).toBe(77);
  });

  it("subtracts 25 per critical and 10 per high under the caps", () => {
    expect(scoreFor([...many("critical", 2), ...many("high", 3), ...many("medium", 1)])).toBe(16);
    expect(scoreFor([...many("high", 5)])).toBe(50);
  });

  it("caps the score at 39 with any critical, else at 59 with any high", () => {
    expect(scoreFor(many("critical", 1))).toBe(39);
    expect(gradeFor(scoreFor(many("critical", 1)))).toBe("F");
    expect(scoreFor(many("high", 1))).toBe(59);
    expect(gradeFor(scoreFor(many("high", 1)))).toBe("D");
    expect(scoreFor([...many("critical", 1), ...many("high", 1)])).toBe(39);
    expect(scoreFor([...many("high", 1), ...many("low", 2)])).toBe(59);
  });

  it("never goes below 0", () => {
    expect(scoreFor(many("critical", 5))).toBe(0);
    expect(scoreFor([...many("critical", 7), ...many("high", 3), ...many("medium", 1)])).toBe(0);
  });

  it("ignores info findings", () => {
    expect(scoreFor(many("info", 50))).toBe(100);
    expect(scoreFor([...many("info", 3), ...many("medium", 1)])).toBe(96);
  });
});

describe("gradeFor", () => {
  it("A 90+, B 75–89, C 60–74, D 40–59, F below 40", () => {
    const cases: [number, string][] = [
      [100, "A"], [90, "A"],
      [89, "B"], [75, "B"],
      [74, "C"], [60, "C"],
      [59, "D"], [40, "D"],
      [39, "F"], [0, "F"],
    ];
    for (const [score, grade] of cases) expect(gradeFor(score), String(score)).toBe(grade);
  });
});

describe("buildFixLink", () => {
  const SITE = "https://fix.example";
  const f = (fixId: string, severity: Severity) => ({ fixId, severity });

  it("lists each fixId once, worst severity first, ties in the order given", () => {
    const link = buildFixLink(
      [
        f("SEC_API_NO_RATE_LIMIT", "medium"),
        f("SEC_ENV_COMMITTED", "critical"),
        f("SEC_SECRET_CLIENT_EXPOSED", "high"),
        f("SEC_API_NO_RATE_LIMIT", "high"), // its worst severity wins
        f("SEC_STRIPE_WEBHOOK_UNSIGNED", "critical"),
        f("SEC_ENV_COMMITTED", "critical"),
        f("SEC_SUPABASE_RLS_UNVERIFIED", "info"),
        f("SEC_ENV_COMMITTED_PUBLIC_ONLY", "low"),
      ],
      SITE,
    );
    expect(link).toBe(
      // Both high: SEC_API_NO_RATE_LIMIT was given first.
      `${SITE}/fix?f=SEC_ENV_COMMITTED,SEC_STRIPE_WEBHOOK_UNSIGNED,SEC_API_NO_RATE_LIMIT,SEC_SECRET_CLIENT_EXPOSED,SEC_ENV_COMMITTED_PUBLIC_ONLY,SEC_SUPABASE_RLS_UNVERIFIED`,
    );
  });

  it("never contains anything but fix IDs: no paths, code or values", () => {
    const real = { fixId: "SEC_SECRET_HARDCODED", severity: "critical" as const, file: "src/lib/ai.ts", message: "sk-proj-****W1xY" };
    const link = buildFixLink(
      [
        real,
        f("src/lib/ai.ts", "critical"),
        f("sk-proj-abc123", "critical"),
        f("SEC_X&f=../../etc", "high"),
      ],
      SITE,
    )!;
    expect(link).toBe(`${SITE}/fix?f=SEC_SECRET_HARDCODED`);
    expect(new URL(link).searchParams.get("f")).toMatch(/^[A-Z0-9_,]+$/);
  });

  it("is undefined when there is nothing to fix, and tolerates a trailing slash on the site URL", () => {
    expect(buildFixLink([], SITE)).toBeUndefined();
    expect(buildFixLink([f("SEC_ENV_COMMITTED", "critical")], `${SITE}/`)).toBe(`${SITE}/fix?f=SEC_ENV_COMMITTED`);
  });
});

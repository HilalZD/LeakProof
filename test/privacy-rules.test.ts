// Serena's Part B tests (tests/rules.test.ts in leakproof-privacy), ported from
// node:test to vitest. The checks are the same; only the runner changed, and
// the context now comes from the scanner's own createProjectContext.
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { Finding, ProjectContext, Rule } from "../src/contract.js";
import { createProjectContext } from "../src/lib/files.js";
import { rules } from "../src/rules/privacy/index.js";
import { PRIVACY_FIXES, PRIVACY_FIX_IDS, type PrivacyFixId } from "../src/rules/privacy/laws.js";

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/privacy/${name}`, import.meta.url));

let bad: ProjectContext;
let good: ProjectContext;
beforeAll(async () => {
  bad = await createProjectContext(fixture("bad-app"));
  good = await createProjectContext(fixture("good-app"));
});

// Words our findings must never use (see her docs/how-leakproof-works.md, section 9).
const BANNED_WORDS = /\b(illegal|compliant|certified|guarantee)/i;

/** Checks that one Finding follows THE LEAKPROOF CONTRACT exactly. */
function checkFormat(f: Finding, rule: Rule, ctx: ProjectContext) {
  const fix = PRIVACY_FIXES[f.fixId as PrivacyFixId];
  expect(f.ruleId, "ruleId must equal the rule's id").toBe(rule.id);
  expect(fix, `Unknown fixId "${f.fixId}" (not in the contract)`).toBeTruthy();
  expect(f.category).toBe("privacy");
  expect(f.severity, "severity must match the contract table").toBe(fix.severity);
  expect(f.lawRefs, "lawRefs must match the contract table").toEqual(fix.lawRefs);
  expect(["high", "medium", "low"], "confidence must be high, medium or low").toContain(f.confidence);
  expect(f.title.length, "title must not be empty").toBeGreaterThan(0);
  expect(f.message, 'message must say "possible gap"').toMatch(/possible gap/i);
  expect(`${f.title} ${f.message}`, "never say illegal/compliant/certified/guarantee").not.toMatch(BANNED_WORDS);
  if (f.file !== undefined) expect(ctx.files, `file "${f.file}" is not in the scanned app`).toContain(f.file);
  if (f.line !== undefined) expect(Number.isInteger(f.line) && f.line >= 1, "line must be 1 or more").toBe(true);
}

describe("privacy rule pack (Serena's tests)", () => {
  it("rule pack: every rule uses a contract ID, is a privacy rule, and appears once", () => {
    const ids = rules.map((r) => r.id);
    expect(new Set(ids).size, "a rule is listed twice in src/rules/privacy/index.ts").toBe(ids.length);
    for (const r of rules) {
      expect(PRIVACY_FIX_IDS, `"${r.id}" is not a contract privacy ID`).toContain(r.id);
      expect(r.category).toBe("privacy");
    }
  });

  for (const id of PRIVACY_FIX_IDS) {
    const rule = rules.find((r) => r.id === id);

    if (!rule) {
      it.todo(`${id}: not written yet`);
      continue;
    }

    it(`${id}: catches the problem in bad-app`, async () => {
      const findings = await rule.run(bad);
      expect(findings.length, "expected at least 1 finding in bad-app, got 0").toBeGreaterThanOrEqual(1);
      for (const f of findings) checkFormat(f, rule, bad);
    });

    it(`${id}: stays silent on good-app`, async () => {
      const findings = await rule.run(good);
      expect(findings, `False alarm on good-app:\n${JSON.stringify(findings, null, 2)}`).toEqual([]);
    });
  }

  // Not in her suite: pins her standalone runner's totals (8 on bad-app, 0 on good-app).
  it("bad-app has 8 privacy findings in total, good-app has none", async () => {
    const all = async (ctx: ProjectContext) => (await Promise.all(rules.map((r) => r.run(ctx)))).flat();
    expect(await all(bad)).toHaveLength(8);
    expect(await all(good)).toEqual([]);
  });
});

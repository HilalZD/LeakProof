import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext } from "../src/lib/files.js";
import { rules } from "../src/rules/index.js";
import { rules as privacyRules } from "../src/rules/privacy/index.js";
import { findMatches } from "../src/rules/privacy/utils.js";
import { dedupe, runScan } from "../src/scan.js";
import type { ScanFinding } from "../src/types.js";

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function project(files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-priv-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(dir, path, ".."), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return dir;
}

const finding = (ruleId: string, fixId: string, category: "security" | "privacy", file = "src/Signup.tsx", line = 13): ScanFinding => ({
  ruleId,
  fixId,
  file,
  line,
  severity: "medium",
  category,
  title: fixId,
  message: `${fixId} at ${file}:${line}`,
  confidence: "medium",
});

describe("privacy rules are registered", () => {
  it("runs all 6 privacy rules after the security rules", () => {
    expect(privacyRules.map((r) => r.id)).toEqual([
      "PRIV_NO_PRIVACY_POLICY",
      "PRIV_TRACKER_BEFORE_CONSENT",
      "PRIV_PII_TO_THIRD_PARTY",
      "PRIV_NO_ACCOUNT_DELETION",
      "PRIV_NO_DATA_EXPORT",
      "PRIV_PII_IN_LOGS",
    ]);
    // Registered with a notApplicable check attached, same id and run.
    for (const rule of privacyRules) expect(rules.find((r) => r.id === rule.id)?.run).toBe(rule.run);
    expect(rules.filter((r) => r.category === "privacy")).toHaveLength(6);
  });
});

describe("dedupe only applies to the secret rules", () => {
  it("3 privacy findings on one line stay 3 findings", () => {
    const findings = [
      finding("PRIV_NO_PRIVACY_POLICY", "PRIV_NO_PRIVACY_POLICY", "privacy"),
      finding("PRIV_NO_ACCOUNT_DELETION", "PRIV_NO_ACCOUNT_DELETION", "privacy"),
      finding("PRIV_NO_DATA_EXPORT", "PRIV_NO_DATA_EXPORT", "privacy"),
    ];
    expect(dedupe(findings)).toHaveLength(3);
  });

  it("a privacy finding on the same line as a secret finding stays too", () => {
    const findings = [
      finding("leaked-keys", "SEC_SECRET_HARDCODED", "security"),
      finding("client-exposed", "SEC_SECRET_CLIENT_EXPOSED", "security"),
      finding("PRIV_PII_IN_LOGS", "PRIV_PII_IN_LOGS", "privacy"),
    ];
    expect(dedupe(findings).map((f) => f.fixId)).toEqual(["SEC_SECRET_CLIENT_EXPOSED", "PRIV_PII_IN_LOGS"]);
  });

  it("other security rules on one line aren't merged either", () => {
    const findings = [finding("rate-limit", "SEC_API_NO_RATE_LIMIT", "security"), finding("api-auth", "SEC_API_ROUTE_NO_AUTH", "security")];
    expect(dedupe(findings)).toHaveLength(2);
  });

  it("a real scan keeps all 3 privacy findings that land on the same sign-up line", async () => {
    const root = await project({ "src/Signup.tsx": "export const go = (email: string, password: string) => supabase.auth.signUp({ email, password });\n" });
    const priv = (await runScan(root)).findings.filter((f) => f.category === "privacy");
    expect(priv.map((f) => `${f.fixId} ${f.file}:${f.line}`).sort()).toEqual([
      "PRIV_NO_ACCOUNT_DELETION src/Signup.tsx:1",
      "PRIV_NO_DATA_EXPORT src/Signup.tsx:1",
      "PRIV_NO_PRIVACY_POLICY src/Signup.tsx:1",
    ]);
  });
});

describe("ProjectContext as the privacy rules expect it", () => {
  it("lists .sql and .astro files with / paths, and skips node_modules, .git, dist and build", async () => {
    const root = await project({
      "supabase/migrations/001_users.sql": "create table users (email text);\n",
      "src/pages/index.astro": "<h1>Hi</h1>\n",
      "node_modules/x/index.js": "x",
      ".git/config": "x",
      "dist/a.js": "x",
      "build/b.js": "x",
    });
    const ctx = await createProjectContext(root);
    expect([...ctx.files].sort()).toEqual(["src/pages/index.astro", "supabase/migrations/001_users.sql"]);
    // Her findMatches reads both file types.
    expect(findMatches(ctx, [/email|<h1>/]).map((m) => m.file).sort()).toEqual(["src/pages/index.astro", "supabase/migrations/001_users.sql"]);
  });

  it("read() never throws: a missing file reads as empty", async () => {
    const ctx = await createProjectContext(await project({ "a.ts": "x" }));
    expect(ctx.read("does/not/exist.ts")).toBe("");
  });
});

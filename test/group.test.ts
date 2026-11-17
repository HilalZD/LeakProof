import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import pc from "picocolors";
import { afterEach, describe, expect, it } from "vitest";
import { groupSameSecret } from "../src/group.js";
import { renderJson, renderReport } from "../src/report.js";
import { runScan, type ScanResult } from "../src/scan.js";
import type { ScanFinding, Severity } from "../src/types.js";

// Fake keys are assembled at runtime so no full key literal appears in this file.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (role: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.${"s1g".repeat(10)}`;
const STRIPE_TEST = "sk_" + "test_" + "y".repeat(24);
const STRIPE_LIVE = "sk_" + "live_" + "x".repeat(24);
const OPENAI = "sk-" + "proj-" + "A1b2C3d4".repeat(6);
const VITE_PACKAGE = JSON.stringify({ devDependencies: { vite: "8.0.0" } });

const finding = (
  fixId: string,
  severity: Severity,
  file: string,
  line: number,
  secretIds: string[],
  fix = `Fix for ${fixId}.`,
): ScanFinding => ({
  ruleId: fixId.toLowerCase(),
  fixId,
  severity,
  category: "security",
  title: fixId,
  message: `${fixId} at ${file}:${line}`,
  confidence: "high",
  file,
  line,
  fix,
  secretIds,
});

describe("groupSameSecret", () => {
  it("one finding per secret, joined by the same value or the same env var name", () => {
    const grouped = groupSameSecret([
      finding("SEC_ENV_COMMITTED", "high", ".env", 7, ["value:aaa", "env:STRIPE_SECRET_KEY"]),
      finding("SEC_SECRET_CLIENT_EXPOSED", "high", ".env", 9, ["value:aaa", "env:VITE_STRIPE_SECRET_KEY"]),
      finding("SEC_SECRET_CLIENT_EXPOSED", "high", "src/lib/payments.ts", 14, ["env:VITE_STRIPE_SECRET_KEY"]),
      finding("SEC_SECRET_HARDCODED", "critical", "src/other.ts", 1, ["value:bbb"]),
      finding("SEC_STRIPE_WEBHOOK_UNSIGNED", "critical", "src/hook.ts", 7, []),
    ]);

    expect(grouped.map((f) => `${f.file}:${f.line}`)).toEqual([".env:9", "src/other.ts:1", "src/hook.ts:7"]);
    expect(grouped[0].alsoAt).toEqual([
      { file: ".env", line: 7 },
      { file: "src/lib/payments.ts", line: 14 },
    ]);
    expect(grouped[1].alsoAt).toBeUndefined();
    for (const f of grouped) expect(f.secretIds).toBeUndefined(); // never leaves grouping
  });

  it("keeps the most important location: worst severity, then most specific fixId, then the line with the value", () => {
    const [bySeverity] = groupSameSecret([
      finding("SEC_SECRET_CLIENT_EXPOSED", "high", "a.ts", 1, ["value:k"]),
      finding("SEC_ENV_COMMITTED", "critical", ".env", 2, ["value:k"]),
    ]);
    expect(bySeverity).toMatchObject({ file: ".env", line: 2 });

    const [bySpecificity] = groupSameSecret([
      finding("SEC_ENV_COMMITTED", "critical", ".env", 2, ["value:k", "env:VITE_K"]),
      finding("SEC_SECRET_CLIENT_EXPOSED", "critical", ".env", 3, ["value:k", "env:VITE_K"]),
    ]);
    expect(bySpecificity).toMatchObject({ line: 3, fixId: "SEC_SECRET_CLIENT_EXPOSED" });

    const [byValue] = groupSameSecret([
      finding("SEC_SECRET_CLIENT_EXPOSED", "critical", "src/components/A.tsx", 13, ["env:VITE_K"]), // a read
      finding("SEC_SECRET_CLIENT_EXPOSED", "critical", ".env", 10, ["value:k", "env:VITE_K"]),
    ]);
    expect(byValue).toMatchObject({ file: ".env", line: 10, alsoAt: [{ file: "src/components/A.tsx", line: 13 }] });
  });

  it("a mixed-fixId group keeps every distinct fix, each fixId's fix once", () => {
    const [kept] = groupSameSecret([
      finding("SEC_ENV_COMMITTED", "high", ".env", 7, ["value:aaa"], "Remove .env from git."),
      finding("SEC_SECRET_CLIENT_EXPOSED", "high", ".env", 9, ["value:aaa", "env:VITE_K"], "Drop the VITE_ prefix."),
      finding("SEC_SECRET_CLIENT_EXPOSED", "high", "src/lib/p.ts", 14, ["env:VITE_K"], "Drop the VITE_ prefix."),
      finding("SEC_ENV_COMMITTED", "high", ".env.production", 3, ["value:aaa"], "Remove .env.production from git."),
    ]);

    expect(kept).toMatchObject({ fixId: "SEC_SECRET_CLIENT_EXPOSED", fix: "Drop the VITE_ prefix." });
    expect(kept.alsoFixes).toEqual([{ fixId: "SEC_ENV_COMMITTED", fix: "Remove .env from git." }]);

    const result: ScanResult = {
      projectPath: "/x",
      checks: [],
      findings: [kept],
      ignored: [],
      skipped: [],
      filesChecked: 3,
      durationMs: 10,
    };
    const out = renderReport(result, { colors: pc.createColors(false), version: "1", siteUrl: "https://fix.example" });
    expect(out).toContain(
      [
        "  .env:9",
        "  also at: .env:7, .env.production:3, src/lib/p.ts:14",
        "    SEC_SECRET_CLIENT_EXPOSED at .env:9",
        "    → Fix: Drop the VITE_ prefix.",
        "    → Also: Remove .env from git.",
      ].join("\n"),
    );
    expect(out.split("Drop the VITE_ prefix.")).toHaveLength(2); // same fixId: its fix once
    // Grouped fixIds still get their fix guide.
    expect(out).toContain("https://fix.example/fix#6");

    const json = JSON.parse(renderJson(result));
    expect(json.findings[0].alsoFixes).toEqual([{ fixId: "SEC_ENV_COMMITTED", fix: "Remove .env from git." }]);
    expect(json.findings[0].alsoAt).toHaveLength(3);
  });
});

describe("same secret, end to end", () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = undefined;
  });

  async function project(files: Record<string, string>): Promise<string> {
    dir = await mkdtemp(join(tmpdir(), "leakproof-group-"));
    for (const [path, content] of Object.entries(files)) {
      await mkdir(dirname(join(dir, path)), { recursive: true });
      await writeFile(join(dir, path), content);
    }
    return dir;
  }

  it("counts a secret once in the score, lists the other places, and never outputs the hash", async () => {
    const root = await project({
      "package.json": VITE_PACKAGE,
      ".env.local": `VITE_OPENAI_API_KEY=${OPENAI}\n`,
      "src/components/Chat.tsx": "const key = import.meta.env.VITE_OPENAI_API_KEY;\n",
      "src/lib/a.ts": `const k = "${STRIPE_LIVE}";\n`,
      "src/lib/b.ts": `\nconst k = "${STRIPE_LIVE}";\n`,
    });
    const result = await runScan(root);

    expect(result.findings.map((f) => `${f.file}:${f.line} ${f.fixId}`)).toEqual(
      expect.arrayContaining([".env.local:1 SEC_SECRET_CLIENT_EXPOSED", "src/lib/a.ts:1 SEC_SECRET_CLIENT_EXPOSED"]),
    );
    const env = result.findings.find((f) => f.file === ".env.local")!;
    expect(env.alsoAt).toEqual([{ file: "src/components/Chat.tsx", line: 1 }]);
    const stripe = result.findings.find((f) => f.file === "src/lib/a.ts")!;
    expect(stripe.alsoAt).toEqual([{ file: "src/lib/b.ts", line: 2 }]);

    const json = renderJson(result);
    const parsed = JSON.parse(json);
    expect(parsed.summary.counts.critical).toBe(2); // two secrets, five raw findings
    expect(json).not.toContain("secretIds");
    expect(json).not.toMatch(/value:[0-9a-f]{8}/);
  });
});

describe("messages never repeat their title", () => {
  it("holds for every rule's findings", async () => {
    const dir = await mkdtemp(join(tmpdir(), "leakproof-titles-"));
    try {
      const files: Record<string, string> = {
        "package.json": VITE_PACKAGE,
        ".env": `STRIPE_SECRET_KEY=${STRIPE_LIVE}\nVITE_STRIPE_SECRET_KEY=${STRIPE_TEST}\n`,
        ".env.production": "VITE_SUPABASE_URL=https://x.supabase.co\n",
        ".env.local": `DB_PASSWORD=hunter2-real-password\n`,
        "src/components/Admin.tsx": `createClient(url, "${jwt("service_role")}");\nconst k = import.meta.env.VITE_STRIPE_SECRET_KEY;\n`,
        "src/lib/ai.ts": `const k = "${OPENAI}";\n`,
        "server/keys.ts": `const k = "${STRIPE_LIVE}x";\n`,
        "src/routes/api/stripe-webhook.ts":
          'import Stripe from "stripe";\nexport async function POST(request: Request) {\n  const event = await request.json();\n  if (event.type === "checkout.session.completed") {}\n}\n',
        "app/api/chat/route.ts":
          'import OpenAI from "openai";\nexport async function POST() {\n  await new OpenAI().chat.completions.create({});\n}\n',
      };
      for (const [path, content] of Object.entries(files)) {
        await mkdir(dirname(join(dir, path)), { recursive: true });
        await writeFile(join(dir, path), content);
      }
      const git = (...args: string[]) =>
        execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", ...args], { cwd: dir, stdio: "ignore" });
      git("init", "-q");
      git("add", "-f", "--", ".env", ".env.production");
      git("commit", "-q", "-m", "init");

      const { findings } = await runScan(dir);
      const ruleIds = new Set(findings.map((f) => f.ruleId));
      for (const id of ["stripe-webhook", "rate-limit", "service-role-client", "client-exposed", "leaked-keys", "committed-env"]) {
        expect(ruleIds, id).toContain(id);
      }
      for (const f of findings) {
        expect(f.message.toLowerCase().startsWith(f.title.toLowerCase()), `${f.ruleId}: ${f.message}`).toBe(false);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

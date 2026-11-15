// A check is ✓ only when it inspected something and found it safe. On a
// project with no JS/TS code, the JS-only checks are "Not checked"; a check
// that found nothing to inspect (no Supabase, no Stripe webhook…) is
// "Not applicable".
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { renderMarkdownSummary } from "../src/github.js";
import { renderJson, renderReport } from "../src/report.js";
import { runScan, type ScanResult } from "../src/scan.js";

const pythonApp = fileURLToPath(new URL("./fixtures/python-app", import.meta.url));
const text = (result: ScanResult, verbose = false) =>
  renderReport(result, { colors: pc.createColors(false), version: "9.9.9", verbose });
const render = async (path: string, verbose = false) => text(await runScan(path), verbose);
const trimmed = (out: string) => out.split("\n").map((l) => l.trim());

/** Runs `body` on a temp project made of `files` (path → content), then deletes it. */
async function withProject(files: Record<string, string>, body: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), "leakproof-na-"));
  try {
    for (const [file, content] of Object.entries(files)) {
      await mkdir(dirname(join(dir, file)), { recursive: true });
      await writeFile(join(dir, file), content);
    }
    await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const JS_ONLY_LINES = [
  "– Not checked: Stripe webhook signature verification (no JS/TS code found)",
  "– Not checked: Login checks on API routes that touch user data (no JS/TS code found)",
  "– Not checked: Rate limits on paid and sensitive endpoints (no JS/TS code found)",
  "– Not checked: Supabase service_role key in frontend code (no JS/TS code found)",
  "– Not checked: Secret keys the browser can reach (no JS/TS code found)",
  "– Not checked: Privacy policy (no JS/TS code found)",
  "– Not checked: Trackers before consent (no JS/TS code found)",
  "– Not checked: Personal data sent to third parties (no JS/TS code found)",
  "– Not checked: Account deletion (no JS/TS code found)",
  "– Not checked: Data export (no JS/TS code found)",
  "– Not checked: Personal data in logs (no JS/TS code found)",
];

describe("Python-only project", () => {
  it("text report: ✓ only for checks that inspected something, the rest Not checked / Not applicable", async () => {
    const out = await render(pythonApp);
    const lines = trimmed(out);
    expect(lines.filter((l) => l.startsWith("✓"))).toEqual(["✓ No secret keys in code"]);
    expect(lines.filter((l) => l.startsWith("– Not checked"))).toEqual(JS_ONLY_LINES);
    expect(lines.filter((l) => l.startsWith("– Not applicable"))).toEqual([
      "– Not applicable: Supabase Row Level Security (no Supabase found)",
      "– Not applicable: Committed .env files (no .env files found)",
    ]);
    // Never claims anything about privacy, since no privacy check ran.
    expect(out).toContain("Privacy: not checked (no JS/TS code found)");
    expect(out).not.toContain("no possible gaps found");
    for (const claim of ["Stripe webhooks verify signatures", "check who is calling", "rate limited", "reachable from the browser", "Row Level Security with real policies"]) {
      expect(out).not.toContain(claim);
    }
  });

  it("--verbose marks them '–', not ✓", async () => {
    const out = await render(pythonApp, true);
    expect(out).toContain("  – Stripe webhook signature verification (stripe-webhook): not checked (no JS/TS code found)");
    expect(out).toContain("  – Privacy policy (PRIV_NO_PRIVACY_POLICY): not checked (no JS/TS code found)");
    expect(out).toContain("  – Supabase Row Level Security (supabase-rls): not applicable (no Supabase found)");
    expect(out).toContain("  ✓ Leaked secret keys in code (any language) (leaked-keys)");
  });

  it("JSON has a notChecked list with ruleId, name and reason", async () => {
    const json = JSON.parse(renderJson(await runScan(pythonApp)));
    expect(json.notChecked).toHaveLength(13);
    expect(json.notChecked).toContainEqual({ ruleId: "stripe-webhook", name: "Stripe webhook signature verification", reason: "no JS/TS code found" });
    expect(json.notChecked).toContainEqual({ ruleId: "supabase-rls", name: "Supabase Row Level Security", reason: "not-applicable", detail: "no Supabase found" });
    expect(json.notChecked.map((n: { ruleId: string }) => n.ruleId)).not.toContain("leaked-keys");
    expect(json.findings).toEqual([]);
  });

  it("the GitHub job summary lists them too", async () => {
    const md = renderMarkdownSummary(await runScan(pythonApp), "9.9.9");
    for (const line of JS_ONLY_LINES) expect(md).toContain(`- ${line}`);
    expect(md).toContain("- – Not applicable: Supabase Row Level Security (no Supabase found)");
  });

  it("not-checked checks don't change the exit code", async () => {
    const code = await run(["node", "leakproof", pythonApp], { stdout: () => {}, stderr: () => {}, env: { CI: "1" }, isTTY: false });
    expect(code).toBe(0);
  });
});

describe("projects with JS/TS code", () => {
  it("run every check: none Not checked, the ones with nothing to inspect Not applicable", async () => {
    await withProject({ "index.ts": "export const x = 1;\n" }, async (dir) => {
      const result = await runScan(dir);
      expect(result.notChecked?.filter((n) => n.kind === "no-js")).toEqual([]);
      const out = text(result);
      expect(out).not.toContain("Not checked");
      expect(trimmed(out).filter((l) => l.startsWith("✓"))).toEqual(["✓ No secret keys in code"]);
      expect(trimmed(out).filter((l) => l.startsWith("– Not applicable"))).toEqual([
        "– Not applicable: Stripe webhook signature verification (no Stripe webhook found)",
        "– Not applicable: Supabase Row Level Security (no Supabase found)",
        "– Not applicable: Login checks on API routes that touch user data (no API routes or server functions found)",
        "– Not applicable: Rate limits on paid and sensitive endpoints (no paid or sensitive endpoints found)",
        "– Not applicable: Supabase service_role key in frontend code (no Supabase found)",
        "– Not applicable: Secret keys the browser can reach (no frontend code or .env files found)",
        "– Not applicable: Committed .env files (no .env files found)",
        "– Not applicable: Privacy policy (no personal data collection found)",
        "– Not applicable: Trackers before consent (no trackers found)",
        "– Not applicable: Personal data sent to third parties (no analytics identify or AI API calls found)",
        "– Not applicable: Account deletion (no self sign-up found)",
        "– Not applicable: Data export (no self sign-up found)",
        "– Not applicable: Personal data in logs (no log calls found)",
      ]);
      expect(out).toContain("Privacy: not applicable (no personal data collection, trackers, sign-up or logs found)");
    });
  });

  it("a .d.ts file alone doesn't count as JS/TS code", async () => {
    await withProject({ "types.d.ts": "declare const x: number;\n" }, async (dir) => {
      expect((await runScan(dir)).notChecked?.filter((n) => n.kind === "no-js")).toHaveLength(11);
    });
  });
});

describe("✓ only for checks that inspected something", () => {
  it("a verified Stripe webhook gets its ✓", async () => {
    const webhook = [
      'import Stripe from "stripe";',
      "export async function POST(request: Request) {",
      "  const body = await request.text();",
      '  const event = stripe.webhooks.constructEvent(body, request.headers.get("stripe-signature")!, secret);',
      '  if (event.type === "checkout.session.completed") {}',
      "}",
    ].join("\n");
    await withProject({ "app/api/stripe/route.ts": webhook }, async (dir) => {
      const out = await render(dir);
      expect(out).toContain("✓ Stripe webhooks verify signatures");
      expect(out).not.toContain("Not applicable: Stripe webhook");
    });
  });

  it("Supabase with no SQL files is 'couldn't verify', neither ✓ nor Not applicable", async () => {
    await withProject({ "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2" } }), "src/main.ts": "export {};\n" }, async (dir) => {
      const result = await runScan(dir);
      const out = text(result);
      expect(result.findings.map((f) => f.fixId)).toContain("SEC_SUPABASE_RLS_UNVERIFIED");
      expect(out).not.toContain("Row Level Security with real policies");
      expect(out).not.toContain("Not applicable: Supabase Row Level Security");
      // Supabase is used, so the service_role check inspected the frontend.
      expect(out).not.toContain("Not applicable: Supabase service_role");
    });
  });

  it("a check with a finding is never Not applicable", async () => {
    await withProject({ "src/signup.ts": "await supabase.auth.signUp({ email, password });\n" }, async (dir) => {
      const result = await runScan(dir);
      expect(result.findings.map((f) => f.ruleId)).toContain("PRIV_NO_ACCOUNT_DELETION");
      const na = result.notChecked?.filter((n) => n.kind === "not-applicable").map((n) => n.check.id);
      expect(na).not.toContain("PRIV_NO_ACCOUNT_DELETION");
      expect(na).not.toContain("PRIV_NO_PRIVACY_POLICY");
    });
  });

  it("not-applicable checks don't change the score or exit code", async () => {
    await withProject({ "index.ts": "export const x = 1;\n" }, async (dir) => {
      const json = JSON.parse(renderJson(await runScan(dir)));
      expect(json.summary.score).toBe(100);
      const code = await run(["node", "leakproof", dir], { stdout: () => {}, stderr: () => {}, env: { CI: "1" }, isTTY: false });
      expect(code).toBe(0);
    });
  });
});

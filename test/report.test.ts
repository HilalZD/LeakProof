import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pc from "picocolors";
import { afterEach, describe, expect, it } from "vitest";
import { run, useColor, type CliIo } from "../src/cli.js";
import { SITE_URL } from "../src/config.js";
import { exitCodeFor, renderJson, renderReport, WIDTH, wrap } from "../src/report.js";
import type { ScanResult } from "../src/scan.js";
import type { ScanFinding as Finding, ScannerRule as Check, Severity } from "../src/types.js";

const noColors = pc.createColors(false);
const ANSI = /\u001b\[/;

const check = (id: string, name: string, passedLabel = `${name} passed`): Check => ({
  id,
  category: "security",
  description: name,
  passedLabel,
  run: async () => [],
});
const leakedKeys = check("leaked-keys", "Leaked secret keys in code", "No secret keys in code");
const committedEnv = check("committed-env", "Committed .env files", "No secrets in committed .env files");
const stripeWebhook = check("stripe-webhook", "Stripe webhook signature verification", "Stripe webhooks verify signatures");
const rateLimit = check("rate-limit", "Rate limits on paid and sensitive endpoints", "Paid and sensitive endpoints are rate limited");

const finding = (
  severity: Severity,
  file: string,
  line: number,
  message = "Something leaked",
  fix = "Fix it.",
  ruleId = "leaked-keys",
): Finding => ({
  ruleId,
  fixId: "SEC_SECRET_HARDCODED",
  category: "security",
  title: "Secret key hardcoded in code",
  confidence: "high",
  severity,
  file,
  line,
  message,
  fix,
});

const result = (findings: Finding[], extra: Partial<ScanResult> = {}): ScanResult => ({
  projectPath: join(tmpdir(), "my-app"),
  checks: [leakedKeys, committedEnv],
  findings,
  ignored: [],
  skipped: [],
  filesChecked: 42,
  durationMs: 1234,
  ...extra,
});

const SITE = "https://fix.example";
const render = (r: ScanResult, verbose = false) => renderReport(r, { colors: noColors, version: "9.9.9", verbose, siteUrl: SITE });
const lines = (text: string) => text.trimEnd().split("\n");
const FOOTER = "Scanned locally. Nothing was sent anywhere.";

describe("renderReport", () => {
  it("clean result: header, score line, passed checks and the footer, with no fix link", () => {
    expect(render(result([]))).toBe(
      [
        "Leakproof v9.9.9 · 42 files checked · 1.2s",
        "",
        "Security 100/100 · Grade A · no leaks",
        "",
        "  ✓ No secret keys in code",
        "  ✓ No secrets in committed .env files",
        "",
        FOOTER,
        "",
      ].join("\n"),
    );
  });

  it("never shows the scanned folder's name", () => {
    expect(render(result([finding("critical", ".env", 7)]))).not.toContain("my-app");
  });

  it("leaks: score line, title, location, message, fix, then the fix link and footer last", () => {
    const out = render(
      result([
        finding("critical", "src/lib/ai.ts", 1, "OpenAI API key hardcoded: sk-proj-****W1xY", "Move this key."),
        finding("high", "src/lib/payments.ts", 14),
        finding("critical", ".env", 7),
      ]),
    );

    expect(lines(out)[2]).toBe("Security 39/100 · Grade F · 2 critical, 1 high");
    expect(out).toContain(
      [
        "  Secret key hardcoded in code",
        "  src/lib/ai.ts:1",
        "    OpenAI API key hardcoded: sk-proj-****W1xY",
        "    → Fix: Move this key.",
      ].join("\n"),
    );
    expect(lines(out).slice(-4)).toEqual([
      "Copy-paste fixes for Lovable, Bolt, Cursor, Claude Code or Codex:",
      `${SITE}/fix#f=SEC_SECRET_HARDCODED`,
      "",
      FOOTER,
    ]);
  });

  it("shows the fix for critical and high only", () => {
    const out = render(
      result([
        finding("critical", "c.ts", 1, "c", "Fix critical."),
        finding("high", "h.ts", 1, "h", "Fix high."),
        finding("medium", "m.ts", 1, "m", "Fix medium."),
        finding("low", "l.ts", 1, "l", "Fix low."),
      ]),
    );
    expect(out).toContain("→ Fix: Fix critical.");
    expect(out).toContain("→ Fix: Fix high.");
    expect(out).not.toContain("Fix medium.");
    expect(out).not.toContain("Fix low.");
  });

  it("only medium: the score line lists only the severities present", () => {
    const out = render(result([finding("medium", ".env.local", 3)]));
    expect(lines(out)[2]).toBe("Security 96/100 · Grade A · 1 medium");
    expect(out).toContain("── MEDIUM (1) ──");
    expect(out).not.toContain("CRITICAL");
    expect(out).not.toContain("HIGH");
  });

  it("says how many findings were ignored, and leaves them out", () => {
    const ignored = [finding("critical", "old.ts", 1, "ignored one")];
    const out = render(result([finding("high", "a.ts", 1)], { ignored }));
    expect(lines(out)[2]).toBe("Security 59/100 · Grade D · 1 high · 1 ignored");
    expect(out).not.toContain("old.ts");
  });

  it("orders sections critical, high, medium whatever order the findings arrive in", () => {
    const out = render(result([finding("medium", "m.ts", 1), finding("high", "h.ts", 1), finding("critical", "c.ts", 1)]));
    const order = ["── CRITICAL", "── HIGH", "── MEDIUM"].map((title) => out.indexOf(title));
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(out.indexOf("c.ts:1")).toBeLessThan(out.indexOf("h.ts:1"));
    expect(out.indexOf("h.ts:1")).toBeLessThan(out.indexOf("m.ts:1"));
  });

  it("within a severity: stripe-webhook, rate-limit, leaked-keys, then committed-env, by file:line within each", () => {
    const out = render(
      result([
        finding("critical", "app/api/chat/route.ts", 4, "no limit", "Fix limit.", "rate-limit"),
        finding("critical", ".env", 9, "env 9", "Fix env 9.", "committed-env"),
        finding("critical", "src/z.ts", 1, "key z", "Fix z.", "leaked-keys"),
        finding("critical", ".env", 7, "env 7", "Fix env 7.", "committed-env"),
        finding("critical", "src/a.ts", 12, "key a12", "Fix a12.", "leaked-keys"),
        finding("critical", "src/a.ts", 3, "key a3", "Fix a3.", "leaked-keys"),
        finding("critical", "src/routes/api/hook.ts", 7, "webhook", "Fix hook.", "stripe-webhook"),
        finding("critical", "src/other.ts", 1, "unknown check", "Fix other.", "future-check"),
      ]),
    );
    const locations = lines(out).filter((l) => /^ {2}\S+:\d+$/.test(l)).map((l) => l.trim());
    expect(locations).toEqual([
      "src/routes/api/hook.ts:7",
      "app/api/chat/route.ts:4",
      "src/a.ts:3",
      "src/a.ts:12",
      "src/z.ts:1",
      ".env:7",
      ".env:9",
      "src/other.ts:1",
    ]);
  });

  it("prints every finding's fix, even when two findings share one", () => {
    const fix = "Remove .env from git and rotate this key.";
    const out = render(
      result([
        finding("critical", ".env", 7, "STRIPE_SECRET_KEY is committed", fix, "committed-env"),
        finding("critical", ".env", 8, "SUPABASE_SERVICE_ROLE_KEY is committed", fix, "committed-env"),
      ]),
    );
    expect(out.split(`→ Fix: ${fix}`)).toHaveLength(3);
  });

  describe("LOW warnings", () => {
    const low = (file = ".env") => finding("low", file, 0, `${file} is committed to git.`, "Keep secrets out.", "committed-env");

    it("only LOW: one point off each, no leak", () => {
      expect(lines(render(result([low()])))[2]).toBe("Security 99/100 · Grade A · 1 low");
      expect(lines(render(result([low(".env"), low(".env.production")])))[2]).toBe("Security 98/100 · Grade A · 2 low");
    });

    it("uses bright blue, not plain blue, for LOW", () => {
      const out = renderReport(result([low()]), { colors: pc.createColors(true), version: "1" });
      const BRIGHT_BLUE = "\u001b[94m";
      const BLUE = "\u001b[34m";
      const line = (start: string) => out.split("\n").find((l) => l.replace(/\u001b\[\d+m/g, "").startsWith(start))!;

      expect(line("Security 99/100")).toContain(`${BRIGHT_BLUE}1 low`);
      expect(line("── LOW (1)")).toContain(BRIGHT_BLUE);
      expect(out).not.toContain(BLUE);
    });

    it("LOW section comes after MEDIUM and has no line number", () => {
      const out = render(result([low(), finding("medium", ".env.local", 3)]));
      expect(out.indexOf("── MEDIUM (1)")).toBeLessThan(out.indexOf("── LOW (1)"));
      expect(lines(out)).toContain("  .env");
    });
  });

  describe("Couldn't verify", () => {
    const info = (): Finding => ({
      ...finding("info", "", 0, "No supabase/migrations folder, so RLS couldn't be checked."),
      file: undefined,
      line: undefined,
      fixId: "SEC_SUPABASE_RLS_UNVERIFIED",
      title: "Database rules couldn't be checked",
    });

    it("is not shown when there are no info findings", () => {
      expect(render(result([finding("high", "a.ts", 1)]))).not.toContain("COULDN'T VERIFY");
    });

    it("lists info findings after LOW, and they don't change the score", () => {
      const out = render(result([finding("low", ".env", 0), info()]));
      expect(lines(out)[2]).toBe("Security 99/100 · Grade A · 1 low");
      expect(out.indexOf("── LOW (1)")).toBeLessThan(out.indexOf("── COULDN'T VERIFY (1)"));
      expect(out).toContain("  Database rules couldn't be checked\n    No supabase/migrations folder");
      expect(out).toContain(`${SITE}/fix#f=SEC_SECRET_HARDCODED,SEC_SUPABASE_RLS_UNVERIFIED`);
    });

    it("doesn't show a ✓ for a check that couldn't verify", () => {
      const out = render(result([{ ...info(), ruleId: rateLimit.id }], { checks: [leakedKeys, rateLimit] }));
      expect(out).toContain("✓ No secret keys in code");
      expect(out).not.toContain("✓ Paid and sensitive endpoints are rate limited");
    });
  });

  describe("checklist on clean results", () => {
    const allChecks = [leakedKeys, committedEnv, stripeWebhook, rateLimit];

    it("lists every passed check, in report order, under the score", () => {
      const out = render(result([], { checks: allChecks }));
      expect(lines(out).slice(2, 8)).toEqual([
        "Security 100/100 · Grade A · no leaks",
        "",
        "  ✓ Stripe webhooks verify signatures",
        "  ✓ Paid and sensitive endpoints are rate limited",
        "  ✓ No secret keys in code",
        "  ✓ No secrets in committed .env files",
      ]);
    });

    it("is shown when the only findings are LOW, and a LOW doesn't stop a check passing", () => {
      const low = finding("low", ".env", 0, "safe for now", "Keep secrets out.", "committed-env");
      const out = render(result([low], { checks: allChecks }));
      expect(out).toContain("  ✓ No secrets in committed .env files");
      expect(out.indexOf("✓ No secrets in committed .env files")).toBeLessThan(out.indexOf("── LOW"));
    });

    it("never lists a skipped check as passed", () => {
      const reason = "Not a git repository.";
      const out = render(result([], { checks: allChecks, skipped: [{ check: committedEnv, reason }] }));
      expect(out).not.toContain("No secrets in committed .env files");
      expect(out).toContain("  ✓ No secret keys in code");
      expect(out).toContain(`⚠ Committed .env files skipped: ${reason}`);
    });

    it("is hidden when there are leaks", () => {
      const out = render(result([finding("high", "a.ts", 1)], { checks: allChecks }));
      expect(out).not.toContain("Stripe webhooks verify signatures");
      expect(out).not.toContain("No secret keys in code");
    });
  });

  describe("exitCodeFor", () => {
    it("0 for no findings or LOW only, 1 as soon as there is a MEDIUM or worse", () => {
      const low = finding("low", ".env", 0);
      expect(exitCodeFor(result([]))).toBe(0);
      expect(exitCodeFor(result([low]))).toBe(0);
      expect(exitCodeFor(result([low, finding("medium", ".env.local", 1)]))).toBe(1);
      expect(exitCodeFor(result([finding("high", "a.ts", 1)]))).toBe(1);
      expect(exitCodeFor(result([finding("critical", "a.ts", 1)]))).toBe(1);
    });

    it("ignored findings don't count", () => {
      expect(exitCodeFor(result([], { ignored: [finding("critical", "a.ts", 1)] }))).toBe(0);
      expect(exitCodeFor(result([finding("low", ".env", 0)], { ignored: [finding("high", "a.ts", 1)] }))).toBe(0);
    });
  });

  it("dividers are exactly the report width", () => {
    const out = render(result([finding("critical", "a.ts", 1)]));
    const divider = lines(out).find((l) => l.startsWith("── CRITICAL"))!;
    expect(divider).toBe("── CRITICAL (1) " + "─".repeat(WIDTH - 16));
    expect(divider).toHaveLength(WIDTH);
  });

  it("wraps long messages and fixes to 80 columns with a hanging indent", () => {
    const fix =
      "Remove .env from git (git rm --cached .env), add .env to .gitignore, and rotate this key; it stays in git history even after deletion. The VITE_ prefix also ships it to the browser.";
    const message = "VITE_STRIPE_SECRET_KEY is committed to git and is also shipped to every visitor: sk_test_****M5wZ";
    const out = render(result([finding("critical", ".env", 9, message, fix)]));
    const all = lines(out);

    for (const line of all) expect(line.length, line).toBeLessThanOrEqual(WIDTH);

    const fixStart = all.findIndex((l) => l.startsWith("    → Fix: Remove"));
    expect(all[fixStart + 1]).toMatch(/^ {11}\S/); // continuation lines line up under the text after "→ Fix: "
    expect(all.slice(fixStart, fixStart + 3).join(" ").replace(/ +/g, " ").trim()).toBe(`→ Fix: ${fix}`);

    // The masked key stays whole on one line.
    expect(all.some((l) => l.includes("sk_test_****M5wZ"))).toBe(true);
  });

  it("never breaks a path or masked key, even when it can't fit", () => {
    const longPath = "src/" + "very-deeply-nested-folder/".repeat(4) + "stripe-webhook.ts";
    const message = `Leaked in ${longPath} near sk-proj-****W1xY`;
    const out = render(result([finding("critical", longPath, 7, message)]));

    expect(out).toContain(`  ${longPath}:7`);
    expect(lines(out)).toContain(`    ${longPath}`);
    expect(out).toContain("sk-proj-****W1xY");
  });

  it("wrap() only breaks at spaces", () => {
    const text = "word ".repeat(30).trim();
    const wrapped = wrap(text, "    ", "    ");
    expect(wrapped.length).toBeGreaterThan(1);
    for (const line of wrapped) {
      expect(line.length).toBeLessThanOrEqual(WIDTH);
      expect(line.trim().split(" ").every((w) => w === "word")).toBe(true);
    }
  });

  it("shows skipped-check warnings after the findings and before the footer", () => {
    const reason = "Not a git repository, so LeakProof can't tell whether .env files are committed.";
    const out = render(result([finding("high", "a.ts", 1)], { skipped: [{ check: committedEnv, reason }] }));

    expect(out).toContain("⚠ Committed .env files skipped: Not a git repository, so LeakProof can't tell");
    expect(out.indexOf("⚠")).toBeGreaterThan(out.indexOf("a.ts:1"));
    expect(out.indexOf("⚠")).toBeLessThan(out.indexOf(FOOTER));
    for (const line of lines(out)) expect(line.length).toBeLessThanOrEqual(WIDTH);
  });

  it("hides the checks list unless verbose", () => {
    const r = result([], { skipped: [{ check: committedEnv, reason: "No git." }] });
    expect(render(r)).not.toContain("Checks run");

    const verbose = render(r, true);
    expect(verbose).toContain("Checks run:\n  ✓ Leaked secret keys in code (leaked-keys)\n  ⚠ Committed .env files (committed-env): skipped");
  });

  it("uses SITE_URL from config.ts by default", () => {
    const out = renderReport(result([finding("critical", ".env", 7)]), { colors: noColors, version: "9.9.9" });
    expect(out).toContain(`${SITE_URL}/fix#f=SEC_SECRET_HARDCODED`);
  });

  it("has no ANSI codes with colors off, and has them with colors on", () => {
    const r = result([finding("critical", "a.ts", 1)]);
    expect(render(r)).not.toMatch(ANSI);
    expect(renderReport(r, { colors: pc.createColors(true), version: "1" })).toMatch(ANSI);
  });
});

describe("renderJson", () => {
  it("has the summary, contract findings with the one-line fix, and skipped checks", () => {
    const findings = [finding("high", "src/a.ts", 2), finding("critical", ".env", 7), finding("low", ".env", 0)];
    const ignored = [finding("critical", "old.ts", 1)];
    const text = renderJson(result(findings, { ignored, skipped: [{ check: committedEnv, reason: "No git." }] }), SITE);
    const json = JSON.parse(text);

    expect(json).toEqual({
      summary: {
        score: 39,
        grade: "F",
        counts: { critical: 1, high: 1, medium: 0, low: 1, info: 0 },
        security: { score: 39, grade: "F", counts: { critical: 1, high: 1, medium: 0, low: 1, info: 0 } },
        privacy: { count: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        filesChecked: 42,
        ignored: 1,
        fixLink: `${SITE}/fix#f=SEC_SECRET_HARDCODED`,
      },
      // Report order: worst first.
      findings: [findings[1], findings[0], findings[2]],
      skipped: [{ ruleId: "committed-env", name: "Committed .env files", reason: "No git." }],
      notChecked: [],
    });
    expect(Object.keys(json.findings[0]).sort()).toEqual(
      ["category", "confidence", "file", "fix", "fixId", "line", "message", "ruleId", "severity", "title"].sort(),
    );
    expect(text).not.toMatch(ANSI);
    expect(text).not.toContain("Nothing was sent");
  });

  it("fixLink is null and the score 100 when there's nothing to report", () => {
    const json = JSON.parse(renderJson(result([])));
    expect(json.summary).toMatchObject({ score: 100, grade: "A", fixLink: null, ignored: 0 });
    expect(json.findings).toEqual([]);
  });

  it("leaves out fields that aren't in the contract", () => {
    const extra = { ...finding("critical", "a.ts", 1), internal: "secret value" } as Finding;
    expect(renderJson(result([extra]))).not.toContain("secret value");
  });
});

describe("colors", () => {
  it("are off with NO_COLOR, off when not a terminal, on with FORCE_COLOR", () => {
    expect(useColor({ env: {}, isTTY: true })).toBe(true);
    expect(useColor({ env: { NO_COLOR: "1" }, isTTY: true })).toBe(false);
    expect(useColor({ env: {}, isTTY: false })).toBe(false);
    expect(useColor({ env: { FORCE_COLOR: "1" }, isTTY: false })).toBe(true);
    expect(useColor({ env: { FORCE_COLOR: "0" }, isTTY: true })).toBe(true);
    expect(useColor({ env: { FORCE_COLOR: "0" }, isTTY: false })).toBe(false);
    expect(useColor({ env: { NO_COLOR: "1", FORCE_COLOR: "1" }, isTTY: true })).toBe(false);
  });
});

describe("CLI exit codes and output", () => {
  let dir: string | undefined;

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = undefined;
  });

  async function cli(args: string[], extra: Partial<CliIo> = {}) {
    let stdout = "";
    let stderr = "";
    const code = await run(["node", "leakproof", ...args], {
      stdout: (t) => (stdout += t),
      stderr: (t) => (stderr += t),
      env: {},
      isTTY: false,
      ...extra,
    });
    return { code, stdout, stderr };
  }

  async function project(files: Record<string, string>) {
    dir = await mkdtemp(join(tmpdir(), "leakproof-cli-"));
    for (const [path, content] of Object.entries(files)) {
      await mkdir(join(dir, path, ".."), { recursive: true });
      await writeFile(join(dir, path), content);
    }
    return dir;
  }

  const key = "sk_" + "live_" + "x".repeat(24);

  it("0 for a clean folder", async () => {
    const { code, stdout } = await cli(["scan", await project({ "src/app.ts": "export const x = 1;\n" })]);
    expect(code).toBe(0);
    expect(stdout).toContain("Security 100/100 · Grade A · no leaks");
    expect(stdout).toContain("1 file checked");
  });

  it("1 when there are findings", async () => {
    const { code, stdout } = await cli(["scan", await project({ "src/app.ts": `const k = "${key}";\n` })]);
    expect(code).toBe(1);
    expect(stdout).toContain("Security 39/100 · Grade F · 1 critical");
    expect(stdout).not.toContain(key);
    expect(stdout).not.toMatch(ANSI); // not a terminal
  });

  it("ignored findings don't fail the scan, and the summary says how many", async () => {
    const files = { "src/app.ts": `const k = "${key}";\n`, ".leakproofignore": "# demo key\nsrc/app.ts:SEC_SECRET_HARDCODED\n" };
    const { code, stdout } = await cli(["scan", await project(files)]);
    expect(code).toBe(0);
    expect(stdout).toContain("Security 100/100 · Grade A · no leaks · 1 ignored");
    expect(stdout).not.toContain("src/app.ts");
  });

  it("--json prints only JSON, with the same exit code", async () => {
    const { code, stdout } = await cli(["scan", await project({ "src/app.ts": `"${key}"\n` }), "--json"], { isTTY: true });
    expect(code).toBe(1);
    expect(stdout).not.toMatch(ANSI); // even in a terminal
    expect(JSON.parse(stdout)).toMatchObject({ summary: { filesChecked: 1, counts: { critical: 1 } } });
  });

  it("2 when the path doesn't exist or isn't a folder", async () => {
    const missing = await cli(["scan", join(tmpdir(), "leakproof-does-not-exist-" + Date.now())]);
    expect(missing).toMatchObject({ code: 2, stdout: "" });
    expect(missing.stderr).toContain("folder not found");

    const file = join(await project({ "a.txt": "a" }), "a.txt");
    expect((await cli(["scan", file])).code).toBe(2);
    expect((await cli(["scan", file, "--json"])).stdout).toBe("");
  });

  it("2 when a check crashes", async () => {
    const crashing: Check = { ...check("boom", "Boom"), run: async () => { throw new Error("disk on fire"); } };
    const { code, stderr } = await cli(["scan", await project({})], { checks: [crashing] });
    expect(code).toBe(2);
    expect(stderr).toContain("LeakProof failed: disk on fire");
  });

  it("2 for usage errors, 0 for --help and --version", async () => {
    expect((await cli(["scan", ".", "--jsn"])).code).toBe(2);
    expect((await cli(["frobnicate"])).code).toBe(2);
    expect((await cli(["--help"])).code).toBe(0);
    expect((await cli(["--version"])).code).toBe(0);
  });
});

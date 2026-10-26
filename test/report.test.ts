import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pc from "picocolors";
import { afterEach, describe, expect, it } from "vitest";
import { run, useColor, type CliIo } from "../src/cli.js";
import { WAITLIST_URL } from "../src/config.js";
import { exitCodeFor, renderJson, renderReport, WIDTH, wrap } from "../src/report.js";
import type { ScanResult } from "../src/scan.js";
import type { Check, Finding, Severity } from "../src/types.js";

const noColors = pc.createColors(false);
const ANSI = /\u001b\[/;

const check = (id: string, name: string): Check => ({ id, name, severity: "critical", run: async () => [] });
const leakedKeys = check("leaked-keys", "Leaked secret keys in code");
const committedEnv = check("committed-env", "Committed .env files");

const finding = (
  severity: Severity,
  file: string,
  line: number,
  message = "Something leaked",
  fix = "Fix it.",
  checkId = "leaked-keys",
): Finding => ({
  checkId,
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
  skipped: [],
  filesChecked: 42,
  durationMs: 1234,
  ...extra,
});

const render = (r: ScanResult, verbose = false) => renderReport(r, { colors: noColors, version: "9.9.9", verbose });
const lines = (text: string) => text.trimEnd().split("\n");

describe("renderReport", () => {
  it("clean result", () => {
    expect(render(result([]))).toBe(
      [
        "LeakProof v9.9.9 · scanning my-app",
        "42 files checked in 1.2s",
        "",
        "✓ No leaks found",
        "",
        `Want 24/7 watching and AI fixes? → ${WAITLIST_URL}`,
        "",
      ].join("\n"),
    );
  });

  it("mixed severities: summary lists only the severities present", () => {
    const out = render(
      result([
        finding("critical", "src/lib/ai.ts", 1, "OpenAI API key hardcoded: sk-proj-****W1xY", "Move this key."),
        finding("high", "src/lib/payments.ts", 14),
        finding("critical", ".env", 7),
      ]),
    );

    expect(lines(out)[3]).toBe("✗ 3 leaks found · 2 critical · 1 high");
    expect(out).toContain(
      ["  src/lib/ai.ts:1", "    OpenAI API key hardcoded: sk-proj-****W1xY", "    → Move this key."].join("\n"),
    );
    expect(out).toContain(`Want 24/7 watching and AI fixes? → ${WAITLIST_URL}`);
  });

  it("only-medium result, singular wording", () => {
    const out = render(result([finding("medium", ".env.local", 3)]));
    expect(lines(out)[3]).toBe("✗ 1 leak found · 1 medium");
    expect(out).toContain("── MEDIUM (1) ──");
    expect(out).not.toContain("CRITICAL");
    expect(out).not.toContain("HIGH");
  });

  it("orders sections critical, high, medium whatever order the findings arrive in", () => {
    const out = render(result([finding("medium", "m.ts", 1), finding("high", "h.ts", 1), finding("critical", "c.ts", 1)]));
    const order = ["── CRITICAL", "── HIGH", "── MEDIUM"].map((title) => out.indexOf(title));
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(out.indexOf("c.ts:1")).toBeLessThan(out.indexOf("h.ts:1"));
    expect(out.indexOf("h.ts:1")).toBeLessThan(out.indexOf("m.ts:1"));
  });

  it("within a severity: stripe-webhook, then leaked-keys, then committed-env, by file:line within each", () => {
    const out = render(
      result([
        finding("critical", ".env", 9, "env 9", "Fix env 9.", "committed-env"),
        finding("critical", "src/z.ts", 1, "key z", "Fix z.", "leaked-keys"),
        finding("critical", ".env", 7, "env 7", "Fix env 7.", "committed-env"),
        finding("critical", "src/a.ts", 12, "key a12", "Fix a12.", "leaked-keys"),
        finding("critical", "src/a.ts", 3, "key a3", "Fix a3.", "leaked-keys"),
        finding("critical", "src/routes/api/hook.ts", 7, "webhook", "Fix hook.", "stripe-webhook"),
        finding("critical", "src/other.ts", 1, "unknown check", "Fix other.", "future-check"),
      ]),
    );
    const locations = lines(out).filter((l) => /^ {2}\S/.test(l)).map((l) => l.trim());
    expect(locations).toEqual([
      "src/routes/api/hook.ts:7",
      "src/a.ts:3",
      "src/a.ts:12",
      "src/z.ts:1",
      ".env:7",
      ".env:9",
      "src/other.ts:1",
    ]);
  });

  describe("shared fixes", () => {
    const fix = "Remove .env from git and rotate this key.";

    it("prints one fix after the last consecutive finding in a file with the same fix", () => {
      const out = render(
        result([
          finding("critical", ".env", 7, "STRIPE_SECRET_KEY is committed", fix, "committed-env"),
          finding("critical", ".env", 8, "SUPABASE_SERVICE_ROLE_KEY is committed", fix, "committed-env"),
          finding("critical", ".env", 9, "VITE_STRIPE_SECRET_KEY is committed", fix + " Also VITE.", "committed-env"),
        ]),
      );

      expect(out).toContain(
        [
          "  .env:7",
          "    STRIPE_SECRET_KEY is committed",
          "  .env:8",
          "    SUPABASE_SERVICE_ROLE_KEY is committed",
          `    → ${fix}`,
          "",
          "  .env:9",
          "    VITE_STRIPE_SECRET_KEY is committed",
          `    → ${fix} Also VITE.`,
          "",
        ].join("\n"),
      );
      expect(out.split(`→ ${fix}\n`)).toHaveLength(2); // the shared fix appears once
    });

    it("still prints the fix for each file when the same fix is in different files", () => {
      const out = render(result([finding("critical", "a/.env", 1, "A", fix), finding("critical", "b/.env", 1, "B", fix)]));
      expect(out.split(`→ ${fix}`)).toHaveLength(3);
    });

    it("still prints both fixes when the findings aren't consecutive", () => {
      const out = render(
        result([
          finding("critical", "src/a.ts", 1, "first", fix),
          finding("critical", "src/a.ts", 2, "middle", "A different fix."),
          finding("critical", "src/a.ts", 3, "last", fix),
        ]),
      );
      expect(out.split(`→ ${fix}`)).toHaveLength(3);
    });

    it("doesn't share a fix across severity groups", () => {
      const out = render(result([finding("critical", ".env", 1, "A", fix), finding("high", ".env", 2, "B", fix)]));
      expect(out.split(`→ ${fix}`)).toHaveLength(3);
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

    const fixStart = all.findIndex((l) => l.startsWith("    → Remove"));
    expect(all[fixStart + 1]).toMatch(/^ {6}\S/); // continuation lines line up under the text after "→ "
    expect(all.slice(fixStart, fixStart + 3).join(" ").replace(/ +/g, " ").trim()).toBe(`→ ${fix}`);

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

  it("shows skipped-check warnings after the findings", () => {
    const reason = "Not a git repository, so LeakProof can't tell whether .env files are committed.";
    const out = render(result([finding("high", "a.ts", 1)], { skipped: [{ check: committedEnv, reason }] }));

    expect(out).toContain("⚠ Committed .env files skipped: Not a git repository, so LeakProof can't tell");
    expect(out.indexOf("⚠")).toBeGreaterThan(out.indexOf("a.ts:1"));
    expect(out.indexOf("⚠")).toBeLessThan(out.indexOf("Want 24/7"));
    for (const line of lines(out)) expect(line.length).toBeLessThanOrEqual(WIDTH);
  });

  it("hides the checks list unless verbose", () => {
    const r = result([], { skipped: [{ check: committedEnv, reason: "No git." }] });
    expect(render(r)).not.toContain("Checks run");

    const verbose = render(r, true);
    expect(verbose).toContain("Checks run:\n  ✓ Leaked secret keys in code (leaked-keys)\n  ⚠ Committed .env files (committed-env): skipped");
  });

  it("has no ANSI codes with colors off, and has them with colors on", () => {
    const r = result([finding("critical", "a.ts", 1)]);
    expect(render(r)).not.toMatch(ANSI);
    expect(renderReport(r, { colors: pc.createColors(true), version: "1" })).toMatch(ANSI);
  });
});

describe("renderJson", () => {
  it("parses, matches the shape, and has no colors or footer", () => {
    const findings = [finding("critical", ".env", 7), finding("high", "src/a.ts", 2)];
    const text = renderJson(result(findings, { skipped: [{ check: committedEnv, reason: "No git." }] }), "9.9.9");
    const json = JSON.parse(text);

    expect(json).toEqual({
      version: "9.9.9",
      path: join(tmpdir(), "my-app"),
      filesChecked: 42,
      durationMs: 1234,
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      findings,
      skipped: [{ checkId: "committed-env", name: "Committed .env files", reason: "No git." }],
    });
    expect(text).not.toMatch(ANSI);
    expect(text).not.toContain("Want 24/7");
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

  it("0 for a clean folder", async () => {
    const { code, stdout } = await cli(["scan", await project({ "src/app.ts": "export const x = 1;\n" })]);
    expect(code).toBe(0);
    expect(stdout).toContain("✓ No leaks found");
    expect(stdout).toContain("1 file checked");
  });

  it("1 when there are findings", async () => {
    const key = "sk_" + "live_" + "x".repeat(24);
    const { code, stdout } = await cli(["scan", await project({ "src/app.ts": `const k = "${key}";\n` })]);
    expect(code).toBe(1);
    expect(stdout).toContain("✗ 1 leak found · 1 critical");
    expect(stdout).not.toContain(key);
    expect(stdout).not.toMatch(ANSI); // not a terminal
  });

  it("--json prints only JSON, with the same exit code", async () => {
    const key = "sk_" + "live_" + "x".repeat(24);
    const { code, stdout } = await cli(["scan", await project({ "src/app.ts": `"${key}"\n` }), "--json"], { isTTY: true });
    expect(code).toBe(1);
    expect(stdout).not.toMatch(ANSI); // even in a terminal
    expect(JSON.parse(stdout)).toMatchObject({ filesChecked: 1, summary: { total: 1, critical: 1 } });
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

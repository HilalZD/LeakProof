import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { run, type CliIo } from "../src/cli.js";
import { annotationLevel, escapeData, escapeProperty, renderAnnotations, renderGithub, renderMarkdownSummary } from "../src/github.js";
import { exitCodeFor, type FailOn } from "../src/report.js";
import type { ScanResult } from "../src/scan.js";
import type { ScanFinding as Finding, Severity } from "../src/types.js";

const finding = (severity: Severity, file?: string, line?: number, extra: Partial<Finding> = {}): Finding => ({
  ruleId: "test-rule",
  fixId: "SEC_SECRET_HARDCODED",
  severity,
  category: "security",
  title: "Secret in code",
  message: "Key sk_live_****abcd is in the code.",
  file,
  line,
  confidence: "high",
  ...extra,
});

const result = (findings: Finding[]): ScanResult => ({
  projectPath: "/p",
  checks: [],
  findings,
  ignored: [],
  skipped: [],
  filesChecked: 3,
  durationMs: 5,
});

describe("--fail-on thresholds", () => {
  const cases: [Severity, FailOn, 0 | 1][] = [
    ["critical", "critical", 1],
    ["high", "critical", 0],
    ["high", "high", 1],
    ["medium", "high", 0],
    ["medium", "medium", 1],
    ["low", "medium", 0],
    ["low", "low", 1],
    ["info", "low", 0],
  ];
  it.each(cases)("a %s finding with --fail-on %s exits %i", (severity, failOn, code) => {
    expect(exitCodeFor(result([finding(severity, "a.ts", 1)]), failOn)).toBe(code);
  });

  it("defaults to medium", () => {
    expect(exitCodeFor(result([finding("medium", "a.ts", 1)]))).toBe(1);
    expect(exitCodeFor(result([finding("low", "a.ts", 1)]))).toBe(0);
    expect(exitCodeFor(result([]))).toBe(0);
  });
});

describe("annotation escaping", () => {
  it("escapes %, CR and LF in messages", () => {
    expect(escapeData("100% done\r\nnext")).toBe("100%25 done%0D%0Anext");
    expect(escapeData("a: b, c")).toBe("a: b, c");
  });

  it("also escapes : and , in properties", () => {
    expect(escapeProperty("C:/a,b%\n.ts")).toBe("C%3A/a%2Cb%25%0A.ts");
  });
});

describe("annotations", () => {
  it("maps severities to levels", () => {
    expect(["critical", "high", "medium", "low", "info"].map((s) => annotationLevel(s as Severity))).toEqual([
      "error",
      "error",
      "warning",
      "warning",
      "notice",
    ]);
  });

  it("formats file, line, title and message, worst first", () => {
    const lines = renderAnnotations([finding("low", "b.ts", 2), finding("critical", "src/a.ts", 7)]);
    expect(lines).toEqual([
      "::error file=src/a.ts,line=7::Secret in code: Key sk_live_****abcd is in the code.",
      "::warning file=b.ts,line=2::Secret in code: Key sk_live_****abcd is in the code.",
    ]);
  });

  it("escapes awkward file names and multi-line messages", () => {
    const [line] = renderAnnotations([finding("high", "odd,name:1.ts", 3, { title: "50% bad", message: "one\ntwo" })]);
    expect(line).toBe("::error file=odd%2Cname%3A1.ts,line=3::50%25 bad: one%0Atwo");
  });

  it("leaves out file and line when they aren't known", () => {
    expect(renderAnnotations([finding("info")])).toEqual(["::notice::Secret in code: Key sk_live_****abcd is in the code."]);
    expect(renderAnnotations([finding("medium", ".env")])).toEqual(["::warning file=.env::Secret in code: Key sk_live_****abcd is in the code."]);
  });

  it("adds one annotation per 'also at' place", () => {
    const lines = renderAnnotations([finding("critical", ".env", 9, { alsoAt: [{ file: "src/p.ts", line: 4 }] })]);
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe("::error file=src/p.ts,line=4::Secret in code: same secret as .env:9. Key sk_live_****abcd is in the code.");
  });

  it("ends with a plain summary line and the fix link", () => {
    const out = renderGithub(result([finding("critical", "a.ts", 1)]), "https://example.test");
    expect(out.trimEnd().split("\n").slice(-2)).toEqual([
      "Leakproof: Security 39/100 · Grade F · 1 critical",
      "Fixes: https://example.test/fix#1",
    ]);
    expect(renderGithub(result([]))).toBe("Leakproof: Security 100/100 · Grade A · no leaks\n");
  });
});

describe("Markdown summary", () => {
  it("has the score, grade, a findings table and the fix link", () => {
    const md = renderMarkdownSummary(
      result([finding("high", "src/a.ts", 3, { message: "a | b", alsoAt: [{ file: ".env", line: 2 }] }), finding("info", undefined, undefined, { fixId: "SEC_SUPABASE_RLS_UNVERIFIED" })]),
      "9.9.9",
      "https://example.test",
    );
    expect(md).toContain("## Leakproof v9.9.9");
    expect(md).toContain("**Security 59/100 · Grade D** · 1 high, 1 couldn't verify");
    expect(md).toContain("| Severity | Finding | Location | Rule |");
    expect(md).toContain("| high | **Secret in code**<br>a \\| b | `src/a.ts:3`, `.env:2` | `SEC_SECRET_HARDCODED` |");
    expect(md).toContain("https://example.test/fix#e9"); // SEC_SECRET_HARDCODED + SEC_SUPABASE_RLS_UNVERIFIED
  });

  it("has no table for a clean scan", () => {
    const md = renderMarkdownSummary(result([]), "1.0.0");
    expect(md).toContain("no leaks");
    expect(md).not.toContain("| Severity");
  });
});

describe("CLI --format github and --fail-on", () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = undefined;
  });

  const key = "sk_" + "live_" + "x".repeat(24);

  async function project(files: Record<string, string>) {
    dir = await mkdtemp(join(tmpdir(), "leakproof-gh-"));
    for (const [path, content] of Object.entries(files)) {
      await mkdir(join(dir, path, ".."), { recursive: true });
      await writeFile(join(dir, path), content);
    }
    return dir;
  }

  async function cli(args: string[], extra: Partial<CliIo> = {}) {
    let stdout = "";
    let stderr = "";
    const code = await run(["node", "leakproof", ...args], {
      stdout: (t) => (stdout += t),
      stderr: (t) => (stderr += t),
      env: {},
      isTTY: true,
      ...extra,
    });
    return { code, stdout, stderr };
  }

  it("prints masked annotations, no colors, and writes the job summary", async () => {
    const path = await project({ "src/app.ts": `const k = "${key}";\n` });
    const writes: [string, string][] = [];
    const { code, stdout } = await cli([path, "--format", "github"], {
      env: { GITHUB_STEP_SUMMARY: "/summary.md" },
      appendFile: (file, text) => writes.push([file, text]),
    });
    expect(code).toBe(1);
    expect(stdout).toMatch(/^::error file=src\/app\.ts,line=1::/);
    expect(stdout).not.toContain("\u001b[");
    expect(stdout).not.toContain(key);
    expect(writes).toHaveLength(1);
    expect(writes[0][0]).toBe("/summary.md");
    expect(writes[0][1]).toContain("Grade F");
    expect(writes[0][1]).not.toContain(key);
  });

  it("writes a real summary file when GITHUB_STEP_SUMMARY is set", async () => {
    const path = await project({ "src/app.ts": `const k = "${key}";\n` });
    const summary = join(path, "..", `leakproof-summary-${Date.now()}.md`);
    try {
      await cli([path, "--format", "github"], { env: { GITHUB_STEP_SUMMARY: summary } });
      expect(await readFile(summary, "utf8")).toContain("| critical |");
    } finally {
      await rm(summary, { force: true });
    }
  });

  it("skips the summary when GITHUB_STEP_SUMMARY isn't set", async () => {
    const writes: string[] = [];
    await cli([await project({}), "--format", "github"], { appendFile: (f) => writes.push(f) });
    expect(writes).toEqual([]);
  });

  it("--fail-on changes only the exit code", async () => {
    const path = await project({ "src/app.ts": `const k = "${key}";\n` });
    expect((await cli([path, "--fail-on", "critical"])).code).toBe(1);
    expect((await cli(["scan", path, "--fail-on", "high"])).code).toBe(1);
    const clean = await project({ "src/app.ts": "export const x = 1;\n" });
    expect((await cli([clean, "--fail-on", "low"])).code).toBe(0);
  });

  it("rejects unknown severities and formats", async () => {
    expect((await cli([".", "--fail-on", "info"])).code).toBe(2);
    expect((await cli([".", "--format", "xml"])).code).toBe(2);
  });

  it("scan is the default command", async () => {
    const { code, stdout } = await cli([await project({ "a.ts": "export {};\n" })], { isTTY: false });
    expect(code).toBe(0);
    expect(stdout).toContain("Grade A");
  });
});

describe("action.yml", () => {
  it("pins the CLI to the package version and passes both inputs", async () => {
    const yml = await readFile(new URL("../action.yml", import.meta.url), "utf8");
    const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
    expect(yml).toContain("using: composite");
    expect(yml).toContain(`npx --yes @leakproof/cli@${pkg.version} "$LEAKPROOF_PATH" --format github --fail-on "$LEAKPROOF_FAIL_ON"`);
    expect(yml).toMatch(/fail-on:\n(?:.*\n)*?\s+default: medium/);
    expect(yml).toMatch(/path:\n(?:.*\n)*?\s+default: \./);
  });
});

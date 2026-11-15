import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { renderAnnotations, renderGithub, renderMarkdownSummary } from "../src/github.js";
import { exitCodeFor, NOT_LEGAL_ADVICE, renderJson, renderReport } from "../src/report.js";
import { rules as privacyRules } from "../src/rules/privacy/index.js";
import { PRIVACY_FIXES } from "../src/rules/privacy/laws.js";
import type { ScanResult } from "../src/scan.js";
import type { ScanFinding as Finding, ScannerRule, Severity } from "../src/types.js";

const securityCheck: ScannerRule = { id: "leaked-keys", category: "security", description: "Leaked keys", passedLabel: "No secret keys in code", run: () => [] };

const sec = (severity: Severity, file = "src/a.ts", line = 1): Finding => ({
  ruleId: "leaked-keys",
  fixId: "SEC_SECRET_HARDCODED",
  severity,
  category: "security",
  title: "Secret in code",
  message: "Key sk_live_****abcd is in the code.",
  file,
  line,
  confidence: "high",
  fix: "Rotate it.",
});

const priv = (id: keyof typeof PRIVACY_FIXES, confidence: Finding["confidence"] = "medium", file = "src/Signup.tsx", line = 13): Finding => ({
  ruleId: id,
  fixId: id,
  severity: PRIVACY_FIXES[id].severity,
  category: "privacy",
  title: PRIVACY_FIXES[id].title,
  message: `Possible gap: ${id}.`,
  file,
  line,
  lawRefs: [...PRIVACY_FIXES[id].lawRefs],
  confidence,
  fix: PRIVACY_FIXES[id].fix,
});

const result = (findings: Finding[]): ScanResult => ({
  projectPath: "/p",
  checks: [securityCheck, ...privacyRules],
  findings,
  ignored: [],
  skipped: [],
  filesChecked: 5,
  durationMs: 10,
});

const render = (r: ScanResult) => renderReport(r, { colors: pc.createColors(false), version: "9.9.9", siteUrl: "https://fix.test" });

describe("privacy never changes the security score", () => {
  it("scores and grades security findings only, and shows privacy on its own line", () => {
    const out = render(result([sec("low"), priv("PRIV_NO_PRIVACY_POLICY"), priv("PRIV_NO_ACCOUNT_DELETION"), priv("PRIV_NO_DATA_EXPORT", "low")]));
    const lines = out.split("\n");
    expect(lines[2]).toBe("Security 99/100 · Grade A · 1 low");
    expect(lines[3]).toBe("Privacy: 3 possible gaps (not legal advice)");
  });

  it("says when no privacy gaps were found", () => {
    expect(render(result([]))).toContain("Privacy: no possible gaps found (not legal advice)");
    expect(render(result([]))).not.toContain(NOT_LEGAL_ADVICE);
  });

  it("privacy-only results are still Security 100/100 · Grade A", () => {
    expect(render(result([priv("PRIV_TRACKER_BEFORE_CONSENT")]))).toContain("Security 100/100 · Grade A · no leaks");
  });
});

describe("privacy section", () => {
  const out = render(
    result([
      priv("PRIV_NO_DATA_EXPORT", "low"),
      sec("critical"),
      priv("PRIV_PII_IN_LOGS", "medium", "src/a.ts", 20),
      priv("PRIV_NO_PRIVACY_POLICY"),
    ]),
  );

  it("comes after the security findings, worst first", () => {
    const at = (text: string) => out.indexOf(text);
    expect(at("── CRITICAL (1)")).toBeLessThan(at("── PRIVACY GAPS (possible) (3)"));
    expect(at("No privacy policy found")).toBeLessThan(at("Personal data printed to logs"));
    expect(at("Personal data printed to logs")).toBeLessThan(at("Users can't get a copy of their data"));
    expect(at("── PRIVACY GAPS")).toBeLessThan(at("Copy-paste fixes"));
  });

  it("shows title, file:line, message, laws on one line, and a fix for high/medium only", () => {
    expect(out).toContain(
      [
        "  No privacy policy found",
        "  src/Signup.tsx:13",
        "    Possible gap: PRIV_NO_PRIVACY_POLICY.",
        "    GDPR Art. 13 · PIPEDA 4.8",
        "    → Fix: Add a privacy policy page",
      ].join("\n"),
    );
    expect(out).toContain("  Users can't get a copy of their data (low confidence)\n  src/Signup.tsx:13\n    Possible gap: PRIV_NO_DATA_EXPORT.\n    GDPR Art. 15 · GDPR Art. 20 · PIPEDA 4.9\n\n");
  });

  it("prints 'This is not legal advice.' exactly once, under the privacy section", () => {
    expect(out.split(NOT_LEGAL_ADVICE)).toHaveLength(2);
    expect(out.indexOf(NOT_LEGAL_ADVICE)).toBeGreaterThan(out.indexOf("Users can't get a copy of their data"));
  });

  it("never gives privacy rules a ✓, even on a clean security result", () => {
    const clean = render(result([priv("PRIV_NO_PRIVACY_POLICY")]));
    expect(clean).toContain("✓ No secret keys in code");
    expect(clean.match(/✓/g)).toHaveLength(1);
  });

  it("the fix link lists each fixId once, privacy included", () => {
    const link = render(result([sec("high"), priv("PRIV_PII_IN_LOGS", "medium", "a.ts", 1), priv("PRIV_PII_IN_LOGS", "medium", "a.ts", 2), priv("PRIV_PII_IN_LOGS", "medium", "b.ts", 3)]))
      .split("\n")
      .find((l) => l.startsWith("https://fix.test"));
    expect(link).toBe("https://fix.test/fix?f=SEC_SECRET_HARDCODED,PRIV_PII_IN_LOGS");
  });
});

describe("exit code: security only, unless --fail-on-privacy", () => {
  const privacyOnly = result([priv("PRIV_NO_PRIVACY_POLICY"), priv("PRIV_NO_DATA_EXPORT", "low")]);

  it("privacy never fails by default", () => {
    expect(exitCodeFor(privacyOnly)).toBe(0);
    expect(exitCodeFor(privacyOnly, "low")).toBe(0);
    expect(exitCodeFor(result([sec("medium"), priv("PRIV_NO_PRIVACY_POLICY")]))).toBe(1);
  });

  it("--fail-on-privacy fails at that severity or worse", () => {
    const mediumOnly = result([priv("PRIV_PII_IN_LOGS")]);
    expect(exitCodeFor(mediumOnly, "medium", "high")).toBe(0);
    expect(exitCodeFor(mediumOnly, "medium", "medium")).toBe(1);
    expect(exitCodeFor(result([priv("PRIV_NO_DATA_EXPORT", "low")]), "medium", "medium")).toBe(0);
    expect(exitCodeFor(result([priv("PRIV_NO_DATA_EXPORT", "low")]), "medium", "low")).toBe(1);
    expect(exitCodeFor(privacyOnly, "medium", "high")).toBe(1);
  });

  it("works from the CLI on Serena's bad-app fixture", async () => {
    const badApp = fileURLToPath(new URL("./fixtures/privacy/bad-app", import.meta.url));
    const cli = (args: string[]) => run(["node", "leakproof", badApp, ...args], { stdout: () => {}, stderr: () => {}, env: { CI: "1" }, isTTY: false });
    expect(await cli([])).toBe(0);
    expect(await cli(["--fail-on-privacy", "high"])).toBe(1);
    expect(await cli(["--fail-on-privacy", "critical"])).toBe(2);
  });
});

describe("JSON and GitHub output", () => {
  const r = result([sec("high"), priv("PRIV_NO_PRIVACY_POLICY"), priv("PRIV_NO_DATA_EXPORT", "low")]);

  it("JSON summary has security {score, grade, counts} and privacy {count, bySeverity}", () => {
    const { summary, findings } = JSON.parse(renderJson(r));
    expect(summary.security).toEqual({ score: 59, grade: "D", counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } });
    expect(summary.privacy).toEqual({ count: 2, bySeverity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 } });
    expect(summary.score).toBe(59);
    expect(findings.map((f: Finding) => f.category)).toEqual(["security", "privacy", "privacy"]);
    expect(findings[1].lawRefs).toEqual(["GDPR Art. 13", "PIPEDA Principle 4.8"]);
  });

  it("privacy findings are ::notice, never ::error or ::warning", () => {
    const lines = renderAnnotations(r.findings);
    expect(lines[0]).toMatch(/^::error /);
    expect(lines.slice(1).every((l) => l.startsWith("::notice file="))).toBe(true);
    expect(lines[1]).toContain("::Privacy (possible gap): No privacy policy found: ");
  });

  it("the stdout summary and the job summary keep privacy apart, with the legal note", () => {
    expect(renderGithub(r)).toContain("Leakproof: Security 59/100 · Grade D · 1 high\nPrivacy: 2 possible gaps (not legal advice)\n");
    const md = renderMarkdownSummary(r, "1.0.0");
    expect(md).toContain("**Security 59/100 · Grade D** · 1 high");
    expect(md).toContain("### Privacy gaps (possible)");
    expect(md).toContain("| low | **Users can't get a copy of their data** (low confidence)<br>");
    expect(md).toContain("GDPR Art. 13 · PIPEDA 4.8");
    expect(md).toContain(`_${NOT_LEGAL_ADVICE}_`);
  });
});

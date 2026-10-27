import { basename } from "node:path";
import pc from "picocolors";
import { WAITLIST_URL } from "./config.js";
import type { ScanResult } from "./scan.js";
import type { Finding, Severity } from "./types.js";

export type Colors = ReturnType<typeof pc.createColors>;

export interface ReportOptions {
  colors: Colors;
  version: string;
  verbose?: boolean;
}

export const WIDTH = 80;

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

/** Leaks fail the scan; LOW findings are warnings and don't. */
const LEAK_SEVERITIES: Severity[] = ["critical", "high", "medium"];
export const isLeak = (finding: Finding) => LEAK_SEVERITIES.includes(finding.severity);

// Within a severity group, findings are shown in this check order; any other
// check comes after these.
const CHECK_ORDER = ["stripe-webhook", "leaked-keys", "committed-env"];

const checkRank = (checkId: string) => {
  const index = CHECK_ORDER.indexOf(checkId);
  return index === -1 ? CHECK_ORDER.length : index;
};

/** Orders findings by check, then by file and line within each check. */
export function sortForReport(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      checkRank(a.checkId) - checkRank(b.checkId) ||
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}

function severityColor(c: Colors, severity: Severity): (text: string) => string {
  if (severity === "critical") return c.red;
  if (severity === "high") return c.yellow;
  if (severity === "medium") return c.cyan;
  return c.blue;
}

/**
 * Word-wraps text to WIDTH columns. The first line starts with `first`, the
 * rest with `rest` (a hanging indent). Lines only break at spaces, so a path
 * or masked key is never split; a word too long for any line gets a line of
 * its own and runs past WIDTH rather than being cut.
 */
export function wrap(text: string, first: string, rest: string): string[] {
  const lines: string[] = [];
  let line = first;
  let empty = true;
  for (const word of text.split(/ +/)) {
    const candidate = empty ? line + word : `${line} ${word}`;
    if (empty || candidate.length <= WIDTH) {
      line = candidate;
      empty = false;
    } else {
      lines.push(line);
      line = rest + word;
    }
  }
  lines.push(line);
  return lines;
}

function divider(c: Colors, severity: Severity, count: number): string {
  const title = `── ${severity.toUpperCase()} (${count}) `;
  return severityColor(c, severity)(c.bold(title + "─".repeat(Math.max(0, WIDTH - title.length))));
}

function renderFinding(c: Colors, finding: Finding, showFix: boolean): string[] {
  const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
  const lines = [`  ${c.bold(location)}`, ...wrap(finding.message, "    ", "    ")];
  if (!showFix) return lines;

  const fix = wrap(finding.fix, "    → ", "      ");
  fix[0] = `    ${severityColor(c, finding.severity)("→")}${fix[0].slice(5)}`;
  return [...lines, ...fix];
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The human-readable report, ending in a newline. */
export function renderReport(result: ScanResult, { colors: c, version, verbose = false }: ReportOptions): string {
  const out: string[] = [];
  const folder = basename(result.projectPath) || result.projectPath;
  const seconds = Math.max(result.durationMs / 1000, 0.1).toFixed(1);

  out.push(`${c.bold("LeakProof")} v${version} · scanning ${c.bold(folder)}`);
  out.push(c.dim(`${plural(result.filesChecked, "file")} checked in ${seconds}s`));
  out.push("");

  if (verbose) {
    out.push("Checks run:");
    for (const check of result.checks) {
      const skipped = result.skipped.some((s) => s.check === check);
      const mark = skipped ? c.yellow("⚠") : c.green("✓");
      out.push(`  ${mark} ${check.name} ${c.dim(`(${check.id})`)}${skipped ? c.yellow(": skipped") : ""}`);
    }
    out.push("");
  }

  const counts = countBySeverity(result.findings);
  const leaks = result.findings.filter(isLeak);
  const warnings = counts.low > 0 ? [c.blue(plural(counts.low, "low-risk warning"))] : [];
  if (leaks.length === 0) {
    out.push([c.green(c.bold("✓ No leaks found")), ...warnings].join(" · "));
    out.push("");

    // Clean result: show what passed. Skipped checks never count as passed.
    const passed = [...result.checks]
      .sort((a, b) => checkRank(a.id) - checkRank(b.id))
      .filter((check) => !result.skipped.some((s) => s.check === check));
    if (passed.length > 0) {
      for (const check of passed) out.push(`  ${c.green("✓")} ${check.passedLabel}`);
      out.push("");
    }
  } else {
    const parts = LEAK_SEVERITIES.filter((s) => counts[s] > 0).map((s) => severityColor(c, s)(`${counts[s]} ${s}`));
    out.push([c.red(c.bold(`✗ ${plural(leaks.length, "leak")} found`)), ...parts, ...warnings].join(" · "));
    out.push("");
  }

  for (const severity of SEVERITY_ORDER) {
    const group = sortForReport(result.findings.filter((f) => f.severity === severity));
    if (group.length === 0) continue;
    out.push(divider(c, severity, group.length), "");
    group.forEach((finding, i) => {
      // Consecutive findings in one file with the same fix share a single
      // fix line after the last of them, with no blank line in between.
      const next = group[i + 1];
      const sharesFix = next !== undefined && next.file === finding.file && next.fix === finding.fix;
      out.push(...renderFinding(c, finding, !sharesFix));
      if (!sharesFix) out.push("");
    });
  }

  if (result.skipped.length > 0) {
    for (const { check, reason } of result.skipped) {
      out.push(...wrap(`${check.name} skipped: ${reason}`, "⚠ ", "  ").map((l) => c.yellow(l)));
    }
    out.push("");
  }

  out.push(c.dim(`Want 24/7 watching and AI fixes? → ${WAITLIST_URL}`));
  return out.join("\n") + "\n";
}

/** Machine-readable output: no colors, no footer. */
export function renderJson(result: ScanResult, version: string): string {
  const counts = countBySeverity(result.findings);
  return JSON.stringify(
    {
      version,
      path: result.projectPath,
      filesChecked: result.filesChecked,
      durationMs: result.durationMs,
      summary: { total: result.findings.length, leaks: result.findings.filter(isLeak).length, ...counts },
      findings: result.findings,
      skipped: result.skipped.map(({ check, reason }) => ({ checkId: check.id, name: check.name, reason })),
    },
    null,
    2,
  ) + "\n";
}

/** 0 = no leaks (LOW warnings allowed), 1 = leaks. (2, the scanner failing, is decided by the CLI.) */
export function exitCodeFor(result: ScanResult): 0 | 1 {
  return result.findings.some(isLeak) ? 1 : 0;
}

import type { ScanResult } from "./scan.js";
import { NOT_LEGAL_ADVICE, isPrivacy, notCheckedLines, privacyOnly, reportOrder, securityOnly, shortLawRef, summarize } from "./report.js";
import type { ScanFinding as Finding, Severity } from "./types.js";

/**
 * GitHub Actions output: workflow-command annotations on stdout and a
 * Markdown job summary. Findings only ever hold masked values, so nothing
 * here can print a full secret.
 */

/** Escapes an annotation's message (GitHub's rules: %, CR and LF). */
export function escapeData(text: string): string {
  return text.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/** Escapes an annotation property such as file= (also : and ,). */
export function escapeProperty(text: string): string {
  return escapeData(text).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

/** critical/high fail loudly as errors, medium/low are warnings, info ("couldn't verify") is a notice. */
export function annotationLevel(severity: Severity): "error" | "warning" | "notice" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "notice";
}

function annotation(level: string, where: { file?: string; line?: number }, text: string): string {
  const props: string[] = [];
  if (where.file) props.push(`file=${escapeProperty(where.file)}`);
  if (where.file && where.line) props.push(`line=${where.line}`);
  return `::${level}${props.length > 0 ? " " + props.join(",") : ""}::${escapeData(text)}`;
}

/** One annotation per location: the finding's own and every "also at" place of the same secret. */
export function renderAnnotations(findings: Finding[]): string[] {
  const lines: string[] = [];
  for (const f of reportOrder(findings)) {
    // Privacy gaps are never errors or warnings: they don't fail the scan.
    const level = isPrivacy(f) ? "notice" : annotationLevel(f.severity);
    const text = isPrivacy(f) ? `Privacy (possible gap): ${f.title}: ${f.message}` : `${f.title}: ${f.message}`;
    lines.push(annotation(level, f, text));
    const first = f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : undefined;
    for (const other of f.alsoAt ?? []) {
      lines.push(annotation(level, other, first ? `${f.title}: same secret as ${first}. ${f.message}` : text));
    }
  }
  return lines;
}

/** Makes text safe inside a Markdown table cell. */
const cell = (text: string) => text.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

const location = (f: { file?: string; line?: number }) => (f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : "");

/** The Markdown job summary: security score and grade, a findings table, the privacy gaps, and the fix link. */
export function renderMarkdownSummary(result: ScanResult, version: string, siteUrl?: string): string {
  const s = summarize(result, siteUrl);
  const counts = (["critical", "high", "medium", "low", "info"] as Severity[])
    .filter((sev) => s.counts[sev] > 0)
    .map((sev) => `${s.counts[sev]} ${sev === "info" ? "couldn't verify" : sev}`);
  const out = [
    `## Leakproof v${version}`,
    "",
    `**Security ${s.score}/100 · Grade ${s.grade}** · ${counts.length > 0 ? counts.join(", ") : "no leaks"}` +
      (s.ignored > 0 ? ` · ${s.ignored} ignored` : ""),
    "",
    `${s.filesChecked} file${s.filesChecked === 1 ? "" : "s"} checked locally. Your code never left the runner.`,
    "",
  ];
  if (s.privacy.count > 0) out.splice(4, 0, `Privacy: ${s.privacy.count} possible gap${s.privacy.count === 1 ? "" : "s"} (not legal advice)`, "");
  const findings = reportOrder(securityOnly(result.findings));
  if (findings.length > 0) {
    out.push("| Severity | Finding | Location | Rule |", "|---|---|---|---|");
    for (const f of findings) {
      const where = [location(f), ...(f.alsoAt ?? []).map(location)].filter(Boolean).map((l) => `\`${cell(l)}\``).join(", ");
      out.push(`| ${f.severity} | **${cell(f.title)}**<br>${cell(f.message)} | ${where} | \`${f.fixId}\` |`);
    }
    out.push("");
  }
  const privacy = reportOrder(privacyOnly(result.findings));
  if (privacy.length > 0) {
    out.push("### Privacy gaps (possible)", "", "| Severity | Possible gap | Location | Laws | Rule |", "|---|---|---|---|---|");
    for (const f of privacy) {
      const low = f.confidence === "low" ? " (low confidence)" : "";
      const where = f.file ? "`" + cell(location(f)) + "`" : "";
      const laws = cell((f.lawRefs ?? []).map(shortLawRef).join(" · "));
      out.push(`| ${f.severity} | **${cell(f.title)}**${low}<br>${cell(f.message)} | ${where} | ${laws} | \`${f.fixId}\` |`);
    }
    out.push("", `_${NOT_LEGAL_ADVICE}_`, "");
  }
  // Checks that didn't run, so the summary never implies they passed.
  const notRun = notCheckedLines(result);
  if (notRun.length > 0) out.push(...notRun.map((line) => `- ${line}`), "");
  if (s.fixLink) out.push(`**Copy-paste fixes for Lovable, Bolt, Cursor, Claude Code or Codex:** ${s.fixLink}`, "");
  return out.join("\n");
}

/** stdout for --format github: the annotations, then one plain summary line. */
export function renderGithub(result: ScanResult, siteUrl?: string): string {
  const s = summarize(result, siteUrl);
  const counts = (["critical", "high", "medium", "low"] as Severity[]).filter((sev) => s.counts[sev] > 0).map((sev) => `${s.counts[sev]} ${sev}`);
  const lines = [
    ...renderAnnotations(result.findings),
    `Leakproof: Security ${s.score}/100 · Grade ${s.grade} · ${counts.length > 0 ? counts.join(", ") : "no leaks"}`,
    ...(s.privacy.count > 0 ? [`Privacy: ${s.privacy.count} possible gap${s.privacy.count === 1 ? "" : "s"} (not legal advice)`] : []),
  ];
  if (s.fixLink) lines.push(`Fixes: ${s.fixLink}`);
  return lines.join("\n") + "\n";
}

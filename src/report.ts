import pc from "picocolors";
import { SITE_URL } from "./config.js";
import type { ScanResult } from "./scan.js";
import { PRIVACY_FIX_IDS } from "./rules/privacy/laws.js";
import { buildFixLink, countBySeverity, gradeFor, scoreFor, type Grade } from "./summary.js";
import type { Rule, ScanFinding as Finding, ScannerRule, Severity } from "./types.js";

export { countBySeverity };

export type Colors = ReturnType<typeof pc.createColors>;

export interface ReportOptions {
  colors: Colors;
  version: string;
  verbose?: boolean;
  /** Base of the fix link. Defaults to SITE_URL from config.ts. */
  siteUrl?: string;
  /**
   * Opt-in usage counts: "off" adds one quiet line inviting the user to turn
   * them on, "on" changes the footer so it never claims nothing was sent.
   * Left out (or "hidden", e.g. in CI): the plain footer.
   */
  telemetry?: "on" | "off" | "hidden";
}

export const TELEMETRY_HINT = "Help improve Leakproof: `leakproof telemetry on` shares anonymous counts (never code).";

export const WIDTH = 80;

/** Sections with their own divider, worst first. info goes under "Couldn't verify". */
const SECTION_ORDER: Severity[] = ["critical", "high", "medium", "low"];

/**
 * Privacy findings are possible gaps, never leaks: they get their own section
 * and never change the score, grade or exit code (unless --fail-on-privacy).
 */
export const isPrivacy = (finding: Pick<Finding, "category">) => finding.category === "privacy";
export const securityOnly = (findings: Finding[]) => findings.filter((f) => !isPrivacy(f));
export const privacyOnly = (findings: Finding[]) => findings.filter(isPrivacy);

/** Security leaks fail the scan; LOW findings are warnings and info is "couldn't verify". */
const LEAK_SEVERITIES: Severity[] = ["critical", "high", "medium"];
export const isLeak = (finding: Finding) => !isPrivacy(finding) && LEAK_SEVERITIES.includes(finding.severity);

/** Privacy gaps at these severities print their one-line fix. */
const PRIVACY_FIX_SEVERITIES: Severity[] = ["high", "medium"];

/** Privacy findings worst first, then in the rule pack's order, then by file and line. */
export function sortPrivacy(findings: Finding[]): Finding[] {
  const rank = (f: Finding) => PRIVACY_FIX_IDS.indexOf(f.fixId as (typeof PRIVACY_FIX_IDS)[number]);
  return [...findings].sort(
    (a, b) =>
      [...SECTION_ORDER, "info"].indexOf(a.severity) - [...SECTION_ORDER, "info"].indexOf(b.severity) ||
      rank(a) - rank(b) ||
      (a.file ?? "").localeCompare(b.file ?? "") ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}

/** "PIPEDA Principle 4.8" reads as "PIPEDA 4.8" in the terminal; JSON keeps the contract wording. */
export const shortLawRef = (ref: string) => ref.replace(/^PIPEDA Principles? /, "PIPEDA ");


/** Findings at these severities print their one-line fix. */
const FIX_SEVERITIES: Severity[] = ["critical", "high"];

// Within a severity group, findings are shown in this rule order; any other
// rule comes after these.
const CHECK_ORDER = ["stripe-webhook", "supabase-rls", "api-auth", "rate-limit", "service-role-client", "client-exposed", "leaked-keys", "committed-env"];

const checkRank = (ruleId: string) => {
  const index = CHECK_ORDER.indexOf(ruleId);
  return index === -1 ? CHECK_ORDER.length : index;
};

const passedLabel = (rule: Rule) => (rule as ScannerRule).passedLabel ?? rule.description;

// Privacy rule descriptions describe the problem ("The app collects personal data but…"),
// so they get a short neutral name when listed as a check.
const PRIVACY_CHECK_NAMES: Record<string, string> = {
  PRIV_NO_PRIVACY_POLICY: "Privacy policy",
  PRIV_TRACKER_BEFORE_CONSENT: "Trackers before consent",
  PRIV_PII_TO_THIRD_PARTY: "Personal data sent to third parties",
  PRIV_NO_ACCOUNT_DELETION: "Account deletion",
  PRIV_NO_DATA_EXPORT: "Data export",
  PRIV_PII_IN_LOGS: "Personal data in logs",
};

/** A short name for a check, e.g. "Stripe webhook signature verification" or "Privacy policy". */
export const checkName = (rule: Rule) => PRIVACY_CHECK_NAMES[rule.id] ?? rule.description;

const notChecked = (result: ScanResult, check: Rule) => result.notChecked?.find((n) => n.check === check);

const notCheckedLabel = (kind: "no-js" | "not-applicable") => (kind === "no-js" ? "Not checked" : "Not applicable");

/**
 * "– Not checked: <name> (<reason>)" for each check that didn't run, then
 * "– Not applicable: <name> (<reason>)" for each that had nothing to inspect.
 * Security before privacy, in report order.
 */
export function notCheckedLines(result: ScanResult): string[] {
  return [...(result.notChecked ?? [])]
    .sort(
      (a, b) =>
        Number(a.kind === "not-applicable") - Number(b.kind === "not-applicable") ||
        Number(a.check.category === "privacy") - Number(b.check.category === "privacy") ||
        checkRank(a.check.id) - checkRank(b.check.id),
    )
    .map(({ check, reason, kind }) => `– ${notCheckedLabel(kind)}: ${checkName(check)} (${reason})`);
}

/** Orders findings by rule, then by file and line within each rule. */
export function sortForReport(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      checkRank(a.ruleId) - checkRank(b.ruleId) ||
      (a.file ?? "").localeCompare(b.file ?? "") ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}

/** Every finding in report order: security worst severity first (then sortForReport), then privacy (sortPrivacy). */
export function reportOrder(findings: Finding[]): Finding[] {
  const security = securityOnly(findings);
  return [
    ...[...SECTION_ORDER, "info" as const].flatMap((s) => sortForReport(security.filter((f) => f.severity === s))),
    ...sortPrivacy(privacyOnly(findings)),
  ];
}

function severityColor(c: Colors, severity: Severity): (text: string) => string {
  if (severity === "critical") return c.red;
  if (severity === "high") return c.yellow;
  if (severity === "medium") return c.cyan;
  if (severity === "low") return c.blueBright; // plain blue is hard to read on dark terminals
  return c.magenta;
}

function gradeColor(c: Colors, grade: Grade): (text: string) => string {
  if (grade === "A" || grade === "B") return c.green;
  if (grade === "C") return c.yellow;
  return c.red;
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

function divider(c: Colors, color: (text: string) => string, title: string): string {
  const head = `── ${title} `;
  return color(c.bold(head + "─".repeat(Math.max(0, WIDTH - head.length))));
}

const location = (f: { file?: string; line?: number }) => (f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : undefined);

/** "    → Fix: text", wrapped with the text lined up, the arrow and label in the severity color. */
function fixLines(c: Colors, severity: Severity, label: string, text: string): string[] {
  const head = `    → ${label}: `;
  const lines = wrap(text, head, " ".repeat(head.length));
  lines[0] = `    ${severityColor(c, severity)(`→ ${label}:`)}${lines[0].slice(head.length - 1)}`;
  return lines;
}

function renderFinding(c: Colors, finding: Finding): string[] {
  const lines = [`  ${c.bold(finding.title)}`];
  const where = location(finding);
  if (where) lines.push(`  ${c.dim(where)}`);
  const also = (finding.alsoAt ?? []).map(location).filter((l): l is string => l !== undefined);
  if (also.length > 0) lines.push(...wrap(`also at: ${also.join(", ")}`, "  ", "  ").map((l) => c.dim(l)));
  lines.push(...wrap(finding.message, "    ", "    "));
  if (FIX_SEVERITIES.includes(finding.severity)) {
    // Every distinct fix in a same-secret group, one per line.
    if (finding.fix) lines.push(...fixLines(c, finding.severity, "Fix", finding.fix));
    for (const { fix } of finding.alsoFixes ?? []) if (fix) lines.push(...fixLines(c, finding.severity, "Also", fix));
  }
  return lines;
}

function renderPrivacyFinding(c: Colors, finding: Finding): string[] {
  const lowConfidence = finding.confidence === "low" ? ` ${c.dim("(low confidence)")}` : "";
  const lines = [`  ${c.bold(finding.title)}${lowConfidence}`];
  const where = location(finding);
  if (where) lines.push(`  ${c.dim(where)}`);
  lines.push(...wrap(finding.message, "    ", "    "));
  if (finding.lawRefs?.length) lines.push(...wrap(finding.lawRefs.map(shortLawRef).join(" · "), "    ", "    ").map((l) => c.dim(l)));
  if (PRIVACY_FIX_SEVERITIES.includes(finding.severity) && finding.fix) lines.push(...fixLines(c, "info", "Fix", finding.fix));
  return lines;
}

/** Every fixId a finding stands for, including the ones grouped into it, at its severity. */
const fixIdsOf = (findings: Finding[]) =>
  findings.flatMap((f) => [f, ...(f.alsoFixes ?? []).map((a) => ({ fixId: a.fixId, severity: f.severity }))]);

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

export interface Summary {
  /** Security score, grade and counts (same as security.*, kept for older --json users). */
  score: number;
  grade: Grade;
  counts: Record<Severity, number>;
  security: { score: number; grade: Grade; counts: Record<Severity, number> };
  /** Privacy findings never change the score. */
  privacy: { count: number; bySeverity: Record<Severity, number> };
  filesChecked: number;
  ignored: number;
  fixLink: string | null;
}

/** Score, grade (security only), privacy counts and the fix link, for the findings that weren't ignored. */
export function summarize(result: ScanResult, siteUrl = SITE_URL): Summary {
  const security = securityOnly(result.findings);
  const privacy = privacyOnly(result.findings);
  const score = scoreFor(security);
  const counts = countBySeverity(security);
  return {
    score,
    grade: gradeFor(score),
    counts,
    security: { score, grade: gradeFor(score), counts },
    privacy: { count: privacy.length, bySeverity: countBySeverity(privacy) },
    filesChecked: result.filesChecked,
    ignored: result.ignored.length,
    fixLink: buildFixLink(fixIdsOf(reportOrder(result.findings)), siteUrl) ?? null,
  };
}

/** The human-readable report, ending in a newline. */
export function renderReport(result: ScanResult, { colors: c, version, verbose = false, siteUrl = SITE_URL, telemetry }: ReportOptions): string {
  const out: string[] = [];
  const summary = summarize(result, siteUrl);
  const seconds = Math.max(result.durationMs / 1000, 0.1).toFixed(1);

  // No folder name, so a screenshot never shows a client's project name.
  out.push(`${c.bold("Leakproof")} v${version} · ${plural(result.filesChecked, "file")} checked · ${seconds}s`);
  out.push("");

  const counted = SECTION_ORDER.filter((s) => summary.counts[s] > 0).map((s) => severityColor(c, s)(`${summary.counts[s]} ${s}`));
  const scoreLine = [
    gradeColor(c, summary.grade)(c.bold(`Security ${summary.score}/100 · Grade ${summary.grade}`)),
    counted.length > 0 ? counted.join(", ") : c.green("no leaks"),
    ...(summary.ignored > 0 ? [c.dim(`${summary.ignored} ignored`)] : []),
  ];
  out.push(scoreLine.join(" · "));
  // Only when privacy rules are in the rule set (custom rule sets in tests may have none).
  const privacyChecks = result.checks.filter((check) => check.category === "privacy");
  if (privacyChecks.length > 0) {
    const gaps = summary.privacy.count;
    const inspected = privacyChecks.some((check) => !notChecked(result, check));
    const ran = privacyChecks.some((check) => notChecked(result, check)?.kind !== "no-js");
    out.push(
      gaps > 0
        ? `Privacy: ${plural(gaps, "possible gap")}`
        : inspected
          ? c.dim("Privacy: no possible gaps found")
          : ran
            ? c.dim("Privacy: not applicable (no personal data collection, trackers, sign-up or logs found)")
            : c.dim(`Privacy: not checked (${notChecked(result, privacyChecks[0])?.reason})`),
    );
  }
  out.push("");

  if (verbose) {
    out.push("Checks run:");
    for (const check of result.checks) {
      const skipped = result.skipped.some((s) => s.check === check);
      const notRun = notChecked(result, check);
      const mark = notRun ? c.dim("–") : skipped ? c.yellow("⚠") : c.green("✓");
      const note = notRun
        ? c.dim(`: ${notCheckedLabel(notRun.kind).toLowerCase()} (${notRun.reason})`)
        : skipped
          ? c.yellow(": skipped")
          : "";
      out.push(`  ${mark} ${checkName(check)} ${c.dim(`(${check.id})`)}${note}`);
    }
    out.push("");
  }

  // Clean result: show what passed. Skipped checks never count as passed.
  if (!result.findings.some(isLeak)) {
    const passed = [...result.checks]
      // Privacy rules have their own section and never get a ✓.
      .filter((check) => check.category !== "privacy")
      .sort((a, b) => checkRank(a.id) - checkRank(b.id))
      .filter((check) => !result.skipped.some((s) => s.check === check))
      // A check that didn't run (e.g. JS-only on a Python project) never gets a ✓.
      .filter((check) => !notChecked(result, check))
      // A check that couldn't verify (info finding) hasn't passed either.
      .filter((check) => !result.findings.some((f) => f.ruleId === check.id && f.severity === "info"));
    if (passed.length > 0) {
      for (const check of passed) out.push(`  ${c.green("✓")} ${passedLabel(check)}`);
      out.push("");
    }
  }

  // Checks that didn't run are always listed, leaks or not, so nothing looks checked that wasn't.
  const notRun = notCheckedLines(result);
  if (notRun.length > 0) {
    for (const line of notRun) out.push(`  ${c.dim(line)}`);
    out.push("");
  }

  const security = securityOnly(result.findings);
  for (const severity of SECTION_ORDER) {
    const group = sortForReport(security.filter((f) => f.severity === severity));
    if (group.length === 0) continue;
    out.push(divider(c, severityColor(c, severity), `${severity.toUpperCase()} (${group.length})`), "");
    for (const finding of group) out.push(...renderFinding(c, finding), "");
  }

  // info findings: things LeakProof couldn't check (e.g. SEC_SUPABASE_RLS_UNVERIFIED).
  const unverified = sortForReport(security.filter((f) => f.severity === "info"));
  if (unverified.length > 0) {
    out.push(divider(c, severityColor(c, "info"), `COULDN'T VERIFY (${unverified.length})`), "");
    for (const finding of unverified) out.push(...renderFinding(c, finding), "");
  }

  // Privacy: possible gaps, after every security finding. Never scored.
  const privacy = sortPrivacy(privacyOnly(result.findings));
  if (privacy.length > 0) {
    out.push(divider(c, c.magenta, `PRIVACY GAPS (${privacy.length})`), "");
    for (const finding of privacy) out.push(...renderPrivacyFinding(c, finding), "");
  }

  if (result.skipped.length > 0) {
    for (const { check, reason } of result.skipped) {
      out.push(...wrap(`${check.description} skipped: ${reason}`, "⚠ ", "  ").map((l) => c.yellow(l)));
    }
    out.push("");
  }

  if (summary.fixLink) {
    // The link gets a line of its own so it stays whole and clickable.
    out.push(c.bold("Copy-paste fixes for any AI platform you use:"), summary.fixLink, "");
  }
  if (telemetry === "on") {
    out.push(c.dim("Scanned locally. Your code never leaves your machine; anonymous usage counts are on (`leakproof telemetry off`)."));
  } else {
    out.push(c.dim("Scanned locally. Nothing was sent anywhere."));
    if (telemetry === "off") out.push(c.dim(TELEMETRY_HINT));
  }
  return out.join("\n") + "\n";
}

/**
 * A contract Finding plus the optional one-line fix and same-secret grouping
 * (alsoAt, alsoFixes), with no other fields: secretIds never leave memory.
 */
function jsonFinding(f: Finding): Finding {
  const { ruleId, fixId, severity, category, title, message, file, line, lawRefs, confidence, fix, alsoAt, alsoFixes } = f;
  return { ruleId, fixId, severity, category, title, message, file, line, lawRefs, confidence, fix, alsoAt, alsoFixes };
}

/** Machine-readable output for AI agents and the GitHub Action: no colors, no footer. */
export function renderJson(result: ScanResult, siteUrl = SITE_URL): string {
  return (
    JSON.stringify(
      {
        summary: summarize(result, siteUrl),
        findings: reportOrder(result.findings).map(jsonFinding),
        skipped: result.skipped.map(({ check, reason }) => ({ ruleId: check.id, name: check.description, reason })),
        // Checks that didn't run (JS-only checks on a project with no JS/TS code) or had nothing to
        // inspect (reason "not-applicable", with the detail). Not passed, not failed.
        notChecked: (result.notChecked ?? []).map(({ check, reason, kind }) =>
          kind === "no-js"
            ? { ruleId: check.id, name: checkName(check), reason }
            : { ruleId: check.id, name: checkName(check), reason: "not-applicable", detail: reason },
        ),
      },
      null,
      2,
    ) + "\n"
  );
}

/** Severities --fail-on accepts. info ("couldn't verify") never fails a scan. */
export const FAIL_ON_LEVELS = ["critical", "high", "medium", "low"] as const;
export type FailOn = (typeof FAIL_ON_LEVELS)[number];

/** Severities --fail-on-privacy accepts (the privacy table has no critical). */
export const FAIL_ON_PRIVACY_LEVELS = ["high", "medium", "low"] as const;
export type FailOnPrivacy = (typeof FAIL_ON_PRIVACY_LEVELS)[number];

const atOrWorse = (findings: Finding[], level: FailOn) =>
  findings.some((f) => {
    const rank = FAIL_ON_LEVELS.indexOf(f.severity as FailOn);
    return rank !== -1 && rank <= FAIL_ON_LEVELS.indexOf(level);
  });

/**
 * 1 when any SECURITY finding is at `failOn` or worse, else 0. The default,
 * medium, means leaks fail and LOW/info don't. Privacy findings never fail
 * the scan unless `failOnPrivacy` is set (--fail-on-privacy). Ignored findings
 * never count. (2 is decided by the CLI.)
 */
export function exitCodeFor(result: ScanResult, failOn: FailOn = "medium", failOnPrivacy?: FailOnPrivacy): 0 | 1 {
  if (atOrWorse(securityOnly(result.findings), failOn)) return 1;
  if (failOnPrivacy && atOrWorse(privacyOnly(result.findings), failOnPrivacy)) return 1;
  return 0;
}

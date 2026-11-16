import { SITE_URL } from "./config.js";
import type { Finding, Severity } from "./contract.js";

export type Grade = "A" | "B" | "C" | "D" | "F";

/** Worst first. */
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Points taken off the score per finding. info findings don't count. */
export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };

/** Any critical caps the score here (grade F); else any high caps it at 59 (grade D). */
export const CRITICAL_CAP = 39;
export const HIGH_CAP = 59;

/**
 * 100 − (25×critical + 10×high + 4×medium + 1×low), never below 0, capped at
 * 39 with any critical and at 59 with any high. info findings don't count.
 */
export function scoreFor(findings: Pick<Finding, "severity">[]): number {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  let score = Math.max(0, 100 - penalty);
  if (findings.some((f) => f.severity === "critical")) score = Math.min(score, CRITICAL_CAP);
  else if (findings.some((f) => f.severity === "high")) score = Math.min(score, HIGH_CAP);
  return score;
}

/** A 90+, B 75–89, C 60–74, D 40–59, F below 40. */
export function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function countBySeverity(findings: Pick<Finding, "severity">[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

// What a fix ID looks like. Anything else (a path, a value) never goes in the link.
const FIX_ID = /^[A-Z][A-Z0-9_]+$/;

/**
 * The one fix link: every unique fixId, worst severity first, ties in the
 * order given. Only fix IDs, never code, paths or values. Undefined when
 * there is nothing to fix. The IDs go after "#", which browsers never send
 * to a server (CONTRACT.md section 4).
 */
export function buildFixLink(findings: Pick<Finding, "fixId" | "severity">[], siteUrl = SITE_URL): string | undefined {
  const worst = new Map<string, number>(); // fixId -> severity rank
  const firstSeen = new Map<string, number>();
  findings.forEach((f, index) => {
    if (!FIX_ID.test(f.fixId)) return;
    const rank = SEVERITY_ORDER.indexOf(f.severity);
    if (!worst.has(f.fixId) || rank < worst.get(f.fixId)!) worst.set(f.fixId, rank);
    if (!firstSeen.has(f.fixId)) firstSeen.set(f.fixId, index);
  });
  if (worst.size === 0) return undefined;

  const ids = [...worst.keys()].sort((a, b) => worst.get(a)! - worst.get(b)! || firstSeen.get(a)! - firstSeen.get(b)!);
  return `${siteUrl.replace(/\/+$/, "")}/fix#f=${ids.join(",")}`;
}

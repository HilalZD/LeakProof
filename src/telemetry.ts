import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { TELEMETRY_URL } from "./config.js";
import type { ScanResult } from "./scan.js";

/**
 * Opt-in anonymous usage counts. OFF unless the user runs
 * `leakproof telemetry on` or sets LEAKPROOF_TELEMETRY=1. The payload is
 * built from counts only: no paths, code, values, names, repo URLs or ids.
 * See docs/telemetry.md.
 */

export interface TelemetryPayload {
  /** CLI version, e.g. "0.2.0". */
  version: string;
  /** process.platform: "linux", "darwin", "win32"… */
  os: string;
  /** fixId → how many findings had it in this scan (security and privacy; ignored findings not counted). */
  fixIds: Record<string, number>;
  /** How many files were checked, as a bucket. */
  filesChecked: FilesBucket;
  /** Which stack was detected. Yes/no only. */
  stack: { vite: boolean; next: boolean; supabase: boolean };
}

export type FilesBucket = "0-100" | "100-1000" | "1000-10000" | "10000+";

export function filesBucket(n: number): FilesBucket {
  if (n < 100) return "0-100";
  if (n < 1000) return "100-1000";
  if (n < 10000) return "1000-10000";
  return "10000+";
}

export function buildPayload(result: ScanResult, version: string, os: string): TelemetryPayload {
  const fixIds: Record<string, number> = {};
  for (const f of result.findings) fixIds[f.fixId] = (fixIds[f.fixId] ?? 0) + 1;
  const stack = result.stack ?? { vite: false, next: false, supabase: false };
  return {
    version,
    os,
    fixIds,
    filesChecked: filesBucket(result.filesChecked),
    stack: { vite: stack.vite, next: stack.next, supabase: stack.supabase },
  };
}

// ── Where the choice is stored ─────────────────────────────────────────────

export const configPath = (home: string) => join(home, ".leakproof", "config.json");

interface Config {
  telemetry?: boolean;
}

function readConfig(home: string): Config {
  try {
    const parsed = JSON.parse(readFileSync(configPath(home), "utf8"));
    return parsed && typeof parsed === "object" ? (parsed as Config) : {};
  } catch {
    return {}; // missing or unreadable: telemetry stays off
  }
}

/** Saves the choice, keeping any other settings in the file. */
export function setTelemetry(home: string, on: boolean): void {
  const config = { ...readConfig(home), telemetry: on };
  mkdirSync(join(home, ".leakproof"), { recursive: true });
  writeFileSync(configPath(home), JSON.stringify(config, null, 2) + "\n");
}

// ── Is it on? ──────────────────────────────────────────────────────────────

const CI_VARS = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION"];

export function isCI(env: Record<string, string | undefined>): boolean {
  return CI_VARS.some((name) => {
    const value = env[name];
    return value !== undefined && value !== "" && value !== "0" && value.toLowerCase() !== "false";
  });
}

export type TelemetryState =
  | { on: true; reason: "env" | "config" }
  | { on: false; reason: "default" | "config" | "env" | "ci" };

/**
 * LEAKPROOF_TELEMETRY=1 turns it on (also in CI), =0 turns it off. Otherwise
 * CI is always off, and elsewhere it follows ~/.leakproof/config.json, which
 * is off unless the user ran `leakproof telemetry on`.
 */
export function telemetryState(env: Record<string, string | undefined>, home: string): TelemetryState {
  const flag = env.LEAKPROOF_TELEMETRY?.trim().toLowerCase();
  if (flag === "1" || flag === "true" || flag === "on") return { on: true, reason: "env" };
  if (flag === "0" || flag === "false" || flag === "off") return { on: false, reason: "env" };
  if (isCI(env)) return { on: false, reason: "ci" };
  const config = readConfig(home);
  if (config.telemetry === true) return { on: true, reason: "config" };
  return { on: false, reason: config.telemetry === false ? "config" : "default" };
}

// ── Sending ────────────────────────────────────────────────────────────────

export const TIMEOUT_MS = 1500;

export const isPlaceholder = (url: string) => !/^https:\/\//.test(url) || url.includes("PLACEHOLDER");

/**
 * Fire-and-forget: never throws, never prints, gives up after 1.5s. Sends
 * nothing at all while TELEMETRY_URL is still the placeholder. Returns the
 * request (or undefined) only so tests can wait for it; callers don't.
 */
export function sendTelemetry(
  payload: TelemetryPayload,
  { url = TELEMETRY_URL, fetchImpl = globalThis.fetch }: { url?: string; fetchImpl?: typeof fetch } = {},
): Promise<void> | undefined {
  if (isPlaceholder(url) || typeof fetchImpl !== "function") return undefined;
  try {
    return fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    }).then(
      () => undefined,
      () => undefined,
    );
  } catch {
    return undefined;
  }
}

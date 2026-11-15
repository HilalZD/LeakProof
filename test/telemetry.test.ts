import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pc from "picocolors";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { run, type CliIo } from "../src/cli.js";
import { TELEMETRY_URL } from "../src/config.js";
import { renderReport, TELEMETRY_HINT } from "../src/report.js";
import { detectStack, type ScanResult } from "../src/scan.js";
import {
  buildPayload,
  configPath,
  filesBucket,
  isCI,
  isPlaceholder,
  sendTelemetry,
  setTelemetry,
  telemetryState,
  TIMEOUT_MS,
} from "../src/telemetry.js";
import type { ScanFinding as Finding } from "../src/types.js";

const key = "sk_" + "live_" + "x".repeat(24);
const REAL_URL = "https://telemetry.example.test/v1";

let home: string;
let project: string;

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "leakproof-home-"));
  project = await mkdtemp(join(tmpdir(), "leakproof-tel-"));
  await mkdir(join(project, "src"), { recursive: true });
  await writeFile(join(project, "src", "app.ts"), `const k = "${key}";\n`);
  await writeFile(join(project, "package.json"), JSON.stringify({ name: "secret-client-project", dependencies: { vite: "1", "@supabase/supabase-js": "2" } }));
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true });
  await rm(project, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

async function cli(args: string[], extra: Partial<CliIo> = {}) {
  let stdout = "";
  let stderr = "";
  const code = await run(["node", "leakproof", ...args], {
    stdout: (t) => (stdout += t),
    stderr: (t) => (stderr += t),
    env: {},
    isTTY: false,
    home,
    ...extra,
  });
  return { code, stdout, stderr };
}

/** A fetch mock that records calls and never touches the network. */
function mockFetch() {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(null, { status: 204 });
  });
  return { fn: fn as unknown as typeof fetch, calls };
}

describe("telemetry state", () => {
  it("is off by default", () => {
    expect(telemetryState({}, home)).toEqual({ on: false, reason: "default" });
  });

  it("follows `leakproof telemetry on/off`", () => {
    setTelemetry(home, true);
    expect(telemetryState({}, home)).toEqual({ on: true, reason: "config" });
    setTelemetry(home, false);
    expect(telemetryState({}, home)).toEqual({ on: false, reason: "config" });
  });

  it("LEAKPROOF_TELEMETRY wins both ways", () => {
    expect(telemetryState({ LEAKPROOF_TELEMETRY: "1" }, home).on).toBe(true);
    setTelemetry(home, true);
    expect(telemetryState({ LEAKPROOF_TELEMETRY: "0" }, home)).toEqual({ on: false, reason: "env" });
  });

  it("is never on in CI unless the env var is set explicitly", () => {
    setTelemetry(home, true);
    expect(telemetryState({ CI: "true" }, home)).toEqual({ on: false, reason: "ci" });
    expect(telemetryState({ GITHUB_ACTIONS: "true" }, home).on).toBe(false);
    expect(telemetryState({ CI: "true", LEAKPROOF_TELEMETRY: "1" }, home)).toEqual({ on: true, reason: "env" });
    expect(isCI({ CI: "false" })).toBe(false);
    expect(isCI({ CI: "" })).toBe(false);
  });

  it("treats a broken config file as off", async () => {
    await mkdir(join(home, ".leakproof"), { recursive: true });
    await writeFile(configPath(home), "{not json");
    expect(telemetryState({}, home).on).toBe(false);
  });

  it("keeps other settings when saving", async () => {
    await mkdir(join(home, ".leakproof"), { recursive: true });
    await writeFile(configPath(home), JSON.stringify({ other: 1 }));
    setTelemetry(home, true);
    expect(JSON.parse(await readFile(configPath(home), "utf8"))).toEqual({ other: 1, telemetry: true });
  });
});

describe("payload", () => {
  const finding = (ruleId: string): Finding => ({
    ruleId,
    fixId: "SEC_SECRET_HARDCODED",
    severity: "critical",
    category: "security",
    title: "Secret in code",
    message: `Key ${key.slice(0, 8)}****xxxx in my-client-app`,
    file: "src/clients/acme/secret.ts",
    line: 3,
    confidence: "high",
    alsoAt: [{ file: "src/other.ts", line: 1 }],
  });
  const result: ScanResult = {
    projectPath: "C:/Users/someone/acme-project",
    checks: [],
    findings: [finding("leaked-keys"), finding("leaked-keys"), finding("api-auth")],
    ignored: [finding("rate-limit")],
    skipped: [],
    filesChecked: 250,
    durationMs: 10,
    stack: { vite: true, next: false, supabase: true },
  };

  it("holds only version, OS, rule counts, a files bucket and the stack", () => {
    expect(buildPayload(result, "0.2.0", "linux")).toEqual({
      version: "0.2.0",
      os: "linux",
      fixIds: { SEC_SECRET_HARDCODED: 3 },
      filesChecked: "100-1000",
      stack: { vite: true, next: false, supabase: true },
    });
  });

  it("contains no paths, code, values, names, repo URLs or ids", () => {
    const json = JSON.stringify(buildPayload(result, "0.2.0", "win32"));
    for (const forbidden of ["src/", "acme", "someone", "Users", "sk_live", "****", "Secret in code", "http", "leaked-keys", "line", "file\"", "id\"", "user", "repo", "path"]) {
      expect(json).not.toContain(forbidden);
    }
  });

  it("buckets file counts", () => {
    expect([0, 99, 100, 999, 1000, 9999, 10000].map(filesBucket)).toEqual([
      "0-100",
      "0-100",
      "100-1000",
      "100-1000",
      "1000-10000",
      "1000-10000",
      "10000+",
    ]);
  });

  it("detects the stack from package.json and config files", () => {
    expect(detectStack({ dependencies: { next: "16" } }, [])).toEqual({ vite: false, next: true, supabase: false });
    expect(detectStack(undefined, ["vite.config.ts", "supabase/config.toml"])).toEqual({ vite: true, next: false, supabase: true });
  });
});

describe("sending", () => {
  const payload = buildPayload(
    { projectPath: "", checks: [], findings: [], ignored: [], skipped: [], filesChecked: 1, durationMs: 1 },
    "0.2.0",
    "linux",
  );

  it("TELEMETRY_URL is still a placeholder, so nothing is ever sent", () => {
    expect(isPlaceholder(TELEMETRY_URL)).toBe(true);
    const { fn } = mockFetch();
    expect(sendTelemetry(payload, { fetchImpl: fn })).toBeUndefined();
    expect(fn).not.toHaveBeenCalled();
  });

  it("posts the payload as JSON with a 1.5s timeout when the URL is real", async () => {
    const { fn, calls } = mockFetch();
    await sendTelemetry(payload, { url: REAL_URL, fetchImpl: fn });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(REAL_URL);
    expect(calls[0].init.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init.body))).toEqual(payload);
    expect(calls[0].init.signal).toBeInstanceOf(AbortSignal);
    expect(TIMEOUT_MS).toBe(1500);
  });

  it("never throws or rejects when fetch fails", async () => {
    const rejecting = vi.fn(async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    const throwing = vi.fn(() => {
      throw new Error("sync boom");
    }) as unknown as typeof fetch;
    await expect(sendTelemetry(payload, { url: REAL_URL, fetchImpl: rejecting })).resolves.toBeUndefined();
    expect(sendTelemetry(payload, { url: REAL_URL, fetchImpl: throwing })).toBeUndefined();
  });
});

describe("CLI", () => {
  it("off by default: a scan makes no network call and the footer invites opting in", async () => {
    const { fn } = mockFetch();
    vi.stubGlobal("fetch", fn);
    const { code, stdout } = await cli([project], { fetch: fn, telemetryUrl: REAL_URL });
    expect(code).toBe(1);
    expect(fn).not.toHaveBeenCalled();
    expect(stdout.trimEnd().split("\n").slice(-2)).toEqual(["Scanned locally. Nothing was sent anywhere.", TELEMETRY_HINT]);
  });

  it("on: sends the counts once and never the key or project name", async () => {
    setTelemetry(home, true);
    const { fn, calls } = mockFetch();
    const { code, stdout } = await cli([project], { fetch: fn, telemetryUrl: REAL_URL });
    expect(code).toBe(1);
    expect(calls).toHaveLength(1);
    const body = String(calls[0].init.body);
    expect(JSON.parse(body)).toMatchObject({ fixIds: { SEC_SECRET_CLIENT_EXPOSED: 1 }, stack: { vite: true, next: false, supabase: true } });
    expect(body).not.toContain(key.slice(0, 8));
    expect(body).not.toContain("secret-client-project");
    expect(body).not.toContain(project.replace(/\\/g, "/").split("/").pop()!);
    expect(stdout).not.toContain(TELEMETRY_HINT);
    expect(stdout).not.toContain("Nothing was sent anywhere");
  });

  it("on, but TELEMETRY_URL is a placeholder: no network call", async () => {
    setTelemetry(home, true);
    const { fn } = mockFetch();
    vi.stubGlobal("fetch", fn);
    await cli([project], { fetch: fn });
    expect(fn).not.toHaveBeenCalled();
  });

  it("CI: no call and no invitation, even with the config on; the env var opts in", async () => {
    setTelemetry(home, true);
    const { fn, calls } = mockFetch();
    const ci = await cli([project], { env: { CI: "true" }, fetch: fn, telemetryUrl: REAL_URL });
    expect(fn).not.toHaveBeenCalled();
    expect(ci.stdout).not.toContain(TELEMETRY_HINT);
    await cli([project, "--format", "github"], { env: { CI: "true", LEAKPROOF_TELEMETRY: "1" }, fetch: fn, telemetryUrl: REAL_URL });
    expect(calls).toHaveLength(1);
  });

  it("a failing request doesn't change the output or exit code", async () => {
    setTelemetry(home, true);
    const failing = vi.fn(async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch;
    const { code, stderr } = await cli([project], { fetch: failing, telemetryUrl: REAL_URL });
    expect(code).toBe(1);
    expect(stderr).toBe("");
  });

  it("`telemetry on/off/status` saves and reports the setting", async () => {
    expect((await cli(["telemetry", "status"])).stdout).toContain("off (the default)");
    const on = await cli(["telemetry", "on"]);
    expect(on.code).toBe(0);
    expect(on.stdout).toContain("Anonymous usage counts are on");
    expect(JSON.parse(await readFile(configPath(home), "utf8"))).toEqual({ telemetry: true });
    const off = await cli(["telemetry", "off"]);
    expect(off.stdout).toContain("Anonymous usage counts are off");
    expect(JSON.parse(await readFile(configPath(home), "utf8"))).toEqual({ telemetry: false });
    expect((await cli(["telemetry", "on"], { env: { CI: "1" } })).stdout).toContain("overrides this setting");
    expect((await cli(["telemetry", "maybe"])).code).toBe(2);
  });
});

describe("report footer", () => {
  const empty: ScanResult = { projectPath: "", checks: [], findings: [], ignored: [], skipped: [], filesChecked: 1, durationMs: 1 };
  const render = (telemetry?: "on" | "off" | "hidden") => renderReport(empty, { colors: pc.createColors(false), version: "1", telemetry });

  it("adds the quiet line only when telemetry is off", () => {
    expect(render("off")).toContain(TELEMETRY_HINT);
    expect(render("hidden")).not.toContain(TELEMETRY_HINT);
    expect(render()).not.toContain(TELEMETRY_HINT);
    expect(render("on")).not.toContain(TELEMETRY_HINT);
    expect(render("on")).toContain("anonymous usage counts are on");
  });
});

import { appendFileSync, existsSync, statSync } from "node:fs";
import { homedir, platform } from "node:os";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { Argument, Command, CommanderError, Option } from "commander";
import pc from "picocolors";
import { renderGithub, renderMarkdownSummary } from "./github.js";
import { exitCodeFor, FAIL_ON_LEVELS, FAIL_ON_PRIVACY_LEVELS, renderJson, renderReport, renderShortSummary, type FailOn, type FailOnPrivacy } from "./report.js";
import { runScan } from "./scan.js";
import { buildPayload, configPath, isCI, sendTelemetry, setTelemetry, telemetryState } from "./telemetry.js";
import type { Rule } from "./types.js";

// Read the version from package.json so it only lives in one place.
const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  /** Whether stdout is a terminal. */
  isTTY: boolean;
  /** Override the rules to run (tests only). */
  checks?: Rule[];
  /** Appends text to a file, for $GITHUB_STEP_SUMMARY. Defaults to fs.appendFileSync (tests pass a fake). */
  appendFile?: (path: string, text: string) => void;
  /** Home folder for ~/.leakproof/config.json. Defaults to os.homedir() (tests pass a temp folder). */
  home?: string;
  /** fetch for opt-in usage counts (tests pass a mock). */
  fetch?: typeof fetch;
  /** Overrides TELEMETRY_URL (tests only). */
  telemetryUrl?: string;
}

/**
 * Colors only for a real terminal, and never with NO_COLOR. We decide this
 * ourselves because picocolors turns colors on for every Windows process,
 * even when output is piped to a file.
 */
export function useColor({ env, isTTY }: Pick<CliIo, "env" | "isTTY">): boolean {
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR && env.FORCE_COLOR !== "0") return true;
  return isTTY;
}

export const FORMATS = ["text", "json", "github"] as const;
type Format = (typeof FORMATS)[number];

interface ScanOptions {
  json?: boolean;
  verbose?: boolean;
  details?: boolean;
  format?: Format;
  failOn: FailOn;
  failOnPrivacy?: FailOnPrivacy;
}

function render(result: Awaited<ReturnType<typeof runScan>>, format: Format, options: ScanOptions, io: CliIo, c: ReturnType<typeof pc.createColors>): string {
  if (format === "json") return renderJson(result);
  if (format === "github") {
    const summaryFile = io.env.GITHUB_STEP_SUMMARY;
    if (summaryFile) {
      try {
        (io.appendFile ?? appendFileSync)(summaryFile, renderMarkdownSummary(result, version) + "\n");
      } catch (error) {
        io.stderr(`LeakProof: couldn't write the job summary: ${error instanceof Error ? error.message : String(error)}\n`);
      }
    }
    return renderGithub(result);
  }
  const state = telemetryState(io.env, io.home ?? homedir());
  // No invitation in CI: there, only LEAKPROOF_TELEMETRY=1 turns it on.
  const telemetry = state.on ? "on" : isCI(io.env) ? "hidden" : "off";
  // Default: the short summary. --details (or --verbose, which adds to the full report) prints the full report.
  if (!options.details && !options.verbose) return renderShortSummary(result, { colors: c, telemetry });
  return renderReport(result, { colors: c, version, verbose: options.verbose, telemetry });
}

async function scan(path: string, options: ScanOptions, io: CliIo): Promise<number> {
  // --format wins over --json; json and github output never have colors.
  const format: Format = options.format ?? (options.json ? "json" : "text");
  const c = pc.createColors(format === "text" && useColor(io));
  const projectPath = resolve(path);

  if (!existsSync(projectPath) || !statSync(projectPath).isDirectory()) {
    io.stderr(c.red(`LeakProof: folder not found: ${projectPath}`) + "\n");
    return 2;
  }

  try {
    const result = await runScan(projectPath, io.checks);
    io.stdout(render(result, format, options, io, c));
    // After the report is printed. Fire-and-forget: never awaited, never fails the scan.
    if (telemetryState(io.env, io.home ?? homedir()).on) {
      void sendTelemetry(buildPayload(result, version, platform()), { url: io.telemetryUrl, fetchImpl: io.fetch });
    }
    return exitCodeFor(result, options.failOn, options.failOnPrivacy);
  } catch (error) {
    io.stderr(c.red(`LeakProof failed: ${error instanceof Error ? error.message : String(error)}`) + "\n");
    return 2;
  }
}

const STATUS_REASON = {
  env: "set by LEAKPROOF_TELEMETRY",
  config: "set by `leakproof telemetry`",
  default: "the default",
  ci: "always off in CI unless LEAKPROOF_TELEMETRY=1",
} as const;

function telemetryCommand(setting: "on" | "off" | "status", io: CliIo): number {
  const home = io.home ?? homedir();
  try {
    if (setting !== "status") setTelemetry(home, setting === "on");
  } catch (error) {
    io.stderr(`LeakProof: couldn't save ${configPath(home)}: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  const state = telemetryState(io.env, home);
  const lines = [`Anonymous usage counts are ${state.on ? "on" : "off"} (${STATUS_REASON[state.reason]}).`];
  if (setting !== "status") lines.push(`Saved in ${configPath(home)}.`);
  if (setting === "on" && !state.on) lines.push("LEAKPROOF_TELEMETRY or CI overrides this setting right now.");
  if (setting === "off" && state.on) lines.push("LEAKPROOF_TELEMETRY=1 overrides this setting right now.");
  lines.push(
    state.on
      ? "Shared: CLI version, OS, which fix IDs came up and how often, a files-checked range, and vite/next/supabase yes/no. Never code, paths, values or names."
      : "Nothing is shared. `leakproof telemetry on` shares anonymous counts only (never code).",
    "Details: https://github.com/HilalZD/LeakProof/blob/main/docs/telemetry.md",
  );
  io.stdout(lines.join("\n") + "\n");
  return 0;
}

/** Runs the CLI and returns the exit code: 0 clean, 1 findings, 2 the scanner failed or bad usage. */
export async function run(argv: string[], io: CliIo): Promise<number> {
  let exitCode = 0;
  const program = new Command();

  program
    .name("leakproof")
    .description("LeakProof: find leaked secrets and risky config in apps built with AI tools.")
    .version(version)
    .exitOverride()
    .configureOutput({ writeOut: io.stdout, writeErr: io.stderr });

  program
    .command("scan", { isDefault: true })
    .description("Scan a project folder for leaks (the default: `leakproof [path]`)")
    .argument("[path]", "folder to scan", ".")
    .option("--json", "print the results as JSON")
    .option("--details", "Show every problem with its file, line and fix")
    .option("--verbose", "also list every check that ran")
    .addOption(new Option("--format <format>", "output format").choices(FORMATS))
    .addOption(
      new Option("--fail-on <severity>", "exit 1 only for security findings at this severity or worse").choices(FAIL_ON_LEVELS).default("medium"),
    )
    .addOption(
      new Option("--fail-on-privacy <severity>", "also exit 1 for privacy gaps at this severity or worse (off by default)").choices(FAIL_ON_PRIVACY_LEVELS),
    )
    .action(async (path: string, options: ScanOptions) => {
      exitCode = await scan(path, options, io);
    });

  program
    .command("telemetry")
    .description("Turn anonymous usage counts on or off (off by default)")
    .addArgument(new Argument("<setting>", "on, off or status").choices(["on", "off", "status"]))
    .action((setting: "on" | "off" | "status") => {
      exitCode = telemetryCommand(setting, io);
    });

  try {
    await program.parseAsync(argv);
  } catch (error) {
    // --help and --version end with exit code 0; every other commander error is bad usage.
    if (error instanceof CommanderError) return error.exitCode === 0 ? 0 : 2;
    throw error;
  }
  return exitCode;
}

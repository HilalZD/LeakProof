import { existsSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { Command, CommanderError } from "commander";
import pc from "picocolors";
import { exitCodeFor, renderJson, renderReport } from "./report.js";
import { runScan } from "./scan.js";
import type { Check } from "./types.js";

// Read the version from package.json so it only lives in one place.
const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  /** Whether stdout is a terminal. */
  isTTY: boolean;
  /** Override the checks to run (tests only). */
  checks?: Check[];
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

interface ScanOptions {
  json?: boolean;
  verbose?: boolean;
}

async function scan(path: string, options: ScanOptions, io: CliIo): Promise<number> {
  const c = pc.createColors(useColor(io));
  const projectPath = resolve(path);

  if (!existsSync(projectPath) || !statSync(projectPath).isDirectory()) {
    io.stderr(c.red(`LeakProof: folder not found: ${projectPath}`) + "\n");
    return 2;
  }

  try {
    const result = await runScan(projectPath, io.checks);
    io.stdout(options.json ? renderJson(result, version) : renderReport(result, { colors: c, version, verbose: options.verbose }));
    return exitCodeFor(result);
  } catch (error) {
    io.stderr(c.red(`LeakProof failed: ${error instanceof Error ? error.message : String(error)}`) + "\n");
    return 2;
  }
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
    .command("scan")
    .description("Scan a project folder for leaks")
    .argument("[path]", "folder to scan", ".")
    .option("--json", "print the results as JSON")
    .option("--verbose", "also list every check that ran")
    .action(async (path: string, options: ScanOptions) => {
      exitCode = await scan(path, options, io);
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

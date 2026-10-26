#!/usr/bin/env node
import { existsSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { runScan } from "./scan.js";
import type { Severity } from "./types.js";

// Read the version from package.json so it only lives in one place.
const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

function severityLabel(severity: Severity): string {
  const label = severity.toUpperCase();
  if (severity === "critical") return pc.bgRed(pc.white(pc.bold(` ${label} `)));
  if (severity === "high") return pc.red(pc.bold(label));
  if (severity === "medium") return pc.yellow(label);
  return pc.dim(label);
}

const program = new Command();

program
  .name("leakproof")
  .description("LeakProof: find leaked secrets and risky config in apps built with AI tools.")
  .version(version);

program
  .command("scan")
  .description("Scan a project folder for leaks")
  .argument("[path]", "folder to scan", ".")
  .action(async (path: string) => {
    const projectPath = resolve(path);

    if (!existsSync(projectPath) || !statSync(projectPath).isDirectory()) {
      console.error(pc.red(`Error: folder not found: ${projectPath}`));
      process.exitCode = 1;
      return;
    }

    console.log(pc.bold(`Scanning ${projectPath}`));
    const result = await runScan(projectPath);

    console.log();
    console.log(pc.dim("Checks run:"));
    for (const check of result.checks) {
      const skip = result.skipped.find((s) => s.check === check);
      if (skip) {
        console.log(`  ${pc.yellow("⚠")} ${check.name} ${pc.dim(`(${check.id})`)}: ${pc.yellow(`skipped. ${skip.reason}`)}`);
      } else {
        console.log(`  ${pc.green("✓")} ${check.name} ${pc.dim(`(${check.id})`)}`);
      }
    }

    for (const finding of result.findings) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      console.log();
      console.log(`${severityLabel(finding.severity)} ${pc.bold(location)}`);
      console.log(`  ${finding.message}`);
      console.log(`  ${pc.cyan("Fix:")} ${finding.fix}`);
    }

    console.log();
    const count = result.findings.length;
    if (count === 0) {
      console.log(pc.green("0 issues found"));
    } else {
      console.log(pc.red(`${count} issue${count === 1 ? "" : "s"} found`));
      process.exitCode = 1;
    }
  });

await program.parseAsync();

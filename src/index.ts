#!/usr/bin/env node
import { run } from "./cli.js";

try {
  process.exitCode = await run(process.argv, {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    env: process.env,
    isTTY: Boolean(process.stdout.isTTY),
  });
} catch (error) {
  console.error(`LeakProof failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}

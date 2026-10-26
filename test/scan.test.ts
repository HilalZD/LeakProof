import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runScan } from "../src/scan.js";

describe("runScan", () => {
  it("runs all checks on a folder without errors", async () => {
    const dir = await mkdtemp(join(tmpdir(), "leakproof-scan-"));
    try {
      const result = await runScan(dir);

      expect(result.checks.length).toBeGreaterThan(0);
      expect(result.findings).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

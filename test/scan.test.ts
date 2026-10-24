import { describe, expect, it } from "vitest";
import { runScan } from "../src/scan.js";

describe("runScan", () => {
  it("runs all checks on a folder without errors", async () => {
    const result = await runScan(process.cwd());

    expect(result.checks.length).toBeGreaterThan(0);
    expect(result.findings).toEqual([]);
  });
});

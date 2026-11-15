import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { dedupe, runScan } from "../src/scan.js";
import type { ScanFinding } from "../src/types.js";

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

describe("dedupe: one leak, one finding", () => {
  const finding = (ruleId: string, fixId: string, file: string, line: number): ScanFinding => ({
    ruleId,
    fixId,
    file,
    line,
    severity: "critical",
    category: "security",
    title: fixId,
    message: `${ruleId} at ${file}:${line}`,
    confidence: "high",
  });

  it("keeps the most specific fixId per file+line, and leaves other lines and same-rule pairs alone", () => {
    const findings = [
      finding("committed-env", "SEC_ENV_COMMITTED", ".env", 10),
      finding("client-exposed", "SEC_SECRET_CLIENT_EXPOSED", ".env", 10),
      finding("leaked-keys", "SEC_SECRET_HARDCODED", "src/a.tsx", 7),
      finding("client-exposed", "SEC_SECRET_CLIENT_EXPOSED", "src/a.tsx", 7),
      finding("service-role-client", "SEC_SUPABASE_SERVICE_ROLE_CLIENT", "src/a.tsx", 7),
      finding("committed-env", "SEC_ENV_COMMITTED", ".env", 8), // only one rule here
      finding("leaked-keys", "SEC_SECRET_HARDCODED", "src/b.ts", 1), // two keys on one line
      finding("leaked-keys", "SEC_SECRET_HARDCODED", "src/b.ts", 1),
    ];

    expect(dedupe(findings).map((f) => `${f.file}:${f.line} ${f.fixId}`)).toEqual([
      ".env:10 SEC_SECRET_CLIENT_EXPOSED",
      "src/a.tsx:7 SEC_SUPABASE_SERVICE_ROLE_CLIENT",
      ".env:8 SEC_ENV_COMMITTED",
      "src/b.ts:1 SEC_SECRET_HARDCODED",
      "src/b.ts:1 SEC_SECRET_HARDCODED",
    ]);
  });

  it("a service_role key in a component is reported once, under its own fixId", async () => {
    const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const key = `${b64({ alg: "HS256" })}.${b64({ role: "service_role" })}.${"s1g".repeat(10)}`;
    const dir = await mkdtemp(join(tmpdir(), "leakproof-dedupe-"));
    try {
      const files = {
        "package.json": JSON.stringify({ devDependencies: { vite: "8.0.0" } }),
        "src/components/AdminStats.tsx": `const admin = createClient(url, "${key}");\n`,
      };
      for (const [path, content] of Object.entries(files)) {
        await mkdir(dirname(join(dir, path)), { recursive: true });
        await writeFile(join(dir, path), content);
      }

      const { findings } = await runScan(dir);
      expect(findings.map((f) => `${f.file}:${f.line} ${f.fixId}`)).toEqual([
        "src/components/AdminStats.tsx:1 SEC_SUPABASE_SERVICE_ROLE_CLIENT",
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext } from "../src/lib/files.js";
import { serviceRoleClientRule } from "../src/rules/service-role-client.js";
import { runScan } from "../src/scan.js";

// Fake keys are assembled at runtime so no full key literal appears in this file.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (role: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.${"s1g".repeat(10)}`;
const VITE_PACKAGE = JSON.stringify({ devDependencies: { vite: "8.0.0" } });
const SECRET = () => "sb_" + "secret_" + "Q7xR2mK9pL4vN8wT1zC6bY3d";
const PUBLISHABLE = () => "sb_" + "publishable_" + "Q7xR2mK9pL4vN8wT1zC6bY3d";

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function run(files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-service-role-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return serviceRoleClientRule.run(await createProjectContext(dir));
}

describe("SEC_SUPABASE_SERVICE_ROLE_CLIENT", () => {
  it("flags a service_role key in frontend code, always critical", async () => {
    const key = jwt("service_role");
    const findings = await run({
      "package.json": VITE_PACKAGE,
      "src/components/AdminStats.tsx": `import { createClient } from "@supabase/supabase-js";\nconst admin = createClient(url, "${key}");\n`,
      "src/lib/admin.ts": `export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n`,
      "src/integrations/db.ts": `createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);\n`,
    });

    expect(findings.map((f) => `${f.file}:${f.line}`)).toEqual([
      "src/components/AdminStats.tsx:2",
      "src/integrations/db.ts:1",
      "src/lib/admin.ts:1",
    ]);
    for (const f of findings) {
      expect(f).toMatchObject({ ruleId: "service-role-client", fixId: "SEC_SUPABASE_SERVICE_ROLE_CLIENT", severity: "critical" });
    }
    expect(JSON.stringify(findings)).not.toContain(key);
  });

  it("treats Supabase's new secret key (sb_secret_) exactly like a service_role key", async () => {
    const key = SECRET();
    const findings = await run({
      "package.json": VITE_PACKAGE,
      "src/lib/supabase.ts": `createClient(url, "${key}");\n`,
      "src/lib/admin.ts": `createClient(url, process.env.SUPABASE_SECRET_KEY!);\n`,
      "src/integrations/db.ts": `createClient(url, import.meta.env.VITE_SUPABASE_SECRET_KEY);\n`,
      ".env.local": `NEXT_PUBLIC_DB_KEY=${key}\n`,
    });

    expect(findings.map((f) => `${f.file}:${f.line} ${f.confidence}`)).toEqual([
      ".env.local:1 high",
      "src/integrations/db.ts:1 high",
      "src/lib/admin.ts:1 medium",
      "src/lib/supabase.ts:1 high",
    ]);
    for (const f of findings) {
      expect(f).toMatchObject({ ruleId: "service-role-client", fixId: "SEC_SUPABASE_SERVICE_ROLE_CLIENT", severity: "critical" });
      expect(f.message).toContain("Supabase secret key");
    }
    expect(JSON.stringify(findings)).not.toContain(key);
  });

  it("flags a service_role key in a VITE_ / NEXT_PUBLIC_ .env variable with any name", async () => {
    const findings = await run({ "package.json": VITE_PACKAGE, ".env": `VITE_ADMIN=${jwt("service_role")}\nVITE_ANON=${jwt("anon")}\n` });
    expect(findings.map((f) => `${f.file}:${f.line}`)).toEqual([".env:1"]);
    expect(findings[0].fix).toContain("drop the VITE_ prefix");
  });

  it("full scan: an sb_secret_ key in a VITE_ variable is one SEC_SUPABASE_SERVICE_ROLE_CLIENT finding", async () => {
    await run({
      "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" }, devDependencies: { vite: "8.0.0" } }),
      ".gitignore": ".env.local\n",
      ".env.local": `VITE_SUPABASE_SECRET_KEY=${SECRET()}\n`,
      "src/lib/supabase.ts": `createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SECRET_KEY);\n`,
    });
    const secrets = (await runScan(dir!)).findings.filter((f) => f.fixId.startsWith("SEC_") && f.fixId !== "SEC_SUPABASE_RLS_UNVERIFIED");
    expect(secrets.map((f) => `${f.fixId} ${f.severity} ${f.file}:${f.line}`)).toEqual([
      "SEC_SUPABASE_SERVICE_ROLE_CLIENT critical .env.local:1",
    ]);
    expect(secrets[0].alsoAt).toEqual([{ file: "src/lib/supabase.ts", line: 1 }]);
  });

  it("never flags Supabase publishable keys (sb_publishable_), anywhere", async () => {
    const key = PUBLISHABLE();
    const findings = await run({
      "package.json": VITE_PACKAGE,
      ".env": `VITE_SUPABASE_PUBLISHABLE_KEY=${key}\nNEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${key}\nSUPABASE_PUBLISHABLE_KEY=${key}\n`,
      "src/lib/supabase.ts": `createClient(url, "${key}");\n`,
      "src/lib/env.ts": `createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY);\n`,
    });
    expect(findings).toEqual([]);
  });

  it("ignores the secret key in server-only code and example .env files", async () => {
    const findings = await run({
      "package.json": VITE_PACKAGE,
      "supabase/functions/admin/index.ts": `const k = Deno.env.get("SUPABASE_SECRET_KEY");\n`,
      "src/lib/admin.server.ts": `createClient(url, process.env.SUPABASE_SECRET_KEY!);\n`,
      ".env.example": `NEXT_PUBLIC_DB_KEY=${SECRET()}\n`,
    });
    expect(findings).toEqual([]);
  });

  it("ignores the service_role key in server-only code and the anon key in frontend code", async () => {
    const findings = await run({
      "package.json": VITE_PACKAGE,
      "src/integrations/supabase/client.server.ts": `createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nconst k = "${jwt("service_role")}";\n`,
      "src/routes/api/users.ts": `createClient(url, process.env["SUPABASE_SERVICE_ROLE_KEY"]);\n`,
      "src/lib/admin.ts": `"use server";\ncreateClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n`,
      "src/components/Login.tsx": `createClient(url, "${jwt("anon")}");\n`,
    });
    expect(findings).toEqual([]);
  });
});

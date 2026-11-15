import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext } from "../src/lib/files.js";
import { serviceRoleClientRule } from "../src/rules/service-role-client.js";

// Fake keys are assembled at runtime so no full key literal appears in this file.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (role: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.${"s1g".repeat(10)}`;
const VITE_PACKAGE = JSON.stringify({ devDependencies: { vite: "8.0.0" } });

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

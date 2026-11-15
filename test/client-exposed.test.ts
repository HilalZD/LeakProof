import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext } from "../src/lib/files.js";
import { clientExposedRule, scanEnvReads } from "../src/rules/client-exposed.js";
import { serviceRoleClientRule } from "../src/rules/service-role-client.js";
import { runScan } from "../src/scan.js";

// Fake keys are assembled at runtime so no full key literal appears in this
// file. Otherwise GitHub's secret scanner would block pushes.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (role: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.${"s1g".repeat(10)}`;
const OPENAI = "sk-" + "proj-" + "A1b2C3d4".repeat(6);
const STRIPE_LIVE = "sk_" + "live_" + "x".repeat(24);
const STRIPE_TEST = "sk_" + "test_" + "y".repeat(24);
const STRIPE_PUBLISHABLE = "pk_" + "live_" + "p".repeat(24);
const FIREBASE_KEY = "AIza" + "SyA1b2C3d4".repeat(3) + "x5";
const VITE_PACKAGE = JSON.stringify({ devDependencies: { vite: "8.0.0" } });

const onLine3 = (code: string) => `// first line\n// second line\n${code}\n`;

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function project(files: Record<string, string>): Promise<string> {
  dir = await mkdtemp(join(tmpdir(), "leakproof-client-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return dir;
}

const run = async (files: Record<string, string>) => clientExposedRule.run(await createProjectContext(await project(files)));
const where = (findings: { file?: string; line?: number; severity: string }[]) =>
  findings.map((f) => `${f.file}:${f.line} ${f.severity}`);

describe("SEC_SECRET_CLIENT_EXPOSED", () => {
  it("flags browser-reachable secrets: .env values, code reads and keys in frontend files", async () => {
    const findings = await run({
      "package.json": VITE_PACKAGE,
      ".env": `VITE_SUPABASE_URL=https://x.supabase.co\nVITE_OPENAI_API_KEY=${OPENAI}\nVITE_STRIPE_SECRET_KEY=${STRIPE_TEST}\n`,
      "src/components/Chat.tsx": onLine3("const key = import.meta.env.VITE_OPENAI_API_KEY;"),
      "src/lib/stripe.ts": onLine3(`const stripe = "${STRIPE_LIVE}";`), // src/lib is frontend in a Vite app
      "src/hooks/useCheckout.ts": onLine3(`const key = "${STRIPE_TEST}";`),
    });

    expect(where(findings)).toEqual([
      ".env:2 critical",
      ".env:3 high", // test key
      "src/components/Chat.tsx:3 critical", // value resolved from .env
      "src/hooks/useCheckout.ts:3 high",
      "src/lib/stripe.ts:3 critical",
    ]);
    expect(findings.every((f) => f.fixId === "SEC_SECRET_CLIENT_EXPOSED" && f.ruleId === "client-exposed")).toBe(true);
    expect(JSON.stringify(findings)).not.toContain(OPENAI);
  });

  it("ignores public-by-design keys, server-only files and example env files", async () => {
    const findings = await run({
      "package.json": VITE_PACKAGE,
      ".env": `VITE_STRIPE_PUBLISHABLE_KEY=${STRIPE_PUBLISHABLE}\nVITE_FIREBASE_API_KEY=${FIREBASE_KEY}\nSTRIPE_SECRET_KEY=${STRIPE_LIVE}\n`,
      ".env.example": `VITE_OPENAI_API_KEY=${OPENAI}\n`,
      "src/components/Pay.tsx": `const pk = "${STRIPE_PUBLISHABLE}";\nconst fb = { apiKey: import.meta.env.VITE_FIREBASE_API_KEY };\n`,
      "src/routes/api/charge.ts": `const stripe = "${STRIPE_LIVE}";\n`,
      "src/integrations/stripe.server.ts": `const stripe = "${STRIPE_LIVE}";\n`,
      "src/lib/actions.ts": `"use server";\nconst stripe = "${STRIPE_LIVE}";\n`,
      "src/lib/charge.ts": `import { createServerFn } from "@tanstack/react-start";\nconst key = "${STRIPE_LIVE}";\nexport const charge = createServerFn().handler(() => key);\n`,
      "src/lib/ai.test.ts": `const key = "${OPENAI}";\n`,
    });
    expect(findings).toEqual([]);
  });

  it("outside Vite apps, only the usual frontend folders count", async () => {
    const findings = await run({
      "package.json": JSON.stringify({ dependencies: { next: "15.0.0" } }),
      "lib/stripe.ts": `const stripe = "${STRIPE_LIVE}";\n`,
      "components/Pay.tsx": `const stripe = "${STRIPE_LIVE}";\n`,
      "app/api/charge/route.ts": `const stripe = "${STRIPE_LIVE}";\n`,
    });
    expect(where(findings)).toEqual(["components/Pay.tsx:1 critical"]);
  });

  it("flags NEXT_PUBLIC_ secrets in .env and in code", async () => {
    const findings = await run({
      ".env.local": `NEXT_PUBLIC_DB_PASSWORD=hunter2-real-password\n`,
      "lib/db.ts": `connect(process.env.NEXT_PUBLIC_DB_PASSWORD);\n`,
    });
    expect(where(findings)).toEqual([".env.local:1 critical", "lib/db.ts:1 critical"]);
  });
});

describe("the Supabase anon key decoy", () => {
  it("is never flagged, in .env, in code reads or hardcoded in a component", async () => {
    const anon = jwt("anon");
    const root = await project({
      "package.json": VITE_PACKAGE,
      ".env": `VITE_SUPABASE_ANON_KEY=${anon}\n`,
      "src/integrations/supabase/client.ts": `createClient(url, import.meta.env.VITE_SUPABASE_ANON_KEY);\n`,
      "src/components/Login.tsx": `const anon = "${anon}";\n`,
    });
    const ctx = await createProjectContext(root);
    expect(await clientExposedRule.run(ctx)).toEqual([]);
    expect(await serviceRoleClientRule.run(ctx)).toEqual([]);
    expect((await runScan(root)).findings).toEqual([]);
  });
});

// Moved from leaked-keys: these code reads were its Detection B.
describe("code reads of secret-named Vite variables", () => {
  const flagged = [
    "import.meta.env.VITE_STRIPE_SECRET_KEY",
    'import.meta.env["VITE_STRIPE_SECRET_KEY"]',
    "import.meta.env['VITE_SUPABASE_SERVICE_ROLE_KEY']",
    "import.meta.env.VITE_PRIVATE_TOKEN",
    "import.meta.env.VITE_DB_PASSWORD",
  ];
  for (const code of flagged) {
    it(`flags ${code}`, () => {
      const findings = scanEnvReads("src/lib/payments.ts", onLine3(`fetch(url, { key: ${code} });`));
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ severity: "high", line: 3 });
    });
  }

  const safe = [
    "import.meta.env.VITE_SUPABASE_URL",
    "import.meta.env['VITE_SUPABASE_PUBLISHABLE_KEY']",
    "import.meta.env.MODE",
    "readonly VITE_STRIPE_SECRET_KEY: string;", // type declaration in vite-env.d.ts
    "process.env.STRIPE_SECRET_KEY", // server-side, not shipped by Vite
  ];
  for (const code of safe) {
    it(`ignores ${code}`, () => {
      expect(scanEnvReads("a.ts", code)).toEqual([]);
    });
  }
});

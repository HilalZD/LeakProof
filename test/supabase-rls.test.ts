import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SITE_URL } from "../src/config.js";
import { createProjectContext } from "../src/lib/files.js";
import { splitStatements } from "../src/lib/sql.js";
import { supabaseRlsRule } from "../src/rules/supabase-rls.js";

const SUPABASE_PACKAGE = JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.50.0" } });

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function run(files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-rls-"));
  for (const [path, content] of Object.entries({ "package.json": SUPABASE_PACKAGE, ...files })) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return supabaseRlsRule.run(await createProjectContext(dir));
}

const brief = (fs: Awaited<ReturnType<typeof run>>) => fs.map((f) => `${f.fixId} ${f.severity} ${f.file}:${f.line}`);
const M = (name: string) => `supabase/migrations/${name}.sql`;

describe("splitStatements", () => {
  it("drops comments, keeps ; inside strings and $$ bodies, and tracks start lines", () => {
    const sql = `-- a comment; with semicolon\nCREATE TABLE a (id int); /* block;\ncomment */\nCREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; END $$ LANGUAGE plpgsql;\nSELECT ';';`;
    const statements = splitStatements(sql);
    expect(statements.map((s) => s.line)).toEqual([2, 4, 5]);
    expect(statements[1].text).toContain("PERFORM 1; END");
    expect(statements[2].text).toBe("SELECT ';'");
  });
});

describe("SEC_SUPABASE_RLS_DISABLED", () => {
  it("flags a public table without RLS and names its personal-data columns", async () => {
    const findings = await run({
      [M("20260101000000_invites")]: `-- invites\nCREATE TABLE public.invites (\n  id uuid PRIMARY KEY,\n  inviter_id uuid REFERENCES auth.users(id),\n  email text NOT NULL,\n  CONSTRAINT one UNIQUE (email)\n);`,
    });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_DISABLED critical ${M("20260101000000_invites")}:2`]);
    expect(findings[0].message).toContain("public.invites");
    expect(findings[0].message).toContain("inviter_id, email");
    expect(findings[0].fix).toContain("ALTER TABLE public.invites ENABLE ROW LEVEL SECURITY");
  });

  it("is not flagged once RLS is enabled, in the same or a later file, any case, quoted or schema-qualified", async () => {
    const findings = await run({
      [M("20260101000000_a")]: `create table "public"."Notes" (id int, "Email" text);\ncreate table items (id int);\nCREATE TABLE IF NOT EXISTS public.tags (id int);`,
      [M("20260102000000_b")]: `ALTER TABLE "public"."Notes" ENABLE ROW LEVEL SECURITY;\nalter table public.items enable row level security; ALTER TABLE ONLY tags ENABLE ROW LEVEL SECURITY;`,
    });
    expect(findings).toEqual([]);
  });

  it("treats quoted names as case-sensitive", async () => {
    const findings = await run({
      [M("20260101000000_a")]: `CREATE TABLE public."Notes" (id int);\nALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;`,
    });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_DISABLED critical ${M("20260101000000_a")}:1`]);
  });

  it("uses the latest state: a later DISABLE wins and is the reported line", async () => {
    const findings = await run({
      [M("20260101000000_a")]: `CREATE TABLE notes (id int, user_id uuid);\nALTER TABLE notes ENABLE ROW LEVEL SECURITY;`,
      [M("20260201000000_b")]: `\n\nALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;`,
    });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_DISABLED critical ${M("20260201000000_b")}:3`]);
  });

  it("applies migrations in timestamp order, not the order they are listed", async () => {
    const findings = await run({
      [M("20260201000000_enable")]: `ALTER TABLE notes ENABLE ROW LEVEL SECURITY;`,
      [M("20260101000000_create")]: `CREATE TABLE notes (id int);`,
    });
    expect(findings).toEqual([]);
  });

  it("reads supabase/schema.sql, ignores dropped and non-public tables", async () => {
    const findings = await run({
      "supabase/schema.sql": `CREATE TABLE public.old (id int);\nCREATE TABLE private.secrets (id int);`,
      [M("20260101000000_a")]: `DROP TABLE IF EXISTS public.old CASCADE;`,
    });
    expect(findings).toEqual([]);
  });
});

describe("SEC_SUPABASE_RLS_PERMISSIVE", () => {
  const base = `CREATE TABLE public.profiles (id uuid, email text, full_name text);\nALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n`;
  const posts = `CREATE TABLE public.posts (id uuid, title text, body text);\nALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;\n`;

  it("flags USING / WITH CHECK (true) on writes as critical", async () => {
    const findings = await run({
      [M("20260101000000_a")]:
        posts +
        `CREATE POLICY "anyone edits" ON public.posts FOR UPDATE USING (true);\n` +
        `CREATE POLICY anyone_adds ON posts FOR INSERT WITH CHECK ( TRUE );\n` +
        `CREATE POLICY "all" ON public.posts USING (true);\n` +
        `CREATE POLICY "del" ON public.posts FOR DELETE TO anon USING (true);`,
    });
    expect(brief(findings)).toEqual([3, 4, 5, 6].map((l) => `SEC_SUPABASE_RLS_PERMISSIVE critical ${M("20260101000000_a")}:${l}`));
  });

  it("flags public SELECT USING (true) on personal data as critical, and on public content as low", async () => {
    const findings = await run({
      [M("20260101000000_a")]:
        base + posts + `CREATE POLICY "read profiles" ON public.profiles FOR SELECT USING (true);\nCREATE POLICY "read posts" ON public.posts FOR SELECT TO anon, authenticated USING (true);`,
    });
    expect(brief(findings)).toEqual([
      `SEC_SUPABASE_RLS_PERMISSIVE critical ${M("20260101000000_a")}:5`,
      `SEC_SUPABASE_RLS_PERMISSIVE low ${M("20260101000000_a")}:6`,
    ]);
    expect(findings[0].message).toContain("email, full_name");
    expect(findings[1].message).toContain("Fine if it's meant to be public");
  });

  it("treats a profiles table with unknown columns as personal data (created outside the repo)", async () => {
    const findings = await run({ [M("20260101000000_a")]: `CREATE POLICY "p" ON public.profiles FOR SELECT USING (true);` });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_PERMISSIVE critical ${M("20260101000000_a")}:1`]);
  });

  it("flags 'every logged-in user' SELECT policies as high", async () => {
    const findings = await run({
      [M("20260101000000_a")]:
        base +
        `CREATE POLICY a ON public.profiles FOR SELECT TO authenticated USING (true);\n` +
        `CREATE POLICY b ON public.profiles FOR SELECT USING (auth.role() = 'authenticated');\n` +
        `CREATE POLICY c ON public.profiles FOR SELECT USING ((select auth.uid()) IS NOT NULL);`,
    });
    expect(findings.map((f) => f.severity)).toEqual(["high", "high", "high"]);
    expect(findings[0].message).toContain("every logged-in user can read everyone's rows");
  });

  it("never flags service_role-only policies or real ownership checks", async () => {
    const findings = await run({
      [M("20260101000000_a")]:
        base +
        `CREATE POLICY s ON public.profiles FOR ALL TO service_role USING (true) WITH CHECK (true);\n` +
        `CREATE POLICY s2 ON public.profiles FOR ALL USING (auth.role() = 'service_role');\n` +
        `CREATE POLICY own ON public.profiles FOR SELECT USING (auth.uid() = id);\n` +
        `CREATE POLICY r ON public.profiles AS RESTRICTIVE FOR SELECT USING (true);`,
    });
    expect(findings).toEqual([]);
  });

  it("forgets a policy after a later DROP POLICY", async () => {
    const findings = await run({
      [M("20260101000000_a")]: base + `CREATE POLICY "Open read" ON public.profiles FOR SELECT USING (true);`,
      [M("20260102000000_b")]: `DROP POLICY IF EXISTS "Open read" ON public.profiles;\nCREATE POLICY "Own" ON public.profiles FOR SELECT USING (auth.uid() = id);`,
    });
    expect(findings).toEqual([]);
  });

  it("follows ALTER POLICY changes", async () => {
    const findings = await run({
      [M("20260101000000_a")]: base + `CREATE POLICY own ON public.profiles FOR UPDATE USING (auth.uid() = id);`,
      [M("20260102000000_b")]: `ALTER POLICY own ON public.profiles USING (true);`,
    });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_PERMISSIVE critical ${M("20260102000000_b")}:1`]);
  });

  it("doesn't report policies on a table whose RLS is off (the RLS finding covers it)", async () => {
    const findings = await run({
      [M("20260101000000_a")]: `CREATE TABLE public.notes (id int, user_id uuid);\nCREATE POLICY p ON public.notes FOR SELECT USING (true);`,
    });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_DISABLED critical ${M("20260101000000_a")}:1`]);
  });
});

describe("SEC_SUPABASE_RLS_UNVERIFIED", () => {
  it("is an info finding when the app uses Supabase but has no SQL files", async () => {
    const findings = await run({ "src/client.ts": `import { createClient } from "@supabase/supabase-js";` });
    expect(brief(findings)).toEqual(["SEC_SUPABASE_RLS_UNVERIFIED info undefined:undefined"]);
    expect(findings[0].fix).toContain("supabase db pull");
  });

  it("says nothing for an app that doesn't use Supabase", async () => {
    dir = await mkdtemp(join(tmpdir(), "leakproof-rls-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ dependencies: { react: "19.0.0" } }));
    expect(await supabaseRlsRule.run(await createProjectContext(dir))).toEqual([]);
  });
});

describe("chunk 3D: public forms and wording", () => {
  const waitlist = `CREATE TABLE public.waitlist (id uuid, email text);\nALTER TABLE public.waitlist ENABLE ROW LEVEL SECURITY;\n`;
  const insertOpen = `CREATE POLICY "Anyone can join" ON public.waitlist FOR INSERT TO anon WITH CHECK (true);\n`;

  it("lowers INSERT WITH CHECK (true) to medium when nobody can read the rows back", async () => {
    const findings = await run({ [M("20260101000000_a")]: waitlist + insertOpen });
    expect(brief(findings)).toEqual([`SEC_SUPABASE_RLS_PERMISSIVE medium ${M("20260101000000_a")}:3`]);
    expect(findings[0].message).toContain("anyone add rows: fine for a public form, add a rate limit or captcha");
  });

  it("keeps it medium when the only read policy is an ownership check", async () => {
    const findings = await run({
      [M("20260101000000_a")]: waitlist + insertOpen + `CREATE POLICY own ON public.waitlist FOR SELECT USING (auth.uid() = id);`,
    });
    expect(findings.map((f) => f.severity)).toEqual(["medium"]);
  });

  it("keeps it critical when a SELECT policy lets anon or logged-in users read every row", async () => {
    for (const read of [
      `CREATE POLICY r ON public.waitlist FOR SELECT USING (true);`,
      `CREATE POLICY r ON public.waitlist FOR SELECT TO authenticated USING (true);`,
    ]) {
      const findings = await run({ [M("20260101000000_a")]: waitlist + insertOpen + read });
      expect(findings.find((f) => f.line === 3)?.severity).toBe("critical");
      await rm(dir!, { recursive: true, force: true });
    }
  });

  it("words a personal-data guess from the table name plainly", async () => {
    const findings = await run({ [M("20260101000000_a")]: `CREATE POLICY "p" ON public.profiles FOR SELECT USING (true);` });
    expect(findings[0].message).toBe(`Anyone can read every row in profiles (a table that usually holds personal data). Policy: "p".`);
  });

  it("adds the Security Advisor tip and the early-access link to Couldn't verify", async () => {
    const [f] = await run({ "src/client.ts": `import { createClient } from "@supabase/supabase-js";` });
    expect(f.message).toContain("Security Advisor");
    expect(f.message).toContain(
      `Leakproof Cloud will check your live database rules, with your permission. Join early access: ${SITE_URL}/fix#e8`,
    );
  });
});

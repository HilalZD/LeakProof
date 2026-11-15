import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext } from "../src/lib/files.js";
import { apiAuthRule, scanContent, scanServerFunctions } from "../src/rules/api-auth.js";
import { runScan } from "../src/scan.js";

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function write(files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-api-auth-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return dir;
}
const run = async (files: Record<string, string>) => apiAuthRule.run(await createProjectContext(await write(files)));

const TANSTACK_USERS = `import { createFileRoute } from "@tanstack/react-router";
import { supabaseAdmin } from "@/integrations/supabase/client.server";

export const Route = createFileRoute("/api/users")({
  server: {
    handlers: {
      GET: async () => {
        const { data } = await supabaseAdmin.from("profiles").select("id, email");
        return Response.json({ users: data });
      },
    },
  },
});
`;

describe("SEC_API_ROUTE_NO_AUTH", () => {
  it("flags a TanStack route that returns user data with no auth check, at the handler line", () => {
    const f = scanContent("src/routes/api/users.ts", TANSTACK_USERS);
    expect(f).toMatchObject({ fixId: "SEC_API_ROUTE_NO_AUTH", severity: "high", confidence: "high", line: 7 });
    expect(f?.fix).toContain("getUser");
  });

  it("flags Next.js app and pages routes and Supabase edge functions", async () => {
    const findings = await run({
      "app/api/orders/route.ts": `import { prisma } from "@/lib/db";\nexport async function GET() {\n  return Response.json(await prisma.order.findMany());\n}\n`,
      "pages/api/list.ts": `import { createClient } from "@supabase/supabase-js";\nconst sb = createClient(url, key);\nexport default async function handler(req, res) {\n  res.json(await sb.from("customers").select("*"));\n}\n`,
      "supabase/functions/export-users/index.ts": `const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nDeno.serve(async () => new Response(JSON.stringify(await admin.from("users").select())));\n`,
    });
    expect(findings.map((f) => `${f.file}:${f.line}`)).toEqual([
      "app/api/orders/route.ts:2",
      "pages/api/list.ts:3",
      "supabase/functions/export-users/index.ts:2",
    ]);
  });

  it("doesn't flag routes that check auth inline", () => {
    for (const check of [
      `const { data: { user } } = await supabase.auth.getUser(token);`,
      `const session = await getServerSession(authOptions);`,
      `const auth = req.headers.get("Authorization");`,
      `const user = await requireAuth(request);`,
    ]) {
      expect(scanContent("src/routes/api/users.ts", TANSTACK_USERS.replace("const { data }", `${check}\n        const { data }`))).toBeUndefined();
    }
  });

  it("doesn't flag routes protected by middleware they import", () => {
    const code = TANSTACK_USERS.replace(
      `import { supabaseAdmin }`,
      `import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";\nimport { supabaseAdmin }`,
    ).replace("server: {", "server: {\n    middleware: [requireSupabaseAuth],");
    expect(scanContent("src/routes/api/users.ts", code)).toBeUndefined();
  });

  it("doesn't flag routes covered by a project-wide auth middleware", async () => {
    const findings = await run({
      "middleware.ts": `export async function middleware(req) { const { data } = await supabase.auth.getUser(); }`,
      "app/api/orders/route.ts": `export async function GET() { return Response.json(await prisma.order.findMany()); }`,
    });
    expect(findings).toEqual([]);
  });

  it("only treats a middleware/proxy as covering the paths in its matcher", async () => {
    const findings = await run({
      "proxy.ts": `export async function proxy(req) { await supabase.auth.getClaims(); }\nexport const config = { matcher: ["/portal/:path*", "/api/portal/:path*"] };`,
      "app/api/portal/patients/route.ts": `export async function GET() { return Response.json(await prisma.patient.findMany()); }`,
      "app/api/orders/route.ts": `export async function GET() { return Response.json(await prisma.order.findMany()); }`,
    });
    expect(findings.map((f) => f.file)).toEqual(["app/api/orders/route.ts"]);
  });

  it("doesn't flag webhooks, static routes, frontend files or public routes without the admin client", () => {
    expect(scanContent("src/routes/api/public/stripe-webhook.ts", TANSTACK_USERS)).toBeUndefined();
    expect(scanContent("app/api/hooks/route.ts", `import { Webhook } from "svix";\n` + TANSTACK_USERS)).toBeUndefined();
    expect(scanContent("app/api/health/route.ts", `export async function GET() { return Response.json({ ok: true, list: Array.from("abc") }); }`)).toBeUndefined();
    expect(scanContent("src/components/Users.tsx", TANSTACK_USERS)).toBeUndefined();
    expect(scanContent("src/routes/api/public/posts.ts", `export async function GET() { return Response.json(await supabase.from("posts").select()); }`)).toBeUndefined();
  });

  it("still flags a public route that uses the admin client", () => {
    expect(scanContent("src/routes/api/public/users.ts", TANSTACK_USERS)).toMatchObject({ fixId: "SEC_API_ROUTE_NO_AUTH" });
  });

  it("reports once per route alongside the rate-limit finding on a different line (dedupe unchanged)", async () => {
    const root = await write({
      "src/routes/api/notes.ts": `import { supabaseAdmin } from "@/x/client.server";\nexport const Route = createFileRoute("/api/notes")({ server: { handlers: {\n  POST: async () => {\n    const r = await fetch("https://api.openai.com/v1/chat/completions", {});\n    await supabaseAdmin.from("notes").insert({});\n  },\n} } });\n`,
    });
    const { findings } = await runScan(root);
    expect(findings.map((f) => `${f.fixId} ${f.line}`).sort()).toEqual(["SEC_API_NO_RATE_LIMIT 4", "SEC_API_ROUTE_NO_AUTH 3"]);
  });
});

describe("SEC_API_ROUTE_NO_AUTH: server functions and helpers (chunk 3D)", () => {
  it("flags each server function that touches data with no auth check, at its createServerFn line", async () => {
    const findings = await run({
      "src/lib/profiles.ts": [
        `import { createServerFn } from "@tanstack/react-start";`,
        `import { supabaseAdmin } from "@/integrations/supabase/client.server";`,
        `import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";`,
        ``,
        `export const listProfiles = createServerFn({ method: "GET" }).handler(async () => {`,
        `  return (await supabaseAdmin.from("profiles").select("*")).data;`,
        `});`,
        `export const myProfile = createServerFn({ method: "GET" }).middleware([requireSupabaseAuth]).handler(async ({ context }) => {`,
        `  return (await context.supabase.from("profiles").select("*")).data;`,
        `});`,
        `export const ping = createServerFn().handler(async () => "pong");`,
      ].join("\n"),
    });
    expect(findings.map((f) => `${f.file}:${f.line} ${f.confidence}`)).toEqual(["src/lib/profiles.ts:5 high"]);
    expect(findings[0].title).toBe("Server function has no login check");
  });

  it("counts a server function's local middleware that checks auth", () => {
    const code = `const authed = createMiddleware().server(async ({ next }) => { await supabase.auth.getUser(); return next(); });\nexport const fn = createServerFn().middleware([authed]).handler(async () => supabase.from("notes").select());`;
    expect(scanServerFunctions("src/lib/notes.ts", code)).toEqual([]);
  });

  it("counts data access inside an imported helper (relative, @/ and ~/ via tsconfig paths)", async () => {
    const findings = await run({
      "tsconfig.json": `{\n  // comment\n  "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"], "~/*": ["./lib/*"], }, },\n}`,
      "src/lib/db.ts": `export const listPatients = () => prisma.patient.findMany();`,
      "lib/orders.ts": `export async function allOrders() { return db.query("select * from orders"); }`,
      "src/routes/api/helpers.ts": `export async function count() { return supabase.from("notes").select(); }`,
      "app/api/patients/route.ts": `import { listPatients } from "@/lib/db";\nexport async function GET() {\n  return Response.json(await listPatients());\n}`,
      "app/api/orders/route.ts": `import { allOrders } from "~/orders";\nexport async function GET() { return Response.json(await allOrders()); }`,
      "src/routes/api/count.ts": `import { count } from "./helpers";\nexport const Route = createFileRoute("/api/count")({ server: { handlers: {\n  GET: async () => Response.json(await count()),\n} } });`,
    });
    expect(findings.map((f) => `${f.file}:${f.line}`)).toEqual([
      "app/api/orders/route.ts:2",
      "app/api/patients/route.ts:2",
      "src/routes/api/count.ts:3",
      "src/routes/api/helpers.ts:1",
    ]);
    expect(findings[1].message).toContain("(through @/lib/db)");
    // orders (SELECT * from orders) and patients (findMany on a people model) return personal data → high;
    // the notes reads are plain public reads → low.
    expect(findings.map((f) => `${f.severity}/${f.confidence}`)).toEqual(["high/medium", "high/medium", "low/low", "low/low"]);
  });

  it("keeps helper-only data access high when the helper uses the admin client", async () => {
    const findings = await run({
      "src/lib/users.ts": `import { supabaseAdmin } from "./client.server";\nexport const allUsers = () => supabaseAdmin.from("profiles").select();`,
      "src/routes/api/users.ts": `import { allUsers } from "@/lib/users";\nexport const Route = createFileRoute("/api/users")({ server: { handlers: {\n  GET: async () => Response.json(await allUsers()),\n} } });`,
    });
    expect(findings.map((f) => `${f.file}:${f.line} ${f.severity}/${f.confidence}`)).toEqual(["src/routes/api/users.ts:3 high/high"]);
  });

  it("falls back to src/ then the root for @/ when there's no tsconfig", async () => {
    const findings = await run({
      "lib/db.ts": `export const all = () => prisma.user.findMany();`,
      "app/api/users/route.ts": `import { all } from "@/lib/db";\nexport async function GET() { return Response.json(await all()); }`,
    });
    expect(findings.map((f) => f.file)).toEqual(["app/api/users/route.ts"]);
  });

  it("counts an auth check inside a called helper, but not in a helper that is only imported", async () => {
    const files = {
      "src/lib/auth.ts": `export async function requireClinician() { const { data } = await supabase.auth.getClaims(); return data; }`,
      "src/lib/db.ts": `export const listPatients = () => prisma.patient.findMany();`,
    };
    const guarded = await run({
      ...files,
      "app/api/a/route.ts": `import { requireClinician } from "@/lib/auth";\nimport { listPatients } from "@/lib/db";\nexport async function GET() { await requireClinician(); return Response.json(await listPatients()); }`,
    });
    expect(guarded).toEqual([]);
    await rm(dir!, { recursive: true, force: true });
    const unguarded = await run({
      ...files,
      "app/api/a/route.ts": `import type { Clinician } from "@/lib/auth";\nimport { listPatients } from "@/lib/db";\nexport async function GET() { const c: Clinician | null = null; return Response.json(await listPatients()); }`,
    });
    expect(unguarded.map((f) => f.file)).toEqual(["app/api/a/route.ts"]);
  });

  it("only looks one level deep", async () => {
    const findings = await run({
      "src/lib/inner.ts": `export const q = () => prisma.user.findMany();`,
      "src/lib/outer.ts": `import { q } from "./inner";\nexport const outer = () => q();`,
      "app/api/users/route.ts": `import { outer } from "@/lib/outer";\nexport async function GET() { return Response.json(await outer()); }`,
    });
    expect(findings).toEqual([]);
  });
});

describe("SEC_API_ROUTE_NO_AUTH: writes vs reads, personal data", () => {
  const brief = (fs: Awaited<ReturnType<typeof run>>) => fs.map((f) => `${f.file}:${f.line} ${f.severity}/${f.confidence}`);

  it("doesn't flag a public create-only form without the admin client, even with lookups", async () => {
    const findings = await run({
      "lib/bookings.ts": [
        `export async function createBooking(input) {`,
        `  const service = await prisma.service.findFirst({ where: { slug: input.service } });`,
        `  return prisma.booking.create({ data: { customerName: input.name, email: input.email, serviceId: service.id } });`,
        `}`,
        `export async function listBookings() { return prisma.booking.findMany({ include: { service: true } }); }`,
        `export async function cancelBooking(id) { return prisma.booking.update({ where: { id }, data: { status: "cancelled" } }); }`,
      ].join("\n"),
      "app/api/bookings/route.ts": `import { createBooking } from "@/lib/bookings";\nexport async function POST(req) {\n  const b = await createBooking(schema.parse(await req.json()));\n  return Response.json({ reference: b.reference }, { status: 201 });\n}`,
      "app/api/contact/route.ts": `export async function POST(req) {\n  const body = await req.json();\n  await supabase.from("messages").insert({ name: body.name, email: body.email, message: body.message }).select();\n  return Response.json({ ok: true });\n}`,
    });
    expect(findings).toEqual([]);
  });

  it("flags an unauthenticated update or delete as high", async () => {
    const findings = await run({
      "app/api/notes/route.ts": `export async function PATCH(req) {\n  const { id, text } = await req.json();\n  await supabase.from("notes").update({ text }).eq("id", id);\n  return Response.json({ ok: true });\n}`,
      "lib/notes.ts": `export const removeNote = (id) => prisma.note.delete({ where: { id } });`,
      "app/api/notes/[id]/route.ts": `import { removeNote } from "@/lib/notes";\nexport async function DELETE(_req, { params }) { await removeNote(params.id); return new Response(null, { status: 204 }); }`,
    });
    expect(brief(findings)).toEqual(["app/api/notes/[id]/route.ts:2 high/medium", "app/api/notes/route.ts:1 high/medium"]);
    expect(findings[0].message).toContain("anyone could change or delete anyone's rows");
  });

  it("flags a read of personal-data columns through a helper as high", async () => {
    const findings = await run({
      "lib/team.ts": `export async function listTeam() {\n  return (await supabase.from("staff").select("id, full_name, phone")).data;\n}`,
      "app/api/team/route.ts": `import { listTeam } from "@/lib/team";\nexport async function GET() { return Response.json(await listTeam()); }`,
    });
    expect(brief(findings)).toEqual(["app/api/team/route.ts:2 high/medium"]);
    expect(findings[0].message).toContain("returns personal data (full_name, phone) (through @/lib/team)");
  });

  it("reports a read of non-personal data through a helper as low", async () => {
    const findings = await run({
      "lib/availability.ts": `export async function getMonth(month) {\n  const live = await prisma.booking.findMany({ where: { month }, select: { slotKey: true } });\n  const blocked = await prisma.blockedDate.findMany();\n  return { live, blocked };\n}`,
      "app/api/availability/route.ts": `import { getMonth } from "@/lib/availability";\nexport async function GET(req) { return Response.json({ days: await getMonth(1) }); }`,
    });
    expect(brief(findings)).toEqual(["app/api/availability/route.ts:2 low/low"]);
    expect(findings[0].message).toBe(
      "This public route reads data without login. Fine if the data is meant to be public; otherwise add an auth check.",
    );
  });

  it("flags an admin client read as high, even of non-personal columns", async () => {
    const findings = await run({
      "app/api/plans/route.ts": `import { supabaseAdmin } from "@/lib/admin";\nexport async function GET() {\n  return Response.json(await supabaseAdmin.from("plans").select("id, price"));\n}`,
    });
    expect(brief(findings)).toEqual(["app/api/plans/route.ts:2 high/high"]);
  });

  it("treats select('*') on a people table and personal response keys as personal data", async () => {
    const findings = await run({
      "app/api/a/route.ts": `export async function GET() { return Response.json(await supabase.from("profiles").select("*")); }`,
      "app/api/b/route.ts": `export async function GET() {\n  const { data } = await supabase.from("rows").select("id, owner");\n  return Response.json({ items: data, email: data[0].owner });\n}`,
      "app/api/c/route.ts": `export async function GET() { return Response.json(await supabase.from("products").select("id, name, price")); }`,
    });
    expect(brief(findings)).toEqual(["app/api/a/route.ts:1 high/medium", "app/api/b/route.ts:1 high/medium", "app/api/c/route.ts:1 low/low"]);
  });

  it("only judges the helper function the route calls, not the rest of its file", async () => {
    const findings = await run({
      "lib/bookings.ts": `import { supabaseAdmin } from "./admin";\nexport async function createBooking(input) { return prisma.booking.create({ data: { slot: input.slot } }); }\nexport async function wipe() { return supabaseAdmin.from("bookings").delete().neq("id", 0); }`,
      "app/api/bookings/route.ts": `import { createBooking } from "@/lib/bookings";\nexport async function POST(req) { return Response.json(await createBooking(await req.json())); }`,
    });
    expect(findings).toEqual([]);
  });

  it("follows calls inside the helper file, but not re-exports from other files", async () => {
    const findings = await run({
      "lib/time.ts": `export const deadline = () => prisma.booking.deleteMany({});`,
      "lib/availability.ts": `import { deadline } from "./time";\nexport { deadline };\nasync function loadSlots() { return prisma.booking.findMany({ select: { slotKey: true } }); }\nexport async function getMonth() { return { slots: await loadSlots() }; }`,
      "app/api/availability/route.ts": `import { getMonth, deadline } from "@/lib/availability";\nexport async function GET() { return Response.json({ days: await getMonth(), until: deadline() }); }`,
    });
    expect(brief(findings)).toEqual(["app/api/availability/route.ts:2 low/low"]);
  });

  it("finds the function body past a return type with braces", async () => {
    const findings = await run({
      "lib/availability.ts": `export async function getMonth(\n  month: string,\n): Promise<{ days: string[]; horizon: number }> {\n  const live = await prisma.booking.findMany({ select: { slotKey: true } });\n  return { days: live.map((b) => b.slotKey), horizon: 30 };\n}`,
      "lib/team.ts": `export function team(): { list: unknown[] } {\n  return { list: prisma.staff.findMany({ select: { phone: true } }) };\n}`,
      "app/api/availability/route.ts": `import { getMonth } from "@/lib/availability";\nexport async function GET() { return Response.json(await getMonth("2026-11")); }`,
      "app/api/team/route.ts": `import { team } from "@/lib/team";\nexport async function GET() { return Response.json(team()); }`,
    });
    expect(brief(findings)).toEqual(["app/api/availability/route.ts:2 low/low", "app/api/team/route.ts:2 high/medium"]);
  });

  it("ignores imported classes (e.g. an error type used in instanceof) from a helper file", async () => {
    const findings = await run({
      "lib/bookings.ts": `export class BookingError extends Error {}\nexport async function createBooking(input) { return prisma.booking.create({ data: { slot: input.slot } }); }\nexport async function cancel(id) { return prisma.booking.update({ where: { id }, data: {} }); }`,
      "app/api/bookings/route.ts": `import { BookingError, createBooking } from "@/lib/bookings";\nexport async function POST(req) {\n  try { return Response.json(await createBooking(await req.json())); }\n  catch (e) { if (e instanceof BookingError) return new Response(null, { status: 409 }); throw e; }\n}`,
    });
    expect(findings).toEqual([]);
  });

  describe("create-only forms with the admin client", () => {
    it("is medium when the request body goes straight into the insert", async () => {
      const findings = await run({
        "app/api/a/route.ts": `import { supabaseAdmin } from "@/lib/admin";\nexport async function POST(req) {\n  const body = await req.json();\n  await supabaseAdmin.from("leads").insert(body);\n  return Response.json({ ok: true });\n}`,
        "app/api/b/route.ts": `import { supabaseAdmin } from "@/lib/admin";\nexport async function POST(req) {\n  const body = await req.json();\n  await supabaseAdmin.from("leads").insert({ ...body, source: "site" });\n  return Response.json({ ok: true });\n}`,
        "app/api/c/route.ts": `import { prismaAdmin as prisma } from "@/lib/db";\nconst SERVICE_ROLE = 1;\nexport async function POST(req) {\n  const body = await req.json();\n  await prisma.lead.create({ data: body });\n  return Response.json({ ok: true });\n}`,
        "lib/leads.ts": `import { createClient } from "@supabase/supabase-js";\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\nexport async function saveLead(input) { await admin.from("leads").insert(input); }`,
        "app/api/d/route.ts": `import { saveLead } from "@/lib/leads";\nexport async function POST(req) {\n  const body = await req.json();\n  await saveLead(body);\n  return Response.json({ ok: true });\n}`,
      });
      expect(brief(findings)).toEqual([
        "app/api/a/route.ts:2 medium/medium",
        "app/api/b/route.ts:2 medium/medium",
        "app/api/c/route.ts:3 medium/medium",
        "app/api/d/route.ts:2 medium/medium",
      ]);
      expect(findings[0].message).toContain(
        "anyone can set any field, including ones like is_pro or user_id, and the admin client skips RLS: pick the allowed fields explicitly and add a rate limit or captcha",
      );
    });

    it("is low when the fields are picked explicitly", async () => {
      const findings = await run({
        "app/api/a/route.ts": `import { supabaseAdmin } from "@/lib/admin";\nexport async function POST(req) {\n  const { name, email, message } = await req.json();\n  await supabaseAdmin.from("leads").insert({ name, email, message });\n  return Response.json({ ok: true });\n}`,
      });
      expect(brief(findings)).toEqual(["app/api/a/route.ts:2 low/low"]);
      expect(findings[0].message).toBe("Public form using the admin client: validate input and add a rate limit or captcha.");
    });
  });
});

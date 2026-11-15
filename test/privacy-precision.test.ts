// Regression tests for the Nov 15, 2026 precision fixes to the privacy rules,
// each shaped after a case seen on a real app (see NOTES-FOR-SERENA.md).
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Rule } from "../src/contract.js";
import { createProjectContext } from "../src/lib/files.js";
import { noAccountDeletion } from "../src/rules/privacy/rules/noAccountDeletion.js";
import { noDataExport } from "../src/rules/privacy/rules/noDataExport.js";
import { noPrivacyPolicy } from "../src/rules/privacy/rules/noPrivacyPolicy.js";

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function run(rule: Rule, files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-precision-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(dir, path, ".."), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return rule.run(await createProjectContext(dir));
}

const where = (findings: { file?: string; line?: number }[]) => findings.map((f) => `${f.file}:${f.line}`);

describe("PRIV_NO_PRIVACY_POLICY: only when personal data leaves the browser", () => {
  it("ignores an email form that only sets local state", async () => {
    const form = `export function Notify() {
  return (
    <form onSubmit={(e) => { e.preventDefault(); setNotified(true) }}>
      <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
    </form>
  );
}
`;
    expect(await run(noPrivacyPolicy, { "app/workshops/Notify.tsx": form })).toEqual([]);
  });

  it("flags the same form once it sends the email", async () => {
    const form = `export function Notify() {
  const send = () => fetch("/api/notify", { method: "POST", body: JSON.stringify({ email }) });
  return <input type="email" value={email} />;
}
`;
    expect(where(await run(noPrivacyPolicy, { "app/Notify.tsx": form }))).toEqual(["app/Notify.tsx:3"]);
  });

  it("ignores admin-only forms (the operator's own details)", async () => {
    const admin = `"use server";
export const save = async () => {};
export default () => <ActionForm action={save}><Field name="notificationEmail" type="email" /></ActionForm>;
`;
    expect(await run(noPrivacyPolicy, { "app/(admin)/admin/settings/page.tsx": admin, "components/admin/LoginForm.tsx": `fetch("/x");\n<input name="email" />\n` })).toEqual([]);
  });

  it("counts a profile form under dashboard/ that sends an email (users' own area, not admin)", async () => {
    const profile = `export function ProfileForm() {
  const save = () => fetch("/api/profile", { method: "POST", body: JSON.stringify({ email }) });
  return <input type="email" value={email} />;
}
`;
    expect(where(await run(noPrivacyPolicy, { "app/dashboard/profile/ProfileForm.tsx": profile }))).toEqual([
      "app/dashboard/profile/ProfileForm.tsx:3",
    ]);
  });

  it("points at the public booking form, not the admin settings page", async () => {
    const booking = `export function BookingFlow() {
  const submit = () => fetch("/api/bookings", { method: "POST", body: JSON.stringify(form) });
  return (<>
    <input autoComplete="name" />
    <input autoComplete="email" />
    <input autoComplete="tel" />
  </>);
}
`;
    const admin = `"use server";\n<Field name="email" type="email" />\n`;
    const findings = await run(noPrivacyPolicy, { "app/(admin)/admin/settings/page.tsx": admin, "components/booking/BookingFlow.tsx": booking });
    expect(where(findings)).toEqual(["components/booking/BookingFlow.tsx:4"]);
  });

  it("flags an API route that reads email/phone/name from the request, ahead of forms", async () => {
    const route = `export async function POST(request: Request) {
  const { name, email } = await request.json();
  return Response.json({ ok: true });
}
`;
    const form = `fetch("/api/contact");\n<input type="email" />\n`;
    const findings = await run(noPrivacyPolicy, { "app/api/contact/route.ts": route, "app/Contact.tsx": form });
    expect(where(findings)).toEqual(["app/api/contact/route.ts:2"]);
  });

  it("skips webhook routes (the provider sends that email, not a user) and points at the sign-up instead", async () => {
    const webhook = `export const POST = async ({ request }) => {
  const event = await request.json();
  const email = event.data.object.customer_email;
};
`;
    const auth = `await supabase.auth.signUp({ email, password });\n`;
    expect(await run(noPrivacyPolicy, { "src/routes/api/public/stripe-webhook.ts": webhook })).toEqual([]);
    const findings = await run(noPrivacyPolicy, { "src/routes/api/public/stripe-webhook.ts": webhook, "src/routes/auth.tsx": auth });
    expect(where(findings)).toEqual(["src/routes/auth.tsx:1"]);
  });

  it("ignores a SQL column on its own", async () => {
    expect(await run(noPrivacyPolicy, { "drizzle/0000_schema.sql": "create table users (id uuid, email text);\n" })).toEqual([]);
  });

  it("still flags a sign-up call", async () => {
    const auth = `await supabase.auth.signUp({ email, password });\n`;
    expect(where(await run(noPrivacyPolicy, { "src/routes/auth.tsx": auth }))).toEqual(["src/routes/auth.tsx:1"]);
  });

  it("counts a privacy / data-protection section in a terms page as a policy", async () => {
    const auth = `await supabase.auth.signUp({ email, password });\n`;
    const terms = `export default () => <section><h2>9. DATA PROTECTION & PRIVACY</h2><p>We only use your email to reply.</p></section>;\n`;
    expect(await run(noPrivacyPolicy, { "src/routes/auth.tsx": auth, "app/terms/page.tsx": terms })).toEqual([]);
  });

  it("doesn't count a terms page with no privacy section", async () => {
    const auth = `await supabase.auth.signUp({ email, password });\n`;
    const terms = `export default () => <p>Payments are non-refundable.</p>;\n`;
    expect(await run(noPrivacyPolicy, { "src/routes/auth.tsx": auth, "app/terms/page.tsx": terms })).toHaveLength(1);
  });
});

describe("PRIV_NO_ACCOUNT_DELETION and PRIV_NO_DATA_EXPORT: only when users sign themselves up", () => {
  const signInOnly = `export async function signIn(email: string, password: string) {
  return supabase.auth.signInWithPassword({ email, password });
}
`;
  const signUp = `export async function join(email: string, password: string) {
  return supabase.auth.signUp({ email, password });
}
`;

  it("don't flag operator-created accounts (sign-in only)", async () => {
    expect(await run(noAccountDeletion, { "lib/db/auth.ts": signInOnly })).toEqual([]);
    expect(await run(noDataExport, { "lib/db/auth.ts": signInOnly })).toEqual([]);
  });

  it("flag self sign-up with no delete or export path", async () => {
    expect(where(await run(noAccountDeletion, { "lib/auth.ts": signUp }))).toEqual(["lib/auth.ts:2"]);
    expect(where(await run(noDataExport, { "lib/auth.ts": signUp }))).toEqual(["lib/auth.ts:2"]);
  });

  it("count OAuth and magic-link logins as self sign-up", async () => {
    expect(await run(noAccountDeletion, { "a.ts": "supabase.auth.signInWithOAuth({ provider: 'google' });\n" })).toHaveLength(1);
    expect(await run(noAccountDeletion, { "a.ts": "supabase.auth.signInWithOtp({ email });\n" })).toHaveLength(1);
  });

  it("don't treat react-hook-form's register() as sign-up", async () => {
    expect(await run(noAccountDeletion, { "Form.tsx": `<input {...register("email")} />\n` })).toEqual([]);
  });
});

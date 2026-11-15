import type { ProjectContext, Rule } from "../../../contract.js";
import { findMatches, isCodeFile, makeFinding, stripComments, type Match } from "../utils.js";

/**
 * Rule 1: PRIV_NO_PRIVACY_POLICY
 * Law: people must be told what data is collected and why (GDPR Art. 13; PIPEDA Principle 4.8, openness).
 *
 * IF   personal data actually LEAVES the browser at a public collection point
 *      (a sign-up call, a form with personal-data fields in a file that sends data,
 *       or an API route that reads email/phone/name from the request)
 * AND  there is no privacy page (no file named "privacy...", no link/route to it,
 *      no privacy/data-protection section in a terms or legal page)
 * THEN report a possible gap, pointing at the first public collection point.
 *
 * Changed Nov 15, 2026 (Hilal, after scanning real apps; see NOTES-FOR-SERENA.md):
 * a form that only keeps the email in local state, an admin-only form and a SQL
 * column no longer count as collecting data.
 */

// Sign-up calls: the email goes to the auth provider.
const SIGN_UP = [
  /\.signUp\s*\(/,                          // Supabase
  /\bsignUp\.(email|social)\s*\(/,          // better-auth
  /createUserWithEmailAndPassword\s*\(/,    // Firebase
];

// Form fields that ask for personal data.
const PERSONAL_DATA_FIELD = [
  /type\s*=\s*["'](email|tel)["']/i,                                           // <input type="email"> or "tel"
  /name\s*=\s*["'](e-?mail|phone|full_?name|first_?name|last_?name|address|birth_?date|dob)["']/i, // <input name="phone">
  /autoComplete\s*=\s*["'](email|tel|name|given-name|family-name|street-address|bday)["']/i,      // autoComplete="email"
  /inputMode\s*=\s*["'](email|tel)["']/i,                                       // inputMode="tel"
];

// Signs that a file sends data somewhere (so its form fields don't just sit in local state).
const SENDS_DATA = [
  /\bfetch\s*\(/,
  /\baxios\b/,
  /<form\b[^>]*\baction\s*=/i,               // <form action="https://..."> or action={serverAction}
  /\.(insert|upsert)\s*\(/,                  // Supabase / Drizzle / Knex writes
  /\.signUp\s*\(|\bsignUp\.(email|social)\s*\(|createUserWithEmailAndPassword\s*\(/,
  /^\s*["']use server["']/,                  // Next.js server actions
  /\buseMutation\s*\(/,                      // TanStack / tRPC mutations
];

// API routes and edge functions (server code that receives requests).
const API_ROUTE_FILE = /(^|\/)(app\/(.+\/)?route\.[cm]?[jt]s$|pages\/api\/|routes\/api\/|supabase\/functions\/|api\/)/;
const READS_REQUEST = [/\b(req|request)\.(json|formData)\s*\(/, /\breq\.body\b/, /\bawait\s+\w+\.json\s*\(\s*\)/];
const WEBHOOK_FILE = /webhook/i;
const PERSONAL_DATA_KEY = /\b(e-?mail|phone|phone_?number|full_?name|first_?name|last_?name|address|birth_?date|dob)\b/i;

// Admin pages: data the operator types in about themselves, not users' data.
// dashboard/ is NOT skipped (Serena's review, Nov 15, 2026): in most apps it's the user's own area,
// e.g. a profile form where users enter their email.
const ADMIN_PATH = /(^|\/)(\(admin\)|admin)\//i;

// Signs that a privacy page exists: a link, a route, or a link to an outside policy.
const PRIVACY_LINK_OR_ROUTE = [
  /(href|to)\s*=\s*\{?\s*["'`][^"'`]*privacy[^"'`]*["'`]/i,  // <a href="/privacy">, <Link to="/privacy-policy">
  /path\s*[:=]\s*["'`][^"'`]*privacy[^"'`]*["'`]/i,          // route path: "/privacy"
];

// A terms or legal page with its own privacy / data-protection section also tells users what happens to their data.
const LEGAL_PAGE_FILE = /(terms|legal|conditions|tos|imprint|impressum)/i;
const PRIVACY_SECTION = /data protection|privacy (policy|notice|statement)|personal (data|information)|\bprivacy\b/i;

/** Lines of a file, without comments. */
const codeLines = (ctx: ProjectContext, file: string) => ctx.read(file).split(/\r?\n/).map(stripComments);

/** Public places where personal data leaves the browser: API routes first, then sign-up calls, then forms that send. */
export function collectionPoints(ctx: ProjectContext): Match[] {
  const routes: Match[] = [];
  const forms: Match[] = [];
  for (const file of ctx.files) {
    if (!isCodeFile(file) || ADMIN_PATH.test(file)) continue;
    const lines = codeLines(ctx, file);
    const at = (i: number): Match => ({ file, line: i + 1, text: lines[i].trim() });

    // Webhooks receive data from a provider (e.g. Stripe's customer email), not from a user filling in a form.
    if (API_ROUTE_FILE.test(file) && !WEBHOOK_FILE.test(file) && lines.some((l) => READS_REQUEST.some((p) => p.test(l)))) {
      const i = lines.findIndex((l) => PERSONAL_DATA_KEY.test(l));
      if (i !== -1) routes.push(at(i));
    }
    if (lines.some((l) => SENDS_DATA.some((p) => p.test(l)))) {
      const i = lines.findIndex((l) => PERSONAL_DATA_FIELD.some((p) => p.test(l)));
      if (i !== -1) forms.push(at(i));
    }
  }
  const signUps = findMatches(ctx, SIGN_UP).filter((m) => !ADMIN_PATH.test(m.file));
  return [...routes, ...signUps, ...forms];
}

function hasPrivacyPolicy(ctx: ProjectContext): boolean {
  if (ctx.files.some((f) => /privacy/i.test(f))) return true;
  if (findMatches(ctx, PRIVACY_LINK_OR_ROUTE).length > 0) return true;
  return ctx.files.some(
    (f) => isCodeFile(f) && LEGAL_PAGE_FILE.test(f) && codeLines(ctx, f).some((l) => PRIVACY_SECTION.test(l)),
  );
}

export const noPrivacyPolicy: Rule = {
  id: "PRIV_NO_PRIVACY_POLICY",
  category: "privacy",
  description: "The app collects personal data but has no privacy policy page or link.",

  run(ctx) {
    // 1. Does personal data leave the browser at a public collection point? If not, this rule has nothing to say.
    const collected = collectionPoints(ctx);
    if (collected.length === 0) return [];

    // 2. Is there a privacy page? (a file named "privacy...", a link/route to one, or a privacy section in the terms)
    if (hasPrivacyPolicy(ctx)) return [];

    // 3. Report once, pointing at the first public place personal data is collected.
    const first = collected[0];
    return [
      makeFinding("PRIV_NO_PRIVACY_POLICY", {
        message:
          `Possible gap: this app seems to collect personal data (first seen in ${first.file}, line ${first.line}) ` +
          `but we couldn't find a privacy policy page or link. Users must be told what you collect and why.`,
        file: first.file,
        line: first.line,
        confidence: "medium", // the policy might be on a separate website we can't see
      }),
    ];
  },
};

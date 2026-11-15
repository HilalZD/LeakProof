import { basename, extname } from "node:path";
import { isCodeFile } from "../lib/files.js";
import { bodyNames, summarize as summarizeData, type DataSummary } from "../lib/data-ops.js";
import { exportedBody, loadAliases, parseImports, resolveImport, type ImportInfo } from "../lib/imports.js";
import type { ScanFinding, ScannerRule, Severity } from "../types.js";
import { LOGIN_CHECKS } from "./rate-limit.js";
import { isStripeWebhookHandler, stripComments } from "./stripe-webhook.js";

const RULE_ID = "api-auth";

const SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
const TEST_FILE = /\.(?:test|spec)\.|\.d\.ts$/i;
const TEST_DIRS = new Set(["__tests__", "__mocks__", "test", "tests", "e2e", "cypress"]);

// Server routes, by path.
const ROUTE_PATHS = [
  /(?:^|\/)routes\/api[/.]/,                                          // TanStack Start: src/routes/api/** and api.x.ts
  /(?:^|\/)app\/api\/(?:.+\/)?route\.(?:ts|js|mjs)$/,                // Next.js app router (also src/app)
  /(?:^|\/)pages\/api\//,                                             // Next.js pages router
  /(?:^|\/)supabase\/functions\/(?!_)[^/]+\/index\.(?:ts|js|mjs)$/,   // Supabase edge functions (not _shared)
];
const WEBHOOK_PATH = /webhook/i;
// Folders that mark a route as intentionally public (Lovable's TanStack template: /api/public/*).
const PUBLIC_PATH = /(?:^|\/)api\/public\//;

// TanStack Start server functions: createServerFn(...).handler(...). Each one is an HTTP endpoint.
const SERVER_FN = /\bcreateServerFn\s*\(/g;
const HAS_SERVER_FN = /\bcreateServerFn\s*\(/;

// Reading or writing user data.
const ADMIN_CLIENT = /\bsupabaseAdmin\b|SERVICE_?ROLE|\bsb_secret_|\bcreateAdminClient\b/i;
const DATA_ACCESS = [
  /(?<!\b(?:storage|Array|Buffer|Uint8Array))\.from\s*\(\s*["'`]/,                // supabase.from("table"), not Array.from("x")
  /\.rpc\s*\(\s*["'`]/,                                                             // supabase.rpc("fn")
  /\.auth\.admin\.\w+\s*\(/,                                                        // listing or changing users
  /\bprisma\.\w+\.(?:find\w*|create\w*|update\w*|delete\w*|upsert|count|aggregate|groupBy)\s*\(/,
  /\b(?:db|pool|client|knex|conn|connection)\.(?:query|select|insert|update|delete|execute)\s*\(/,
  /\bsql\s*`/,
];

// Webhooks (they have their own rule) are called by the provider, not users.
const WEBHOOK_VERIFICATION = /\bsvix\b|\bcreateHmac\b|\btimingSafeEqual\b|["'`]HMAC["'`]|\bconstructEvent(?:Async)?\b/i;

// An imported helper from an auth-sounding module, e.g. requireSupabaseAuth from "@/integrations/supabase/auth-middleware".
const AUTH_MODULE = /auth|middleware|guard|protect|session/i;
// middleware: [x] (TanStack routes) or .middleware([x]) (server functions).
const MIDDLEWARE_LIST = /\bmiddleware\s*:\s*\[\s*[\w$]|\.middleware\s*\(\s*\[\s*[\w$]/;

// Where the handler starts; the finding points there.
const HANDLER_LINES = [
  /\b(?:GET|POST|PUT|PATCH|DELETE)\s*:\s*(?:async\b|\()/,                           // TanStack handlers: { GET: async () => ... }
  /\bexport\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)\b/,  // Next.js app router
  /\bexport\s+default\b/,                                                           // pages/api
  /\b(?:Deno\.)?serve\s*\(/,                                                        // Supabase edge functions
];

const FIX =
  "Check who is calling before touching data (e.g. supabase.auth.getUser(token) and return 401 if there's no user), then only return that user's own rows.";
const FIX_SERVER_FN =
  "Add an auth middleware to the server function (e.g. .middleware([requireSupabaseAuth])) or check supabase.auth.getUser() first, and only return the caller's own rows.";

/** What one helper function does, as far as a caller is concerned. */
export interface HelperFacts {
  summary: DataSummary;
  /** It touches data and its file sets up the admin/service_role client. */
  admin: boolean;
  /** Its file checks auth (file-level, so a local getClaims() wrapper still counts). */
  auth: boolean;
}

/**
 * Looks up what an imported binding does: `imported` is the exported name
 * ("default", "*"), `bodyArg` is true when the caller passes it the raw request body.
 * Undefined for packages and files that can't be read.
 */
export type HelperLookup = (spec: string, imported: string, bodyArg: boolean) => HelperFacts | undefined;

const hasData = (code: string) => DATA_ACCESS.some((p) => p.test(code));
const escape = (name: string) => name.replace(/\$/g, "\\$");
const uses = (code: string, name: string) => new RegExp(`(?<![\\w$.])${escape(name)}\\b`).test(code);
const calls = (code: string, name: string) =>
  new RegExp(`(?<![\\w$.])${escape(name)}\\s*\\(`).test(code) || new RegExp(`middleware\\s*\\(?\\s*[:\\[][^\\]]*\\b${escape(name)}\\b`).test(code);

/** The first parameter's name of a function source, if it's a plain identifier. */
const firstParam = (fn: string) => /(?:function\s*\*?\s*[\w$]*\s*(?:<[^>]*>)?|=\s*(?:async\s*)?)\(\s*([\w$]+)/.exec(fn)?.[1];

/**
 * The function's source plus the functions it calls that are defined in the
 * same file (e.g. getMonthAvailability → loadBlockedDays), so work split
 * across one helper file still counts. Imports of other files aren't followed.
 */
function withLocalCallees(file: string, fn: string): string {
  const parts = [fn];
  const seen = new Set<string>();
  for (let i = 0; i < parts.length && parts.length < 20; i++) {
    for (const m of parts[i].matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(/g)) {
      const name = m[1];
      if (seen.has(name) || /^(?:if|for|while|switch|catch|function|return|await|typeof|new)$/.test(name)) continue;
      seen.add(name);
      const body = exportedBody(file, name);
      if (body && !parts.includes(body)) parts.push(body);
    }
  }
  return parts.join("\n");
}

/** Facts for one exported function of a helper file (the whole file for a namespace import). */
export function factsOf(code: string, imported = "*", bodyArg = false): HelperFacts {
  const c = stripComments(code);
  // A class (an error type used in instanceof) or type isn't a data call.
  if (imported !== "*" && imported !== "default" && new RegExp(`\\b(?:class|interface|type|enum)\\s+${escape(imported)}\\b`).test(c)) {
    return { summary: summarizeData(""), admin: false, auth: false };
  }
  const own = exportedBody(c, imported);
  // A named import the helper doesn't define itself is re-exported from another file: that's two levels away.
  if (own === undefined && imported !== "*") return { summary: summarizeData(""), admin: false, auth: false };
  const fn = own === undefined ? c : withLocalCallees(c, own);
  const param = bodyArg ? firstParam(fn) : undefined;
  const summary = summarizeData(fn, param ? [param] : []);
  if (!summary.data && hasData(fn)) Object.assign(summary, { data: true, reads: true });
  // Admin clients set up at the top of the file: const admin = createClient(url, SERVICE_ROLE_KEY), or imported supabaseAdmin.
  const adminNames = [
    ...[...c.matchAll(/(?:const|let|var)\s+([\w$]+)\s*=[^;\n]*/g)].filter((m) => ADMIN_CLIENT.test(m[0])).map((m) => m[1]),
    ...parseImports(c).flatMap((i) => i.names).filter((n) => ADMIN_CLIENT.test(n)),
  ];
  const admin = summary.data && (ADMIN_CLIENT.test(fn === c ? c : fn) || adminNames.some((n) => uses(fn, n)));
  return { summary, admin, auth: LOGIN_CHECKS.some((p) => p.test(c)) };
}

interface Analysis {
  data: boolean;
  creates: boolean;
  writes: boolean;
  reads: boolean;
  personal: string[];
  rawCreate: boolean;
  admin: boolean;
  auth: boolean;
  via?: string; // helper import that touches data, when the scope itself doesn't
}

/**
 * Data access and auth checks in `scope` (a route file, or one server
 * function), counting imported local helpers one level deep.
 */
function analyze(scope: string, imports: ImportInfo[], helpers: HelperLookup, fileCode: string, responses: boolean): Analysis {
  const s = summarizeData(scope, [], responses);
  const direct = s.data || hasData(scope);
  const a: Analysis = {
    ...s,
    data: direct,
    reads: s.reads || (direct && !s.data),
    admin: ADMIN_CLIENT.test(scope),
    auth: LOGIN_CHECKS.some((p) => p.test(scope)),
  };
  const raw = bodyNames(scope).map(escape).concat(String.raw`req\.body`, String.raw`await\s+(?:req|request)\.json\(\s*\)`).join("|");
  for (const imp of imports) {
    const used = imp.bindings.filter((b) => uses(scope, b.local));
    if (used.length === 0) continue;
    // Auth middleware or helper imported from an auth-sounding module.
    if (AUTH_MODULE.test(imp.spec) && (MIDDLEWARE_LIST.test(scope) || used.some((b) => calls(scope, b.local)))) a.auth = true;
    for (const b of used) {
      const bodyArg = new RegExp(`(?<![\\w$.])${escape(b.local)}\\s*\\(\\s*(?:${raw})\\s*[,)]`).test(scope);
      const facts = helpers(imp.spec, b.imported, bodyArg);
      if (!facts) continue;
      // An auth check inside the helper counts when the route calls it (or uses it as middleware).
      if (facts.auth && calls(scope, b.local)) a.auth = true;
      const h = facts.summary;
      // Only helpers the route actually calls (fn() or obj.method()) do data work for it.
      const invoked = calls(scope, b.local) || new RegExp(`(?<![\\w$.])${escape(b.local)}\\.[\\w$]+\\s*\\(`).test(scope);
      if (!h.data || !invoked) continue;
      if (!a.data) a.via ??= imp.spec;
      a.creates ||= h.creates;
      a.writes ||= h.writes;
      a.reads ||= h.reads;
      a.rawCreate ||= h.rawCreate;
      a.personal = [...new Set([...a.personal, ...h.personal])];
      a.admin ||= facts.admin;
    }
  }
  a.data ||= a.creates || a.writes || a.reads;
  // A middleware defined in this file that checks auth.
  if (!a.auth && MIDDLEWARE_LIST.test(scope) && LOGIN_CHECKS.some((p) => p.test(fileCode))) a.auth = true;
  return a;
}

/** Whether the route checks who is calling: inline checks or an imported auth helper/middleware. */
export function hasAuthCheck(code: string): boolean {
  const imports = parseImports(code);
  const scope = imports.reduce((c, i) => c.replace(i.statement, ""), code);
  return analyze(scope, imports, () => undefined, code, false).auth || LOGIN_CHECKS.some((p) => p.test(code));
}

/** Project-wide middleware (Next.js middleware.ts / proxy.ts, TanStack start.ts). */
const PROJECT_MIDDLEWARE = /^(?:src\/)?(?:middleware|proxy|start)\.(?:ts|js|mjs)$/;

/**
 * The route paths a project-wide middleware covers: every path, or only the
 * prefixes in its Next.js `matcher` (e.g. "/api/portal/:path*" → "/api/portal/").
 */
export function middlewareScope(code: string): "all" | string[] {
  const m = /\bmatcher\s*:\s*(\[[^\]]*\]|["'`][^"'`]*["'`])/.exec(code);
  if (!m) return "all";
  const entries = [...m[1].matchAll(/["'`]([^"'`]*)["'`]/g)].map((e) => e[1]);
  if (entries.some((e) => e.includes("(") || e === "/:path*" || e === "/")) return "all"; // negative lookahead catch-alls
  return entries.map((e) => e.replace(/:path\*.*$|\*.*$/, "").replace(/\/?$/, "/"));
}

/** The URL path a route file serves, e.g. app/api/portal/me/route.ts → /api/portal/me/. */
function routeUrl(file: string): string {
  const path = file
    .replace(/^src\//, "")
    .replace(/^(?:app|pages)\//, "/")
    .replace(/^routes\//, "/")
    .replace(/\/route\.\w+$|\.\w+$/, "")
    .replace(/^supabase\/functions\/([^/]+)\/index$/, "/functions/$1");
  return path.replace(/\/?$/, "/");
}

function firstLine(lines: string[], patterns: RegExp[]): number {
  for (const p of patterns) {
    const i = lines.findIndex((l) => p.test(l));
    if (i !== -1) return i;
  }
  return -1;
}

const viaText = (via?: string) => (via ? ` (through ${via})` : "");

type Verdict = { severity: Severity; confidence: "high" | "medium" | "low"; kind: "write" | "admin-read" | "personal" | "public-read" | "raw-form" | "admin-form" };

/**
 * How bad a route or server function with no auth check is:
 * changes/deletes → high; reads with the admin client or personal fields → high;
 * other reads → low; creates (forms) → not flagged, unless they use the admin
 * client (raw body → medium, picked fields → low).
 */
function verdict(a: Analysis): Verdict | undefined {
  if (!a.data || a.auth) return undefined;
  if (a.writes) return { severity: "high", confidence: a.admin ? "high" : "medium", kind: "write" };
  // Reads that only support a create (look up a service, check a slot) are part of the form.
  const formLookup = a.creates && a.personal.length === 0;
  if (a.reads && !formLookup) {
    if (a.admin) return { severity: "high", confidence: "high", kind: "admin-read" };
    if (a.personal.length > 0) return { severity: "high", confidence: "medium", kind: "personal" };
    return { severity: "low", confidence: "low", kind: "public-read" };
  }
  if (a.creates && a.admin) return a.rawCreate ? { severity: "medium", confidence: "medium", kind: "raw-form" } : { severity: "low", confidence: "low", kind: "admin-form" };
  return undefined;
}

const FIX_RAW_FORM = "Pick the allowed fields explicitly (e.g. insert({ name, email, message })) and add a rate limit or captcha.";
const FIX_PUBLIC = "If this data isn't meant to be public, check who is calling first (e.g. supabase.auth.getUser()).";

function finding(file: string, line: number, a: Analysis, v: Verdict, serverFn: boolean): ScanFinding {
  const what = serverFn ? "This server function" : "This route";
  const anyone = serverFn ? "anyone can call it over HTTP" : "anyone can call it";
  const via = viaText(a.via);
  const fields = a.personal.slice(0, 4).join(", ") + (a.personal.length > 4 ? ", …" : "");
  const noLogin = serverFn ? "Server function has no login check" : "API route has no login check";
  const texts: Record<Verdict["kind"], { title: string; message: string; fix: string }> = {
    write: {
      title: noLogin,
      message: `${what} changes or deletes rows${via} and never checks who is calling: anyone could change or delete anyone's rows.`,
      fix: serverFn ? FIX_SERVER_FN : FIX,
    },
    "admin-read": {
      title: noLogin,
      message: `${what} reads user data${via} with the Supabase admin client, which skips Row Level Security, and never checks who is calling: ${anyone} and get the data.`,
      fix: serverFn ? FIX_SERVER_FN : FIX,
    },
    personal: {
      title: noLogin,
      message: `${what} returns personal data (${fields})${via} and never checks who is calling: ${anyone} and get it.`,
      fix: serverFn ? FIX_SERVER_FN : FIX,
    },
    "public-read": {
      title: serverFn ? "Public server function reads data without login" : "Public route reads data without login",
      message: `This public ${serverFn ? "server function" : "route"} reads data without login. Fine if the data is meant to be public; otherwise add an auth check.`,
      fix: FIX_PUBLIC,
    },
    "raw-form": {
      title: "Public form writes with the admin client",
      message: `${what} saves the request body as-is${via}: anyone can set any field, including ones like is_pro or user_id, and the admin client skips RLS: pick the allowed fields explicitly and add a rate limit or captcha.`,
      fix: FIX_RAW_FORM,
    },
    "admin-form": {
      title: "Public form writes with the admin client",
      message: `Public form using the admin client${via}: validate input and add a rate limit or captcha.`,
      fix: FIX_RAW_FORM,
    },
  };
  return {
    ruleId: RULE_ID,
    fixId: "SEC_API_ROUTE_NO_AUTH",
    category: "security",
    severity: v.severity,
    confidence: v.confidence,
    ...texts[v.kind],
    file,
    line: line + 1,
  };
}

const isTestFile = (file: string) => TEST_FILE.test(basename(file)) || file.split("/").some((p) => TEST_DIRS.has(p));

/** Server functions in a file without an auth check that touch data, one finding each. */
export function scanServerFunctions(file: string, content: string, helpers: HelperLookup = () => undefined): ScanFinding[] {
  if (isTestFile(file)) return [];
  const code = stripComments(content);
  const starts = [...code.matchAll(SERVER_FN)].map((m) => m.index!);
  if (starts.length === 0) return [];
  const imports = parseImports(code);
  const findings: ScanFinding[] = [];
  starts.forEach((start, i) => {
    const scope = code.slice(start, starts[i + 1] ?? code.length);
    const a = analyze(scope, imports, helpers, code, false);
    const v = verdict(a);
    if (v) findings.push(finding(file, code.slice(0, start).split("\n").length - 1, a, v, true));
  });
  return findings;
}

/** The finding for one route file, or undefined. */
export function scanContent(file: string, content: string, helpers: HelperLookup = () => undefined): ScanFinding | undefined {
  if (isTestFile(file) || !ROUTE_PATHS.some((p) => p.test(file))) return undefined;
  const code = stripComments(content);
  if (/^\s*["']use client["']/m.test(code)) return undefined;
  if (WEBHOOK_PATH.test(file) || isStripeWebhookHandler(file, content) || WEBHOOK_VERIFICATION.test(code)) return undefined;

  const imports = parseImports(code);
  const scope = imports.reduce((c, i) => c.replace(i.statement, (s) => s.replace(/[^\n]/g, " ")), code);
  const a = analyze(scope, imports, helpers, code, true);
  // Public routes are allowed to read data RLS already exposes; the admin client skips RLS.
  if (PUBLIC_PATH.test(file) && !a.admin) return undefined;
  const v = verdict(a);
  if (!v) return undefined;

  const lines = scope.split(/\r?\n/);
  const helperNames = imports.filter((i) => i.spec === a.via).flatMap((i) => i.names);
  const dataLine = firstLine(lines, [...DATA_ACCESS, ...helperNames.map((n) => new RegExp(`(?<![\\w$./])${escape(n)}\\s*[(.]`))]);
  const handlerLine = firstLine(lines, HANDLER_LINES);
  const line = handlerLine !== -1 && (dataLine === -1 || handlerLine <= dataLine) ? handlerLine : Math.max(dataLine, 0);
  return finding(file, line, a, v, false);
}

const isScriptFile = (name: string) => isCodeFile(name) && SCRIPT_EXTENSIONS.has(extname(name).toLowerCase());

export const apiAuthRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Login checks on API routes that touch user data",
  passedLabel: "API routes and server functions that touch user data check who is calling",
  jsOnly: true,
  notApplicable: (ctx) =>
    ctx.files.some(
      (file) =>
        isScriptFile(basename(file)) &&
        !isTestFile(file) &&
        (ROUTE_PATHS.some((p) => p.test(file)) || HAS_SERVER_FN.test(ctx.read(file))),
    )
      ? undefined
      : "no API routes or server functions found",
  run(ctx) {
    const scripts = ctx.files.filter((f) => isScriptFile(basename(f)));
    const fileSet = new Set(ctx.files);
    const aliases = loadAliases(ctx);
    const factsCache = new Map<string, HelperFacts>();
    const helpersFor = (file: string): HelperLookup => (spec, imported, bodyArg) => {
      const target = resolveImport(fileSet, aliases, file, spec);
      if (!target || target === file || !isScriptFile(basename(target))) return undefined;
      const key = `${target}\0${imported}\0${bodyArg}`;
      let facts = factsCache.get(key);
      if (!facts) factsCache.set(key, (facts = factsOf(ctx.read(target), imported, bodyArg)));
      return facts;
    };

    // A project-wide middleware that checks auth covers the routes its matcher selects.
    const middleware = scripts
      .filter((f) => PROJECT_MIDDLEWARE.test(f))
      .map((f) => ({ file: f, code: stripComments(ctx.read(f)) }))
      .filter(({ code }) => LOGIN_CHECKS.some((p) => p.test(code)));
    const scopes = middleware.map(({ code }) => middlewareScope(code));
    const covered = (file: string) => scopes.some((s) => s === "all" || s.some((prefix) => routeUrl(file).startsWith(prefix)));
    // TanStack's start.ts can add auth middleware to every server function.
    const serverFnsCovered = middleware.some(({ file }) => /(?:^|\/)start\.\w+$/.test(file));

    const findings: ScanFinding[] = [];
    for (const file of scripts) {
      const content = ctx.read(file);
      if (HAS_SERVER_FN.test(content)) {
        if (!serverFnsCovered) findings.push(...scanServerFunctions(file, content, helpersFor(file)));
        continue;
      }
      if (!ROUTE_PATHS.some((p) => p.test(file)) || covered(file)) continue;
      const f = scanContent(file, content, helpersFor(file));
      if (f) findings.push(f);
    }
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
  },
};

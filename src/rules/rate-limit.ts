import { basename, extname } from "node:path";
import { isCodeFile } from "../lib/files.js";
import type { ScanFinding, ScannerRule, Severity } from "../types.js";
import { isStripeWebhookHandler, stripComments } from "./stripe-webhook.js";

const RULE_ID = "rate-limit";

const SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
const TEST_FILE = /\.(?:test|spec)\./i;
const TEST_DIRS = new Set(["__tests__", "__mocks__", "test", "tests", "e2e", "cypress"]);

// ── Step A: server endpoints ────────────────────────────────────────────────

// Endpoint files recognized by their path.
const ENDPOINT_PATHS = [
  /(?:^|\/)app\/api\/(?:.+\/)?route\.(?:ts|js|mjs)$/,                // Next.js app router (also src/app)
  /(?:^|\/)pages\/api\//,                                             // Next.js pages router
  /(?:^|\/)routes\/api[/.]/,                                          // TanStack Start: src/routes/api/** and api.x.ts
  /(?:^|\/)supabase\/functions\/(?!_)[^/]+\/index\.(?:ts|js|mjs)$/,   // Supabase edge functions (not _shared)
  /(?:^|\/)netlify\/functions\//,                                     // Netlify functions
  /^api\//,                                                           // Vercel functions: api/ at the project root
];

// Express and Hono servers can live anywhere, so they're recognized by their
// imports plus a route registration such as app.post("/x", ...).
const SERVER_FRAMEWORK = importOf("express|hono(?:/[\\w-]+)?");
const ROUTE_REGISTRATION = /\b(?:app|router|server|api|route)\.(?:get|post|put|patch|delete|all)\s*\(\s*["'`]/;

// Files that apply to every endpoint: Next.js middleware, server entries.
const PROJECT_WIDE = /^(?:src\/|server\/)?(?:_?middleware|server|app|main|index|start)\.(?:ts|js|mjs|cjs)$/;

// Webhooks are called by the provider, not by users.
const SVIX = /\bsvix\b|\bWebhook\s*\(\s*\w*secret/i;
const HMAC = /\bcreateHmac\b|\btimingSafeEqual\b|["'`]HMAC["'`]/;

// ── Step B: costly or sensitive calls ───────────────────────────────────────

/**
 * An import of a package, in any form: import ... from "pkg", import("pkg"),
 * require("pkg"), or a Deno URL such as "npm:pkg@1" or "https://esm.sh/pkg@1".
 */
function importOf(pkg: string): RegExp {
  return new RegExp(
    `(?:\\bfrom|\\bimport|\\brequire)\\s*\\(?\\s*["'\`](?:npm:|jsr:|https?:\\/\\/[^"'\`]*?\\/)?(?:${pkg})(?:@[^"'\`/]*)?(?:\\/[^"'\`]*)?["'\`]`,
  );
}

type Kind = "ai" | "email" | "sms";

interface Provider {
  name: string;
  kind: Kind;
  /** Any of these means the file uses the provider. */
  markers: RegExp[];
  /** The expensive call itself; its line is reported. Falls back to the first marker. */
  calls: RegExp[];
  /** All of these must also be present (for providers whose import alone says little). */
  requires?: RegExp[];
}

const OPENAI_CALLS = [
  /\.(?:chat\.)?completions\.create\s*\(/,
  /\.responses\.(?:create|stream|parse)\s*\(/,
  /\.embeddings\.create\s*\(/,
  /\.images\.(?:generate|edit|createVariation)\s*\(/,
  /\.audio\.\w+\.create\s*\(/,
];
const AI_SDK_CALLS = [/\b(?:generateText|streamText|generateObject|streamObject|embedMany|embed)\s*\(/];

// Messages, calls and sending a Verify code; "VerificationCheck" doesn't match.
const TWILIO_SEND_URL = /api\.twilio\.com|verify\.twilio\.com[^"'`\n]*\/Verifications\b/;

const PROVIDERS: Provider[] = [
  {
    name: "OpenAI",
    kind: "ai",
    markers: [importOf("openai|@ai-sdk/openai"), /api\.openai\.com/, /\bnew\s+OpenAI\s*\(/],
    calls: [/api\.openai\.com/, ...OPENAI_CALLS, ...AI_SDK_CALLS],
  },
  {
    name: "Anthropic",
    kind: "ai",
    markers: [importOf("@anthropic-ai/sdk|@ai-sdk/anthropic"), /api\.anthropic\.com/, /\bnew\s+Anthropic\s*\(/],
    calls: [/api\.anthropic\.com/, /\.messages\.(?:create|stream)\s*\(/, ...AI_SDK_CALLS],
  },
  {
    name: "Google Gemini",
    kind: "ai",
    markers: [
      importOf("@google/generative-ai|@google/genai|@ai-sdk/google"),
      /generativelanguage\.googleapis\.com/,
      /\bnew\s+GoogleGenerativeAI\s*\(|\bnew\s+GoogleGenAI\s*\(/,
    ],
    calls: [/generativelanguage\.googleapis\.com/, /\bgenerateContent(?:Stream)?\s*\(/, ...AI_SDK_CALLS],
  },
  {
    name: "Replicate",
    kind: "ai",
    markers: [importOf("replicate"), /api\.replicate\.com/, /\bnew\s+Replicate\s*\(/],
    calls: [/api\.replicate\.com/, /\.(?:run|stream)\s*\(/, /\.predictions\.create\s*\(/],
  },
  {
    name: "ElevenLabs",
    kind: "ai",
    markers: [importOf("elevenlabs|@elevenlabs/[\\w-]+"), /api\.elevenlabs\.io/, /\bnew\s+ElevenLabsClient\s*\(/],
    calls: [/api\.elevenlabs\.io/, /\.textToSpeech\.\w+\s*\(/, /\.generate\s*\(/],
  },
  {
    // The Vercel AI SDK on its own (its provider packages are matched above).
    name: "the Vercel AI SDK",
    kind: "ai",
    markers: [importOf("ai")],
    requires: AI_SDK_CALLS,
    calls: AI_SDK_CALLS,
  },
  {
    name: "Resend",
    kind: "email",
    markers: [importOf("resend"), /api\.resend\.com/, /\bnew\s+Resend\s*\(/],
    calls: [/api\.resend\.com/, /\.emails\.send\s*\(/, /\.batch\.send\s*\(/],
  },
  {
    name: "SendGrid",
    kind: "email",
    markers: [importOf("@sendgrid/mail"), /api\.sendgrid\.com/],
    calls: [/api\.sendgrid\.com/, /\.send(?:Multiple)?\s*\(/],
  },
  {
    name: "Nodemailer",
    kind: "email",
    markers: [importOf("nodemailer")],
    calls: [/\.sendMail\s*\(/],
  },
  {
    name: "Postmark",
    kind: "email",
    markers: [importOf("postmark"), /api\.postmarkapp\.com/],
    calls: [/api\.postmarkapp\.com/, /\.sendEmail(?:WithTemplate|Batch)?\s*\(/],
  },
  {
    // Only calls that send something. Checking a code (Verify's VerificationCheck,
    // verificationChecks.create) sends nothing, so it doesn't count.
    name: "Twilio",
    kind: "sms",
    markers: [importOf("twilio"), TWILIO_SEND_URL],
    requires: [new RegExp(`${TWILIO_SEND_URL.source}|\\.(?:messages|verifications|calls)\\.create\\s*\\(`)],
    calls: [TWILIO_SEND_URL, /\.(?:messages|verifications|calls)\.create\s*\(/],
  },
  {
    name: "Vonage",
    kind: "sms",
    markers: [importOf("@vonage/server-sdk|nexmo"), /(?:rest|api)\.nexmo\.com/],
    calls: [/(?:rest|api)\.nexmo\.com/, /\.sms\.send\s*\(/, /\.verify\.start\s*\(/],
  },
  {
    name: "MessageBird",
    kind: "sms",
    markers: [importOf("messagebird")],
    calls: [/\.messages\.create\s*\(/],
  },
  {
    name: "Plivo",
    kind: "sms",
    markers: [importOf("plivo")],
    calls: [/\.messages\.create\s*\(/],
  },
  {
    name: "Telnyx",
    kind: "sms",
    markers: [importOf("telnyx"), /api\.telnyx\.com/],
    calls: [/api\.telnyx\.com/, /\.messages\.create\s*\(/],
  },
  {
    name: "AWS SNS",
    kind: "sms",
    markers: [importOf("@aws-sdk/client-sns")],
    calls: [/\bnew\s+PublishCommand\s*\(/],
  },
];

// A custom login/signup/password-reset handler: an auth-sounding endpoint path
// plus its own password hashing or token signing. Supabase Auth (supabase.auth.*)
// has Supabase's own limits, so a handler that only calls it isn't flagged.
const AUTH_PATH =
  /(?:^|[/._-])(?:log-?in|sign-?in|sign-?up|register|(?:reset|forgot|change)-?password|password-?reset|otp|verify-?otp|magic-?link)(?:[/._-]|$)/i;
const AUTH_LOGIC = [/\b(?:bcrypt|argon2|scrypt|pbkdf2)\w*\b/i, /\bjwt\.sign\s*\(/, /\bnew\s+SignJWT\s*\(/];

// Ways an endpoint checks who is calling it.
export const LOGIN_CHECKS = [
  /\.auth\.(?:getUser|getSession|getClaims)\s*\(/,
  /\brequire\w*Auth\w*\b/i,
  /\bwithAuth\b/,
  /\bgetServerSession\s*\(/,
  /\b(?:auth|getAuth|currentUser)\s*\(/,
  /\bjwt\.verify\s*\(|\bjwtVerify\s*\(|\bverifyIdToken\s*\(/,
  // Shared helpers such as getAuthedUser(req), getCurrentUser(), verifyAuth(req), ensureUser().
  /\b(?:get|require|verify|check|ensure|validate)(?:Authed|Authenticated|Current|SignedIn|LoggedIn)?(?:User|Session|Auth)\s*\(/i,
  // Reading the caller's Authorization header (not setting one on an outgoing call).
  /headers\.get\s*\(\s*["'`]authorization["'`]/i,
  /headers\s*\[\s*["'`]authorization["'`]\s*\]/i,
  /headers\.authorization\b/i,
];

// ── Step C: rate limiting ───────────────────────────────────────────────────

const RATE_LIMIT_PACKAGE = importOf(
  "@upstash/ratelimit|express-rate-limit|rate-limiter-flexible|hono-rate-limiter|@hono-rate-limiter/[\\w-]+",
);
// A helper whose name contains "ratelimit" (any case, rate_limit too), called,
// used as a method target or passed as an argument: rateLimit(ip),
// ratelimit.limit(ip), app.use(rateLimiter). Matched with strings blanked out,
// so an error message such as "Rate limit exceeded" doesn't count.
const RATE_LIMIT_HELPER = /\b[\w$]*rate_?limit[\w$]*\s*[(.,)\]]/i;
// A database function such as supabase.rpc("check_rate_limit", ...).
const RATE_LIMIT_RPC = /\.rpc\s*\(\s*["'`][\w.]*rate_?limit[\w.]*["'`]/i;
const STATUS_429 = /(?:\bstatus(?:Code)?\s*[:=(]\s*|,\s*)429\b/;
const REQUEST_COUNTING = [
  /\.incr(?:by)?\s*\(/i,
  /\b\w*(?:count|hits|requests|attempts|calls)\w*\s*(?:\+\+|\+=)/i,
  /\b\w*(?:count|hits|requests|attempts|calls)\w*\b[^;\n]*\+\s*1\b/i, // count = (map.get(ip) ?? 0) + 1
];

// ── Findings ────────────────────────────────────────────────────────────────

const FIX =
  "Add a per-user or per-IP rate limit before the expensive call (for example @upstash/ratelimit), and require login for anything that costs money.";

/** Replaces the contents of quoted strings with spaces, keeping line breaks. */
function blankStrings(code: string): string {
  return code.replace(/"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`/g, (s) => s.replace(/[^\n]/g, " "));
}

const isTestFile = (file: string) => TEST_FILE.test(file) || file.split("/").some((part) => TEST_DIRS.has(part));

/** Whether the code applies a rate limit (call on comment-stripped code). */
export function hasRateLimit(code: string): boolean {
  if (RATE_LIMIT_PACKAGE.test(code) || RATE_LIMIT_RPC.test(code)) return true;
  if (RATE_LIMIT_HELPER.test(blankStrings(code))) return true;
  return STATUS_429.test(code) && REQUEST_COUNTING.some((p) => p.test(code));
}

export function isEndpoint(file: string, code: string): boolean {
  if (/^\s*["']use client["']/m.test(code)) return false;
  if (ENDPOINT_PATHS.some((p) => p.test(file))) return true;
  return SERVER_FRAMEWORK.test(code) && ROUTE_REGISTRATION.test(code);
}

function isWebhook(file: string, content: string, code: string): boolean {
  return isStripeWebhookHandler(file, content) || SVIX.test(code) || HMAC.test(code);
}

const IMPORT_LINE = /^\s*(?:import\b|(?:const|let|var)\s+[\w{}\s,]+=\s*require\s*\()/;

/** The first line matching a pattern, preferring lines that aren't imports. */
function firstLine(lines: string[], patterns: RegExp[]): number {
  const matches = (line: string) => patterns.some((p) => p.test(line));
  const code = lines.findIndex((line) => !IMPORT_LINE.test(line) && matches(line));
  return code !== -1 ? code : lines.findIndex(matches);
}

interface Hit {
  provider: Provider;
  line: number; // 0-based
}

function findCall(provider: Provider, code: string, lines: string[]): Hit | undefined {
  if (!provider.markers.some((p) => p.test(code))) return undefined;
  if (provider.requires && !provider.requires.every((p) => p.test(code))) return undefined;
  let line = firstLine(lines, provider.calls);
  if (line === -1) line = firstLine(lines, provider.markers);
  return { provider, line: Math.max(fetchLineFor(lines, line), 0) };
}

const FETCH_CALL = /\bfetch\s*\(/;

/**
 * When the matched line only holds the API URL (const url = "https://api..."),
 * the expensive call is the fetch that follows, usually a few lines later.
 */
function fetchLineFor(lines: string[], line: number): number {
  if (line < 0 || IMPORT_LINE.test(lines[line]) || FETCH_CALL.test(lines[line])) return line;
  if (!/https?:\/\/|\.(?:com|io)\b/.test(lines[line])) return line;
  for (let i = line + 1; i < Math.min(lines.length, line + 25); i++) {
    if (FETCH_CALL.test(lines[i])) return i;
  }
  return line;
}

function message(hit: Hit, loginRequired: boolean): string {
  const { name, kind } = hit.provider;
  if (kind === "ai") {
    const text = `This endpoint calls ${name} with no rate limit: anyone can call it in a loop and run up your AI bill.`;
    return loginRequired ? text : `${text} It also doesn't require login.`;
  }
  if (kind === "email") {
    return `This endpoint sends email through ${name} with no rate limit: anyone can call it in a loop to spam people and run up your email bill.`;
  }
  return `This endpoint sends SMS through ${name} with no rate limit: anyone can call it in a loop and run up your SMS bill.`;
}

/**
 * The finding for one file, or undefined. `projectRateLimited` is true when a
 * project-wide middleware or server entry already applies a rate limit.
 */
export function scanContent(file: string, content: string, projectRateLimited = false): ScanFinding | undefined {
  if (projectRateLimited || isTestFile(file)) return undefined;

  const code = stripComments(content);
  if (!isEndpoint(file, code) || isWebhook(file, content, code) || hasRateLimit(code)) return undefined;

  const lines = code.split(/\r?\n/);
  const hits = PROVIDERS.map((p) => findCall(p, code, lines)).filter((h): h is Hit => h !== undefined);
  const byLine = (a: Hit, b: Hit) => a.line - b.line;
  const ai = hits.filter((h) => h.provider.kind === "ai").sort(byLine)[0];
  const other = hits.filter((h) => h.provider.kind !== "ai").sort(byLine)[0];

  const finding = (severity: Severity, line: number, text: string): ScanFinding => ({
    ruleId: RULE_ID,
    // Not in CONTRACT v1 yet: proposed to Hilal for the "Proposed" section.
    fixId: "SEC_API_NO_RATE_LIMIT",
    category: "security",
    title: "Endpoint has no rate limit",
    confidence: "medium",
    severity,
    file,
    line: line + 1,
    message: text,
    fix: FIX,
  });

  if (ai) return finding("high", ai.line, message(ai, LOGIN_CHECKS.some((p) => p.test(code))));
  if (other) return finding("medium", other.line, message(other, true));

  const authLine = AUTH_PATH.test(file) ? firstLine(lines, AUTH_LOGIC) : -1;
  if (authLine !== -1) {
    return finding(
      "medium",
      authLine,
      "This login/signup endpoint has no rate limit: anyone can try passwords or create accounts in a loop.",
    );
  }
  return undefined;
}

const isScriptFile = (name: string) => isCodeFile(name) && SCRIPT_EXTENSIONS.has(extname(name).toLowerCase());

/**
 * Whether the file is an endpoint this check cares about (calls a paid AI,
 * email or SMS API, or is a login/signup endpoint), rate limited or not.
 */
export function isSensitiveEndpoint(file: string, content: string): boolean {
  if (isTestFile(file)) return false;
  const code = stripComments(content);
  if (!isEndpoint(file, code) || isWebhook(file, content, code)) return false;
  const lines = code.split(/\r?\n/);
  return PROVIDERS.some((p) => findCall(p, code, lines) !== undefined) || (AUTH_PATH.test(file) && firstLine(lines, AUTH_LOGIC) !== -1);
}

export const rateLimitRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Rate limits on paid and sensitive endpoints",
  passedLabel: "Paid and sensitive endpoints are rate limited",
  jsOnly: true,
  notApplicable: (ctx) =>
    ctx.files.some((file) => isScriptFile(basename(file)) && isSensitiveEndpoint(file, ctx.read(file)))
      ? undefined
      : "no paid or sensitive endpoints found",
  run(ctx) {
    const files: { file: string; content: string }[] = [];
    let projectRateLimited = false;

    for (const file of ctx.files) {
      if (!isScriptFile(basename(file))) continue;
      const content = ctx.read(file);
      if (PROJECT_WIDE.test(file) && hasRateLimit(stripComments(content))) projectRateLimited = true;
      // Keep only possible endpoints; scanContent decides once the whole project is read.
      if (ENDPOINT_PATHS.some((p) => p.test(file)) || SERVER_FRAMEWORK.test(content)) files.push({ file, content });
    }

    const findings: ScanFinding[] = [];
    for (const { file, content } of files) {
      const finding = scanContent(file, content, projectRateLimited);
      if (finding) findings.push(finding);
    }
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? ""));
  },
};

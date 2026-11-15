import { basename, extname } from "node:path";
import { isCodeFile } from "../lib/files.js";
import type { ScanFinding, ScannerRule } from "../types.js";

const RULE_ID = "stripe-webhook";

const SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"]);
const TEST_FILE = /\.(?:test|spec)\./i;

// A quoted Stripe event name, e.g. "checkout.session.completed" or 'invoice.paid'.
// The quotes keep code like `invoice.status` from counting.
const EVENT_NAME = /["'`](?:checkout\.session|customer\.subscription|invoice|payment_intent|charge)\.[a-z_.]+["'`]/;

// Other providers reuse names like "charge.success" (Paystack), so the file
// or its path must also mention Stripe: an import of "stripe", api.stripe.com,
// "stripe-signature", a stripe-webhook route, or constructEvent.
const STRIPE_MARKER = /stripe|constructEvent/i;

// Reading the body of an incoming request. Every pattern needs req/request
// (or a raw-body helper), so reading a response with res.json() doesn't count.
const BODY_READS = [
  /\b(?:request|req)\.(?:json|text|arrayBuffer|formData|blob)\s*\(/, // fetch-style: Next app router, TanStack, Deno, Hono
  /\b(?:request|req)\.(?:body|rawBody)\b/,                           // Express, Next pages/api
  /\.arrayBuffer\s*\(/,
  /\b(?:buffer|getRawBody|json|text)\s*\(\s*(?:req|request)\b/,     // micro / raw-body helpers
  /\bread(?:Raw)?Body\s*\(/,                                         // Nitro/h3: readBody, readRawBody
];

const CONSTRUCT_EVENT = /\bconstructEvent(?:Async)?\b/;
const SIGNATURE_HEADER = /["'`]stripe-signature["'`]/i;
const HMAC = [/\bcreateHmac\b/, /\btimingSafeEqual\b/];
const SUBTLE = /\bcrypto\.subtle\b/;
const HMAC_NAME = /["'`]HMAC["'`]/;
const VERIFY_CALL = /\w*verify\w*\s*\(/i;

const MESSAGE = "Anyone can send a fake 'payment completed' event and unlock paid features for free.";
const FIX =
  "Verify the stripe-signature header with stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET) before trusting the event. Use the raw request body, not parsed JSON.";

/**
 * Removes /* *\/ blocks and lines that start with //, so commented-out
 * verification doesn't count. Quoted strings are skipped over, so "/*" or
 * "//" inside a string (a glob, a URL) is left alone. Newlines are kept.
 */
export function stripComments(code: string): string {
  let out = "";
  let quote: string | null = null;
  let lineStart = true; // only whitespace so far on this line

  for (let i = 0; i < code.length; i++) {
    const c = code[i];

    if (quote) {
      out += c;
      if (c === "\\") {
        out += code[++i] ?? "";
      } else if (c === quote || (c === "\n" && quote !== "`")) {
        // '...' and "..." can't span lines, so a stray apostrophe ends at the newline.
        quote = null;
        lineStart = c === "\n";
      }
      continue;
    }

    if (c === "/" && code[i + 1] === "/" && lineStart) {
      const end = code.indexOf("\n", i);
      if (end === -1) break;
      i = end - 1;
      continue;
    }

    if (c === "/" && code[i + 1] === "*") {
      const end = code.indexOf("*/", i + 2);
      const block = end === -1 ? code.slice(i) : code.slice(i, end + 2);
      out += block.replace(/[^\n]/g, "");
      i += block.length - 1;
      continue;
    }

    if (c === '"' || c === "'" || c === "`") quote = c;
    if (c === "\n") lineStart = true;
    else if (!/\s/.test(c)) lineStart = false;
    out += c;
  }
  return out;
}

export function isVerified(code: string): boolean {
  const text = stripComments(code);
  if (CONSTRUCT_EVENT.test(text)) return true;
  if (!SIGNATURE_HEADER.test(text)) return false;

  const hmac = HMAC.some((p) => p.test(text)) || (SUBTLE.test(text) && HMAC_NAME.test(text));
  return hmac || VERIFY_CALL.test(text);
}

/** The 0-based line where the body is read, or -1 if the file isn't a Stripe webhook handler (verified or not). */
function handlerBodyLine(file: string, content: string): number {
  if (!EVENT_NAME.test(content)) return -1;
  if (!STRIPE_MARKER.test(file) && !STRIPE_MARKER.test(content)) return -1;
  return content.split(/\r?\n/).findIndex((line) => BODY_READS.some((p) => p.test(line)));
}

/** Whether this check treats the file as a Stripe webhook handler, verified or not. */
export const isStripeWebhookHandler = (file: string, content: string) => handlerBodyLine(file, content) !== -1;

/** The finding for one file, or undefined if it isn't an unverified Stripe webhook handler. */
export function scanContent(file: string, content: string): ScanFinding | undefined {
  const bodyLine = handlerBodyLine(file, content);
  if (bodyLine === -1 || isVerified(content)) return undefined;

  return {
    ruleId: RULE_ID,
    fixId: "SEC_STRIPE_WEBHOOK_UNSIGNED",
    category: "security",
    title: "Stripe webhook doesn't verify signatures",
    confidence: "medium",
    severity: "critical",
    file,
    line: bodyLine + 1,
    message: MESSAGE,
    fix: FIX,
  };
}

const isScriptFile = (name: string) =>
  isCodeFile(name) && SCRIPT_EXTENSIONS.has(extname(name).toLowerCase()) && !TEST_FILE.test(name);

/** The files this check reads: script files outside tests. */
const handlerFiles = (files: string[]) =>
  files.filter((file) => isScriptFile(basename(file)) && !file.split("/").includes("__tests__"));

export const stripeWebhookRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Stripe webhook signature verification",
  passedLabel: "Stripe webhooks verify signatures",
  jsOnly: true,
  notApplicable: (ctx) =>
    handlerFiles(ctx.files).some((file) => isStripeWebhookHandler(file, ctx.read(file))) ? undefined : "no Stripe webhook found",
  run(ctx) {
    const findings: ScanFinding[] = [];
    for (const file of handlerFiles(ctx.files)) {
      const finding = scanContent(file, ctx.read(file));
      if (finding) findings.push(finding);
    }
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? ""));
  },
};

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import { isCodeFile, toProjectPath, walkFiles } from "../lib/files.js";
import type { Check, Finding } from "../types.js";

const CHECK_ID = "stripe-webhook";

const SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"]);
const TEST_FILE = /\.(?:test|spec)\./i;

// A quoted Stripe event name, e.g. "checkout.session.completed" or 'invoice.paid'.
// The quotes keep code like `invoice.status` from counting.
const EVENT_NAME = /["'`](?:checkout\.session|customer\.subscription|invoice|payment_intent|charge)\.[a-z_.]+["'`]/;

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

const MESSAGE =
  "Stripe webhook doesn't verify signatures: anyone can send a fake 'payment completed' event and unlock paid features for free";
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

/** The finding for one file, or undefined if it isn't an unverified Stripe webhook handler. */
export function scanContent(file: string, content: string): Finding | undefined {
  if (!EVENT_NAME.test(content)) return undefined;

  const lines = content.split(/\r?\n/);
  const bodyLine = lines.findIndex((line) => BODY_READS.some((p) => p.test(line)));
  if (bodyLine === -1 || isVerified(content)) return undefined;

  return { checkId: CHECK_ID, severity: "critical", file, line: bodyLine + 1, message: MESSAGE, fix: FIX };
}

const isScriptFile = (name: string) =>
  isCodeFile(name) && SCRIPT_EXTENSIONS.has(extname(name).toLowerCase()) && !TEST_FILE.test(name);

export const stripeWebhookCheck: Check = {
  id: CHECK_ID,
  name: "Stripe webhook signature verification",
  passedLabel: "Stripe webhooks verify signatures",
  severity: "critical",
  async run(projectPath, context) {
    const findings: Finding[] = [];
    for await (const filePath of walkFiles(projectPath, isScriptFile, context)) {
      const file = toProjectPath(projectPath, filePath);
      if (file.split("/").includes("__tests__")) continue;

      const finding = scanContent(file, await readFile(filePath, "utf8"));
      if (finding) findings.push(finding);
    }
    return findings.sort((a, b) => a.file.localeCompare(b.file));
  },
};

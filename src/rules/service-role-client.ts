import { basename } from "node:path";
import { isCodeFile, isEnvFile } from "../lib/files.js";
import { frontendFiles } from "../lib/frontend.js";
import { mask } from "../lib/mask.js";
import { isServiceRoleJwt, JWT_REGEX, KEY_PATTERNS, secretEnvId, secretValueId } from "../lib/patterns.js";
import type { ScanFinding, ScannerRule } from "../types.js";
import { isExampleEnvFile, parseEnv } from "./committed-env.js";
import { usesSupabase } from "./supabase-rls.js";

const RULE_ID = "service-role-client";

// Any env read: import.meta.env.X, import.meta.env["X"], process.env.X, process.env["X"].
// The name ends up in group 2 or 3.
const ENV_READ = /(import\.meta\.env|process\.env)(?:\.(\w+)|\[\s*["'](\w+)["']\s*\])/g;
// The legacy service_role key, or Supabase's new secret key (SUPABASE_SECRET_KEY / SUPABASE_SECRET_KEYS).
// Both skip Row Level Security, so both are treated the same. Publishable keys are public and never match.
const SERVICE_ROLE_NAME = /SERVICE_?ROLE|SUPABASE_?SECRET_?KEYS?$/i;
const PUBLIC_PREFIX = /^(?:VITE_|NEXT_PUBLIC_)/;
// sb_secret_... (same pattern the leaked-keys rule uses).
const SUPABASE_SECRET_SOURCE = KEY_PATTERNS.find((p) => p.name === "Supabase secret key")!.regex.source;

/** "secret key" for the new sb_secret_ keys and their env names, "service_role key" for the legacy one. */
const keyKind = (nameOrValue: string) =>
  /SERVICE_?ROLE/i.test(nameOrValue) || nameOrValue.startsWith("eyJ") ? "service_role key" : "secret key";

/** A value that skips Row Level Security: a service_role JWT or an sb_secret_ key. */
const isAdminKeyValue = (value: string) =>
  new RegExp(`^${SUPABASE_SECRET_SOURCE}$`).test(value) || (value.startsWith("eyJ") && isServiceRoleJwt(value));

const FIX =
  "Use the anon or publishable key in the browser. Keep the service_role key in server-only code (an API route or server function) and rotate it now.";
const WHY = "it skips Row Level Security, so anyone can read or change every table";
const WHY_KEY = "skips Row Level Security, so anyone who opens the site can read or change every table";

const finding = (
  file: string,
  line: number,
  message: string,
  confidence: "high" | "medium",
  secretIds: string[],
  fix = FIX,
): ScanFinding => ({
  ruleId: RULE_ID,
  fixId: "SEC_SUPABASE_SERVICE_ROLE_CLIENT",
  category: "security",
  title: "Supabase service_role key in frontend code",
  severity: "critical",
  confidence,
  secretIds,
  file,
  line,
  message,
  fix,
});

// The .env line wins over the client-exposed finding on the same line, so it carries the prefix advice too.
const prefixFix = (name: string) => {
  const prefix = PUBLIC_PREFIX.exec(name)![0];
  return `${FIX} ${prefix === "VITE_" ? "Vite" : "Next.js"} ships every ${prefix} variable to the browser, so drop the ${prefix} prefix.`;
};

/** service_role JWTs, sb_secret_ keys and SERVICE_ROLE / SUPABASE_SECRET_KEY env reads in a file the browser runs. */
export function scanFrontendFile(file: string, content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  content.split(/\r?\n/).forEach((text, index) => {
    for (const [token] of text.matchAll(JWT_REGEX)) {
      if (isServiceRoleJwt(token)) {
        findings.push(finding(file, index + 1, `The key ${mask(token)} ${WHY_KEY}.`, "high", [secretValueId(token)]));
      }
    }
    for (const [key] of text.matchAll(new RegExp(SUPABASE_SECRET_SOURCE, "g"))) {
      findings.push(finding(file, index + 1, `The Supabase secret key ${mask(key)} ${WHY_KEY}.`, "high", [secretValueId(key)]));
    }
    for (const match of text.matchAll(ENV_READ)) {
      const name = match[2] ?? match[3];
      if (SERVICE_ROLE_NAME.test(name) && !PUBLIC_PREFIX.test(name)) {
        findings.push(finding(file, index + 1, `Frontend code reads the Supabase ${keyKind(name)} (${match[1]}.${name}): ${WHY}.`, "medium", [secretEnvId(name)]));
      }
    }
  });
  return findings;
}

/** VITE_ / NEXT_PUBLIC_ service_role / secret key variables, wherever they're read: the bundler ships them. */
export function scanPublicEnvReads(file: string, content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  content.split(/\r?\n/).forEach((text, index) => {
    for (const match of text.matchAll(ENV_READ)) {
      const name = match[2] ?? match[3];
      if (SERVICE_ROLE_NAME.test(name) && PUBLIC_PREFIX.test(name)) {
        findings.push(finding(file, index + 1, `The Supabase ${keyKind(name)} is shipped to the browser (${match[1]}.${name}): ${WHY}.`, "high", [secretEnvId(name)]));
      }
    }
  });
  return findings;
}

/** .env lines that put a service_role or sb_secret_ key in a VITE_ / NEXT_PUBLIC_ variable, whatever its name. */
export function scanPublicEnvValues(file: string, content: string): ScanFinding[] {
  if (isExampleEnvFile(basename(file))) return [];
  return parseEnv(content)
    .filter((entry) => PUBLIC_PREFIX.test(entry.name) && isAdminKeyValue(entry.value))
    .map((entry) =>
      finding(
        file,
        entry.line,
        `The Supabase ${keyKind(entry.value)} is shipped to the browser (${entry.name}=${mask(entry.value)}): ${WHY}.`,
        "high",
        [secretValueId(entry.value), secretEnvId(entry.name)],
        prefixFix(entry.name),
      ),
    );
}


export const serviceRoleClientRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Supabase service_role key in frontend code",
  passedLabel: "No Supabase service_role key in frontend code",
  jsOnly: true,
  notApplicable: (ctx) => (usesSupabase(ctx) ? undefined : "no Supabase found"),
  run(ctx) {
    const findings: ScanFinding[] = [];
    for (const file of ctx.files) {
      const name = basename(file);
      if (isEnvFile(name)) findings.push(...scanPublicEnvValues(file, ctx.read(file)));
      else if (isCodeFile(name)) findings.push(...scanPublicEnvReads(file, ctx.read(file)));
    }
    for (const { file, content } of frontendFiles(ctx)) findings.push(...scanFrontendFile(file, content));
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
  },
};

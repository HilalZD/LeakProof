import { basename } from "node:path";
import { isCodeFile } from "../lib/files.js";
import { frontendFiles } from "../lib/frontend.js";
import { mask } from "../lib/mask.js";
import { isServiceRoleJwt, JWT_REGEX, secretEnvId, secretValueId } from "../lib/patterns.js";
import type { ScanFinding, ScannerRule } from "../types.js";
import { usesSupabase } from "./supabase-rls.js";

const RULE_ID = "service-role-client";

// Any env read: import.meta.env.X, import.meta.env["X"], process.env.X, process.env["X"].
// The name ends up in group 2 or 3.
const ENV_READ = /(import\.meta\.env|process\.env)(?:\.(\w+)|\[\s*["'](\w+)["']\s*\])/g;
const SERVICE_ROLE_NAME = /SERVICE_?ROLE/i;
const PUBLIC_PREFIX = /^(?:VITE_|NEXT_PUBLIC_)/;

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
  fix: FIX,
});

/** service_role JWTs and SERVICE_ROLE env reads in a file the browser runs. */
export function scanFrontendFile(file: string, content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  content.split(/\r?\n/).forEach((text, index) => {
    for (const [token] of text.matchAll(JWT_REGEX)) {
      if (isServiceRoleJwt(token)) {
        findings.push(finding(file, index + 1, `The key ${mask(token)} ${WHY_KEY}.`, "high", [secretValueId(token)]));
      }
    }
    for (const match of text.matchAll(ENV_READ)) {
      const name = match[2] ?? match[3];
      if (SERVICE_ROLE_NAME.test(name) && !PUBLIC_PREFIX.test(name)) {
        findings.push(finding(file, index + 1, `Frontend code reads the Supabase service_role key (${match[1]}.${name}): ${WHY}.`, "medium", [secretEnvId(name)]));
      }
    }
  });
  return findings;
}

/** VITE_ / NEXT_PUBLIC_ service_role variables, wherever they're read: the bundler ships them. */
export function scanPublicEnvReads(file: string, content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  content.split(/\r?\n/).forEach((text, index) => {
    for (const match of text.matchAll(ENV_READ)) {
      const name = match[2] ?? match[3];
      if (SERVICE_ROLE_NAME.test(name) && PUBLIC_PREFIX.test(name)) {
        findings.push(finding(file, index + 1, `The Supabase service_role key is shipped to the browser (${match[1]}.${name}): ${WHY}.`, "high", [secretEnvId(name)]));
      }
    }
  });
  return findings;
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
      if (isCodeFile(basename(file))) findings.push(...scanPublicEnvReads(file, ctx.read(file)));
    }
    for (const { file, content } of frontendFiles(ctx)) findings.push(...scanFrontendFile(file, content));
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
  },
};

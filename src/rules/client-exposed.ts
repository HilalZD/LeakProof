import { basename } from "node:path";
import { frontendFiles } from "../lib/frontend.js";
import { isCodeFile, isEnvFile } from "../lib/files.js";
import { mask } from "../lib/mask.js";
import { findSecretKeys, isTestKey, secretEnvId, secretValueId, SERVICE_ROLE_JWT } from "../lib/patterns.js";
import type { ProjectContext, ScanFinding, ScannerRule, Severity } from "../types.js";
import { classify, isExampleEnvFile, parseEnv } from "./committed-env.js";

const RULE_ID = "client-exposed";
const BASE = { ruleId: RULE_ID, fixId: "SEC_SECRET_CLIENT_EXPOSED", category: "security" } as const;
const TITLE = "Secret key exposed to the browser";

// Variables with these prefixes are copied into the browser bundle.
const PUBLIC_PREFIX = /^(VITE_|NEXT_PUBLIC_)(.+)$/;
const FRAMEWORK: Record<string, string> = { VITE_: "Vite", NEXT_PUBLIC_: "Next.js" };

// import.meta.env.VITE_X, import.meta.env["VITE_X"], process.env.NEXT_PUBLIC_X,
// process.env["NEXT_PUBLIC_X"]. The name ends up in group 2 or 3.
const ENV_READ =
  /(import\.meta\.env|process\.env)(?:\.((?:VITE_|NEXT_PUBLIC_)\w+)|\[\s*["']((?:VITE_|NEXT_PUBLIC_)\w+)["']\s*\])/g;
const SECRET_NAME_PARTS = ["SECRET", "SERVICE_ROLE", "PRIVATE", "PASSWORD"];
// Firebase web config is public by design.
const PUBLIC_BY_DESIGN = /FIREBASE/i;

/** Live keys are critical; test keys (sk_test_, rk_test_) can't move real money, so they're high. */
const severityOf = (value: string): Severity => (isTestKey(value) ? "high" : "critical");

export interface ExposedEnvValue {
  masked: string;
  severity: Severity;
  /** In memory only: the hash identity of the value. */
  valueId: string;
}

/** Secret values of VITE_ / NEXT_PUBLIC_ variables in the project's .env files (not example files). */
export function exposedEnvValues(ctx: ProjectContext): Map<string, ExposedEnvValue> {
  const values = new Map<string, ExposedEnvValue>();
  for (const file of ctx.files) {
    const name = basename(file);
    if (!isEnvFile(name) || isExampleEnvFile(name)) continue;
    for (const entry of parseEnv(ctx.read(file))) {
      const secret = exposedSecret(entry.name, entry.value);
      if (secret && !values.has(entry.name)) values.set(entry.name, secret);
    }
  }
  return values;
}

function exposedSecret(name: string, value: string): ExposedEnvValue | undefined {
  const prefixed = PUBLIC_PREFIX.exec(name);
  if (!prefixed || PUBLIC_BY_DESIGN.test(name)) return undefined;
  // Classify without the prefix: NEXT_PUBLIC_ contains "PUBLIC", which would read as a safe name.
  const secret = classify({ line: 0, name: prefixed[2], value }, false);
  return secret ? { masked: secret.masked, severity: severityOf(secret.value), valueId: secretValueId(secret.value) } : undefined;
}

const fixFor = (name: string) => {
  const [, prefix, rest] = PUBLIC_PREFIX.exec(name)!;
  return `${FRAMEWORK[prefix]} ships every ${prefix} variable to the browser: drop the ${prefix} prefix, use ${rest} only in server-side code, and rotate it.`;
};

/** .env lines that put a secret in a VITE_ / NEXT_PUBLIC_ variable. */
export function scanEnvFile(file: string, content: string): ScanFinding[] {
  if (isExampleEnvFile(basename(file))) return [];
  const findings: ScanFinding[] = [];
  for (const entry of parseEnv(content)) {
    const secret = exposedSecret(entry.name, entry.value);
    if (!secret) continue;
    findings.push({
      ...BASE,
      title: TITLE,
      confidence: "high",
      severity: secret.severity,
      secretIds: [secret.valueId, secretEnvId(entry.name)],
      file,
      line: entry.line,
      message: `${entry.name} is shipped to the browser: ${secret.masked}`,
      fix: fixFor(entry.name),
    });
  }
  return findings;
}

/**
 * Code that reads a VITE_ / NEXT_PUBLIC_ variable holding a secret: either its
 * name says so, or its value in .env is one. A secret name with no known value
 * is reported as high with medium confidence: it could be a test key.
 */
export function scanEnvReads(file: string, content: string, envValues = new Map<string, ExposedEnvValue>()): ScanFinding[] {
  const findings: ScanFinding[] = [];
  content.split(/\r?\n/).forEach((text, index) => {
    for (const match of text.matchAll(ENV_READ)) {
      const name = match[2] ?? match[3];
      if (PUBLIC_BY_DESIGN.test(name)) continue;
      const known = envValues.get(name);
      const secretName = SECRET_NAME_PARTS.some((part) => name.toUpperCase().includes(part));
      if (!known && !secretName) continue;

      const framework = name.startsWith("VITE_") ? "Vite" : "Next.js";
      findings.push({
        ...BASE,
        title: TITLE,
        confidence: known ? "high" : "medium",
        severity: known?.severity ?? "high",
        secretIds: [secretEnvId(name)], // a read, not the value: grouped by name
        file,
        line: index + 1,
        message: `${match[1]}.${name} holds a secret, and ${framework} puts it in the browser bundle.`,
        fix: fixFor(name),
      });
    }
  });
  return findings;
}

/** Secret keys written directly in a file the browser runs. service_role keys have their own rule. */
export function scanFrontendFile(file: string, content: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  content.split(/\r?\n/).forEach((text, index) => {
    for (const { pattern, value } of findSecretKeys(text)) {
      if (pattern === SERVICE_ROLE_JWT) continue;
      findings.push({
        ...BASE,
        title: TITLE,
        confidence: "high",
        severity: severityOf(value),
        secretIds: [secretValueId(value)],
        file,
        line: index + 1,
        message: `${pattern.name} in frontend code, so anyone can copy it from the browser: ${mask(value)}`,
        fix: pattern.fix,
      });
    }
  });
  return findings;
}

const byLocation = (a: ScanFinding, b: ScanFinding) =>
  (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0);

export const clientExposedRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Secret keys the browser can reach",
  passedLabel: "No secret keys reachable from the browser",
  jsOnly: true,
  notApplicable: (ctx) =>
    ctx.files.some((file) => isEnvFile(basename(file))) || frontendFiles(ctx).length > 0 ? undefined : "no frontend code or .env files found",
  run(ctx) {
    const envValues = exposedEnvValues(ctx);
    const findings: ScanFinding[] = [];
    for (const file of ctx.files) {
      const name = basename(file);
      if (isEnvFile(name)) findings.push(...scanEnvFile(file, ctx.read(file)));
      else if (isCodeFile(name)) findings.push(...scanEnvReads(file, ctx.read(file), envValues));
    }
    for (const { file, content } of frontendFiles(ctx)) findings.push(...scanFrontendFile(file, content));
    return findings.sort(byLocation);
  },
};

import { open, readdir, readFile, stat } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import type { Check, Finding, Severity } from "../types.js";

const SCANNED_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json",
  ".vue", ".svelte", ".html", ".toml", ".yaml", ".yml",
]);

// .output is the build folder of Nitro-based frameworks (TanStack Start, Nuxt).
const SKIPPED_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".output", "coverage"]);

const LOCKFILES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
  "pnpm-lock.yaml", "bun.lock", "bun.lockb",
]);

const MAX_FILE_SIZE = 1024 * 1024;

// Shared by every key pattern: the character before the key must not be part
// of a word, so "task-..." is never read as "sk-...".
const START = "(?<![A-Za-z0-9_-])";

interface KeyPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  fix: string;
}

const SERVER_SIDE_FIX = "Move this key to a server-side function and rotate it now.";

// To support a new provider, add an entry here.
export const KEY_PATTERNS: KeyPattern[] = [
  {
    name: "Anthropic API key",
    regex: new RegExp(`${START}sk-ant-[A-Za-z0-9_-]{20,}`, "g"),
    severity: "critical",
    fix: SERVER_SIDE_FIX,
  },
  {
    name: "OpenAI API key",
    regex: new RegExp(`${START}sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}`, "g"),
    severity: "critical",
    fix: SERVER_SIDE_FIX,
  },
  {
    // Legacy OpenAI keys: letters and digits only after "sk-".
    name: "OpenAI API key",
    regex: new RegExp(`${START}sk-(?!ant-)[A-Za-z0-9]{20,}`, "g"),
    severity: "critical",
    fix: SERVER_SIDE_FIX,
  },
  {
    name: "Stripe live secret key",
    regex: new RegExp(`${START}(?:sk|rk)_live_[A-Za-z0-9]{16,}`, "g"),
    severity: "critical",
    fix: "Move this key to a server-side function and roll it in the Stripe dashboard now.",
  },
  {
    name: "Stripe test secret key",
    regex: new RegExp(`${START}(?:sk|rk)_test_[A-Za-z0-9]{16,}`, "g"),
    severity: "high",
    fix: "Move this key to a server-side function and roll it in the Stripe dashboard.",
  },
  {
    name: "Supabase secret key",
    regex: new RegExp(`${START}sb_secret_[A-Za-z0-9_-]{16,}`, "g"),
    severity: "critical",
    fix: "Use the publishable key in frontend code, keep the secret key server-side, and rotate it now.",
  },
  {
    name: "AWS access key",
    regex: new RegExp(`${START}AKIA[0-9A-Z]{16}(?![0-9A-Z])`, "g"),
    severity: "critical",
    fix: "Deactivate this key in AWS IAM now and load credentials from the environment instead.",
  },
  {
    name: "GitHub token",
    regex: new RegExp(`${START}ghp_[A-Za-z0-9]{36}`, "g"),
    severity: "critical",
    fix: "Revoke this token in GitHub settings now and load it from the environment instead.",
  },
  {
    name: "GitHub token",
    regex: new RegExp(`${START}github_pat_[A-Za-z0-9_]{22,}`, "g"),
    severity: "critical",
    fix: "Revoke this token in GitHub settings now and load it from the environment instead.",
  },
];

// Three base64url chunks separated by dots; "eyJ" is base64 for '{"'.
const JWT_REGEX = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

// import.meta.env.VITE_X or import.meta.env["VITE_X"]; the name ends up in group 1 or 2.
const VITE_ENV_REGEX = /import\.meta\.env(?:\.(VITE_\w+)|\[\s*["'](VITE_\w+)["']\s*\])/g;
const SECRET_NAME_PARTS = ["SECRET", "SERVICE_ROLE", "PRIVATE", "PASSWORD"];

/** Never show a full key: first 8 characters, "****", last 4 characters. */
export function mask(value: string): string {
  if (value.length <= 16) return value.slice(0, 4) + "****";
  return value.slice(0, 8) + "****" + value.slice(-4);
}

function isServiceRoleJwt(token: string): boolean {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    return payload?.role === "service_role";
  } catch {
    return false;
  }
}

function shouldScanFile(name: string): boolean {
  if (name.startsWith(".env")) return false; // handled by the .env check
  if (LOCKFILES.has(name)) return false;
  if (/\.min\.[a-z]+$/i.test(name)) return false;
  return SCANNED_EXTENSIONS.has(extname(name).toLowerCase());
}

async function* walk(dir: string): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) yield* walk(fullPath);
    } else if (entry.isFile() && shouldScanFile(entry.name)) {
      yield fullPath;
    }
  }
}

async function isBinary(filePath: string): Promise<boolean> {
  const handle = await open(filePath, "r");
  try {
    const buffer = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).includes(0);
  } finally {
    await handle.close();
  }
}

export function scanContent(file: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((text, index) => {
    const line = index + 1;

    for (const pattern of KEY_PATTERNS) {
      for (const match of text.matchAll(pattern.regex)) {
        findings.push({
          checkId: leakedKeysCheck.id,
          severity: pattern.severity,
          file,
          line,
          message: `${pattern.name} hardcoded: ${mask(match[0])}`,
          fix: pattern.fix,
        });
      }
    }

    for (const match of text.matchAll(JWT_REGEX)) {
      if (!isServiceRoleJwt(match[0])) continue;
      findings.push({
        checkId: leakedKeysCheck.id,
        severity: "critical",
        file,
        line,
        message: `Supabase service_role key hardcoded: ${mask(match[0])}`,
        fix: "Use the anon or publishable key in frontend code, keep the service_role key server-side, and rotate it now.",
      });
    }

    for (const match of text.matchAll(VITE_ENV_REGEX)) {
      const name = match[1] ?? match[2];
      if (!SECRET_NAME_PARTS.some((part) => name.toUpperCase().includes(part))) continue;
      findings.push({
        checkId: leakedKeysCheck.id,
        severity: "high",
        file,
        line,
        message: `Secret exposed to the browser through Vite: import.meta.env.${name}`,
        fix: `Vite ships every VITE_ variable to the browser: drop the VITE_ prefix, use ${name.slice(5)} only in server-side code, and rotate it.`,
      });
    }
  });

  return findings;
}

export const leakedKeysCheck: Check = {
  id: "leaked-keys",
  name: "Leaked secret keys in code",
  severity: "critical",
  async run(projectPath) {
    const findings: Finding[] = [];
    for await (const filePath of walk(projectPath)) {
      const { size } = await stat(filePath);
      if (size > MAX_FILE_SIZE || (await isBinary(filePath))) continue;

      const file = relative(projectPath, filePath).split(sep).join("/");
      findings.push(...scanContent(file, await readFile(filePath, "utf8")));
    }
    return findings.sort((a, b) => a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
  },
};

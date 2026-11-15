import { execFile } from "node:child_process";
import { basename } from "node:path";
import { isEnvFile } from "../lib/files.js";
import { mask } from "../lib/mask.js";
import { findSecretKeys, isDocumentedExampleKey, isTestKey, secretEnvId, secretValueId } from "../lib/patterns.js";
import { CheckSkipped, type ScanFinding, type ScannerRule } from "../types.js";

const RULE_ID = "committed-env";
const BASE = { ruleId: RULE_ID, category: "security", confidence: "high" } as const;

const SECRET_NAME_PARTS = ["SECRET", "SERVICE_ROLE", "PRIVATE", "PASSWORD", "TOKEN", "API_KEY"];
// FIREBASE: Firebase web config (apiKey, authDomain, ...) is public by design.
const SAFE_NAME_PARTS = ["PUBLISHABLE", "ANON", "URL", "PROJECT_ID", "PUBLIC", "FIREBASE"];

const PLACEHOLDERS = [
  /^your[-_]/i,                     // your-api-key, your_secret
  /^<.*>$/,                         // <paste key here>
  /\.\.\.|…/,                       // sk-...
  /change[-_]?me/i,                 // changeme, change-me
  /placeholder|example|todo/i,
  /(?:^|[-_.])x{3,}(?:$|[-_.])/i,   // xxx, sk_test_xxx
  /^\$\{?\w+\}?$/,                  // ${OTHER_VAR}: a reference, not a value
];

// scheme://user:password@host. The lookahead after the host makes the lazy
// password stretch to the last "@", so passwords that contain "@" still work.
const CREDENTIAL_URL = /^([a-z][a-z0-9+.-]*):\/\/([^:/?#@\s]*):(\S+?)@([^@/?#\s]+)(?=$|[/?#])/i;

const EXAMPLE_FILE = /\.(example|sample|template)$/i;

/** .env.example, .env.sample, .env.template: placeholders, never loaded by Vite. */
export const isExampleEnvFile = (name: string) => EXAMPLE_FILE.test(name);

export interface EnvEntry {
  line: number;
  name: string;
  value: string;
}

/** Parses NAME=VALUE lines, skipping blanks, comments and anything that isn't an assignment. */
export function parseEnv(content: string): EnvEntry[] {
  const entries: EnvEntry[] = [];
  content
    .replace(/^﻿/, "")
    .split(/\r?\n/)
    .forEach((rawLine, index) => {
      const text = rawLine.trim();
      if (text === "" || text.startsWith("#")) return;

      const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/.exec(text);
      if (!match) return;
      entries.push({ line: index + 1, name: match[1], value: parseValue(match[2]) });
    });
  return entries;
}

function parseValue(raw: string): string {
  const quote = raw[0];
  if (quote === '"' || quote === "'" || quote === "`") {
    const end = raw.indexOf(quote, 1);
    return end === -1 ? raw.slice(1) : raw.slice(1, end);
  }
  if (raw.startsWith("#")) return "";
  return raw.replace(/\s+#.*$/, "").trim();
}

const isPlaceholder = (value: string) => PLACEHOLDERS.some((p) => p.test(value));

interface Secret {
  entry: EnvEntry;
  masked: string;
  /** The secret part of the value: the key, the URL's password, or the whole value. In memory only. */
  value: string;
}

/** Returns how the entry should be shown if it is a secret, or undefined if it's safe. */
export function classify(entry: EnvEntry, exampleFile: boolean): Secret | undefined {
  const { name, value } = entry;

  // Rule 1: a real-shaped key, whatever the variable is called.
  const [key] = findSecretKeys(value);
  if (key) return { entry, masked: mask(key.value), value: key.value };
  if (exampleFile) return undefined;

  // Rule 3: a URL with a real password in it, whatever the variable is called.
  const url = CREDENTIAL_URL.exec(value);
  if (url) {
    const [, scheme, user, password, host] = url;
    if (!isPlaceholder(password)) return { entry, masked: `${scheme}://${user}:****@${host}`, value: password };
  }

  // Rule 2: a secret-sounding name with a real value.
  const upper = name.toUpperCase();
  if (
    SECRET_NAME_PARTS.some((part) => upper.includes(part)) &&
    !SAFE_NAME_PARTS.some((part) => upper.includes(part)) &&
    value !== "" &&
    !isPlaceholder(value) &&
    !isDocumentedExampleKey(value)
  ) {
    return { entry, masked: mask(value), value };
  }
  return undefined;
}

interface GitResult {
  code: number;
  stdout: string;
}

function git(cwd: string, args: string[], input?: string): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    const child = execFile("git", args, { cwd, windowsHide: true }, (error, stdout) => {
      // A non-number code means git never started (ENOENT: not installed).
      if (error && typeof error.code !== "number") return reject(error);
      resolve({ code: typeof error?.code === "number" ? error.code : 0, stdout });
    });
    child.stdin?.on("error", () => {}); // the callback above reports failures
    child.stdin?.end(input ?? "");
  });
}

const splitNul = (stdout: string) => new Set(stdout.split("\0").filter(Boolean));

async function gitStatus(projectPath: string, files: string[]) {
  try {
    const repo = await git(projectPath, ["rev-parse", "--is-inside-work-tree"]);
    if (repo.code !== 0 || repo.stdout.trim() !== "true") {
      throw new CheckSkipped("Not a git repository, so LeakProof can't tell whether .env files are committed.");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new CheckSkipped("git is not installed, so LeakProof can't tell whether .env files are committed.");
    }
    throw error;
  }

  // --literal-pathspecs: treat names like "*.env" as file names, not wildcards.
  const tracked = await git(projectPath, ["--literal-pathspecs", "ls-files", "-z", "--", ...files]);
  if (tracked.code !== 0) throw new Error(`git ls-files failed with exit code ${tracked.code}`);
  const trackedFiles = splitNul(tracked.stdout);

  const untracked = files.filter((f) => !trackedFiles.has(f));
  let ignoredFiles = new Set<string>();
  if (untracked.length > 0) {
    // check-ignore only accepts -z with --stdin, so the names go in on stdin.
    // Exit code 1 means "none of these are ignored", which is not an error.
    const ignored = await git(projectPath, ["check-ignore", "-z", "--stdin"], untracked.join("\0") + "\0");
    if (ignored.code > 1) throw new Error(`git check-ignore failed with exit code ${ignored.code}`);
    ignoredFiles = splitNul(ignored.stdout);
  }

  return { trackedFiles, ignoredFiles };
}

export const committedEnvRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Committed .env files",
  passedLabel: "No secrets in committed .env files",
  notApplicable: (ctx) => (ctx.files.some((file) => isEnvFile(basename(file))) ? undefined : "no .env files found"),
  async run(ctx) {
    const envFiles: { file: string; example: boolean; entries: number; secrets: Secret[] }[] = [];
    for (const file of ctx.files) {
      if (!isEnvFile(basename(file))) continue;
      const example = EXAMPLE_FILE.test(basename(file));
      const entries = parseEnv(ctx.read(file));
      const secrets = entries.map((entry) => classify(entry, example)).filter((s): s is Secret => s !== undefined);
      envFiles.push({ file, example, entries: entries.length, secrets });
    }
    if (envFiles.length === 0) return [];

    const { trackedFiles, ignoredFiles } = await gitStatus(ctx.root, envFiles.map((f) => f.file));
    const findings: ScanFinding[] = [];

    for (const { file, example, entries, secrets } of envFiles) {
      // Vite loads .env, .env.local, .env.[mode] and .env.[mode].local, never example files.
      const shipped = (name: string) => !example && name.startsWith("VITE_");

      if (trackedFiles.has(file) && secrets.length > 0) {
        const fix = example
          ? `Replace the real value in ${file} with a placeholder and rotate this key; it stays in git history even after deletion.`
          : `Remove ${file} from git (git rm --cached ${file}), add ${file} to .gitignore, and rotate this key; it stays in git history even after deletion.`;
        for (const { entry, masked, value } of secrets) {
          const where = shipped(entry.name) ? "committed to git and shipped to the browser" : "committed to git";
          findings.push({
            ...BASE,
            fixId: "SEC_ENV_COMMITTED",
            title: ".env file with secrets committed",
            // Test keys can't move real money, so they're one level lower.
            severity: isTestKey(value) ? "high" : "critical",
            secretIds: [secretValueId(value), secretEnvId(entry.name)],
            file,
            line: entry.line,
            message: `${entry.name} is ${where}: ${masked}`,
            fix,
          });
        }
      } else if (trackedFiles.has(file)) {
        // Safe today, but this is where someone will paste the next secret.
        if (example || entries === 0) continue;
        findings.push({
          ...BASE,
          // Not in CONTRACT v1 yet: proposed to Hilal for the "Proposed" section.
          fixId: "SEC_ENV_COMMITTED_PUBLIC_ONLY",
          title: ".env file committed (public values only)",
          severity: "low",
          file,
          message: `${file} is committed to git. It's safe right now (public values only), but any secret you add here becomes public.`,
          fix: "Keep secrets out of this file: store them in your platform's secrets manager (e.g. Lovable or Supabase secrets) or in a git-ignored .env.local.",
        });
      } else if (secrets.length > 0 && !ignoredFiles.has(file)) {
        const list = secrets.map((s) => `${s.entry.name}=${s.masked}`).join(", ");
        const vite = secrets.map((s) => s.entry.name).filter(shipped);
        const viteSentence = vite.length > 0 ? ` ${vite.join(", ")} ${vite.length === 1 ? "is" : "are"} also shipped to the browser.` : "";
        findings.push({
          ...BASE,
          // Not in CONTRACT v1 yet: proposed to Hilal for the "Proposed" section.
          fixId: "SEC_ENV_NOT_GITIGNORED",
          secretIds: secrets.flatMap((s) => [secretValueId(s.value), secretEnvId(s.entry.name)]),
          title: ".env file with secrets not in .gitignore",
          severity: "medium",
          file,
          line: secrets[0].entry.line,
          message: `${file} has ${secrets.length} secret${secrets.length === 1 ? "" : "s"} (${list}) and is not in .gitignore, one git add away from being committed.${viteSentence}`,
          fix: example
            ? `Replace the real value in ${file} with a placeholder before it gets committed.`
            : `Add ${file} to .gitignore before it gets committed.`,
        });
      }
    }

    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
  },
};

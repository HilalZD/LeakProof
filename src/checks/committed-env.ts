import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { isEnvFile, toProjectPath, walkFiles } from "../lib/files.js";
import { mask } from "../lib/mask.js";
import { findSecretKeys } from "../lib/patterns.js";
import { CheckSkipped, type Check, type Finding } from "../types.js";

const CHECK_ID = "committed-env";

const SECRET_NAME_PARTS = ["SECRET", "SERVICE_ROLE", "PRIVATE", "PASSWORD", "TOKEN", "API_KEY"];
const SAFE_NAME_PARTS = ["PUBLISHABLE", "ANON", "URL", "PROJECT_ID", "PUBLIC"];

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
}

/** Returns how the entry should be shown if it is a secret, or undefined if it's safe. */
export function classify(entry: EnvEntry, exampleFile: boolean): Secret | undefined {
  const { name, value } = entry;

  // Rule 1: a real-shaped key, whatever the variable is called.
  const [key] = findSecretKeys(value);
  if (key) return { entry, masked: mask(key.value) };
  if (exampleFile) return undefined;

  // Rule 3: a URL with a real password in it, whatever the variable is called.
  const url = CREDENTIAL_URL.exec(value);
  if (url) {
    const [, scheme, user, password, host] = url;
    if (!isPlaceholder(password)) return { entry, masked: `${scheme}://${user}:****@${host}` };
  }

  // Rule 2: a secret-sounding name with a real value.
  const upper = name.toUpperCase();
  if (
    SECRET_NAME_PARTS.some((part) => upper.includes(part)) &&
    !SAFE_NAME_PARTS.some((part) => upper.includes(part)) &&
    value !== "" &&
    !isPlaceholder(value)
  ) {
    return { entry, masked: mask(value) };
  }
  return undefined;
}

const viteNote = (names: string[]) =>
  names.some((n) => n.startsWith("VITE_")) ? " The VITE_ prefix also ships it to the browser." : "";

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

export const committedEnvCheck: Check = {
  id: CHECK_ID,
  name: "Committed .env files",
  severity: "critical",
  async run(projectPath, context) {
    const secretsByFile = new Map<string, Secret[]>();
    const files: string[] = [];
    for await (const filePath of walkFiles(projectPath, isEnvFile, context)) {
      const file = toProjectPath(projectPath, filePath);
      files.push(file);
      const exampleFile = EXAMPLE_FILE.test(basename(file));
      const secrets = parseEnv(await readFile(filePath, "utf8"))
        .map((entry) => classify(entry, exampleFile))
        .filter((s): s is Secret => s !== undefined);
      if (secrets.length > 0) secretsByFile.set(file, secrets);
    }
    if (files.length === 0) return [];

    const { trackedFiles, ignoredFiles } = await gitStatus(projectPath, files);
    const findings: Finding[] = [];

    for (const [file, secrets] of secretsByFile) {
      const example = EXAMPLE_FILE.test(basename(file));

      if (trackedFiles.has(file)) {
        for (const { entry, masked } of secrets) {
          const fix = example
            ? `Replace the real value in ${file} with a placeholder and rotate this key; it stays in git history even after deletion.`
            : `Remove ${file} from git (git rm --cached ${file}), add ${file} to .gitignore, and rotate this key; it stays in git history even after deletion.`;
          findings.push({
            checkId: CHECK_ID,
            severity: "critical",
            file,
            line: entry.line,
            message: `${entry.name} is committed to git: ${masked}`,
            fix: fix + viteNote([entry.name]),
          });
        }
      } else if (!ignoredFiles.has(file)) {
        const names = secrets.map((s) => s.entry.name);
        const fix = example
          ? `Replace the real value in ${file} with a placeholder before it gets committed.`
          : `Add ${file} to .gitignore before it gets committed.`;
        findings.push({
          checkId: CHECK_ID,
          severity: "medium",
          file,
          line: secrets[0].entry.line,
          message: `${file} has ${names.length} secret${names.length === 1 ? "" : "s"} (${secrets.map((s) => `${s.entry.name}=${s.masked}`).join(", ")}) and is not in .gitignore, one git add away from being committed`,
          fix: fix + viteNote(names),
        });
      }
    }

    return findings.sort((a, b) => a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
  },
};

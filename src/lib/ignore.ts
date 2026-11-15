import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../contract.js";

// .leakproofignore, in the scanned project's root. One entry per line:
//   SEC_ENV_COMMITTED              a fixId: ignored everywhere
//   src/legacy/**  or  *.test.ts   a path or glob: every finding in matching files
//   .env.example:SEC_ENV_COMMITTED  path:fixId: that fixId in matching files only
// "#" starts a comment. Blank lines are skipped.

export const IGNORE_FILE = ".leakproofignore";

const FIX_ID = /^[A-Z][A-Z0-9]*_[A-Z0-9_]+$/;

export interface IgnoreEntry {
  /** The line as written, without the comment. */
  source: string;
  fixId?: string;
  path?: RegExp;
}

/**
 * A path or glob as a regex over project paths (forward slashes).
 * "*" stays inside one folder, "**" crosses folders, "?" is one character.
 * A pattern with no "/" matches at any depth; a folder matches everything in it.
 */
export function globToRegExp(glob: string): RegExp {
  let pattern = glob.replace(/\\/g, "/").replace(/^\.\//, "");
  const anchored = pattern.startsWith("/") || pattern.replace(/\/$/, "").includes("/");
  pattern = pattern.replace(/^\/+/, "").replace(/\/+$/, "");

  let source = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*" && pattern[i + 1] === "*") {
      // "**/" matches zero or more folders; a bare "**" matches anything.
      if (pattern[i + 2] === "/") {
        source += "(?:.*/)?";
        i += 2;
      } else {
        source += ".*";
        i += 1;
      }
    } else if (c === "*") {
      source += "[^/]*";
    } else if (c === "?") {
      source += "[^/]";
    } else {
      source += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${anchored ? "" : "(?:.*/)?"}${source}(?:/.*)?$`);
}

export function parseIgnoreFile(text: string): IgnoreEntry[] {
  const entries: IgnoreEntry[] = [];
  for (const raw of text.replace(/^﻿/, "").split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (line === "") continue;

    if (FIX_ID.test(line)) {
      entries.push({ source: line, fixId: line });
      continue;
    }
    const colon = line.lastIndexOf(":");
    const suffix = colon === -1 ? "" : line.slice(colon + 1).trim();
    if (colon > 0 && FIX_ID.test(suffix)) {
      entries.push({ source: line, fixId: suffix, path: globToRegExp(line.slice(0, colon).trim()) });
      continue;
    }
    entries.push({ source: line, path: globToRegExp(line) });
  }
  return entries;
}

/** The project's ignore entries, or none if it has no .leakproofignore. */
export function loadIgnoreFile(projectPath: string): IgnoreEntry[] {
  try {
    return parseIgnoreFile(readFileSync(join(projectPath, IGNORE_FILE), "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

export function isIgnored(finding: Pick<Finding, "fixId" | "file">, entries: IgnoreEntry[]): boolean {
  return entries.some((entry) => {
    if (entry.fixId && entry.fixId !== finding.fixId) return false;
    if (!entry.path) return true;
    return finding.file !== undefined && entry.path.test(finding.file);
  });
}

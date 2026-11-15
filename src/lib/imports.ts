import { posix } from "node:path";
import type { ProjectContext } from "../contract.js";

// Resolving local imports (relative paths and tsconfig aliases such as @/ and ~/)
// to project files, so a rule can look one level into helper files.

export interface ImportBinding {
  local: string;
  /** The exported name, "default", or "*" for a namespace import. */
  imported: string;
}

export interface ImportInfo {
  spec: string;       // "@/lib/db" or "./helpers"
  names: string[];    // local names it binds
  bindings: ImportBinding[];
  statement: string;  // the whole import statement
}

// import a from "x" · import { b, c as d } from "x" · import * as e from "x" · import a, { b } from "x"
const IMPORT =
  /^\s*import\s+(?:type\s+)?(?:\*\s+as\s+([\w$]+)|([\w$]+))?\s*,?\s*(?:\{([^}]*)\})?\s*from\s*["']([^"']+)["']/gm;

export function parseImports(code: string): ImportInfo[] {
  const result: ImportInfo[] = [];
  for (const m of code.matchAll(IMPORT)) {
    const bindings: ImportBinding[] = [];
    if (m[1]) bindings.push({ local: m[1], imported: "*" });
    if (m[2]) bindings.push({ local: m[2], imported: "default" });
    for (const part of (m[3] ?? "").split(",")) {
      const [imported, local] = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/).map((s) => s.trim());
      if (imported) bindings.push({ local: local ?? imported, imported });
    }
    result.push({ spec: m[4], names: bindings.map((b) => b.local), bindings, statement: m[0] });
  }
  return result;
}

/** Index just past the bracket that closes the one at `open` ((, [ or {), skipping strings. */
export function closeBracket(code: string, open: number): number {
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === "`") {
      for (i++; i < code.length && code[i] !== c; i++) if (code[i] === "\\") i++;
    } else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      if (--depth === 0) return i + 1;
    }
  }
  return code.length;
}

/** End of a `const x = ...` initializer: the first ; at depth 0, or the next top-level export. */
function endOfInitializer(code: string, from: number): number {
  for (let i = from; i < code.length; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") i = closeBracket(code, i) - 1;
    else if (c === '"' || c === "'" || c === "`") {
      for (i++; i < code.length && code[i] !== c; i++) if (code[i] === "\\") i++;
    } else if (c === ";") return i + 1;
    else if (c === "\n" && /^\n\s*export\b/.test(code.slice(i, i + 20))) return i;
  }
  return code.length;
}

const escapeName = (name: string) => name.replace(/\$/g, "\\$");

/**
 * The "{" that opens a function body, starting right after its parameters.
 * Skips a return type such as `: Promise<{ days: string[] }>` or `: { a: number }`.
 */
function bodyBrace(code: string, from: number): number {
  let i = from;
  while (/\s/.test(code[i] ?? "")) i++;
  if (code[i] !== ":") return code.indexOf("{", from);
  let angle = 0;
  for (i++; i < code.length; i++) {
    const c = code[i];
    if (c === "<") angle++;
    else if (c === ">" && code[i - 1] !== "=") angle--;
    else if (c === "(" || c === "[") i = closeBracket(code, i) - 1;
    else if (c === "{") {
      if (angle > 0) {
        i = closeBracket(code, i) - 1;
        continue;
      }
      // `: { a: number } {`: a type literal followed by the body.
      const end = closeBracket(code, i);
      let j = end;
      while (/\s/.test(code[j] ?? "")) j++;
      return code[j] === "{" ? j : i;
    }
  }
  return -1;
}

/**
 * The source of one exported function or const in a helper file, so a caller
 * is judged by the function it calls, not by everything else in the file.
 * Undefined when it can't be found (re-exports, classes, namespace imports).
 */
export function exportedBody(code: string, imported: string): string | undefined {
  if (imported === "*") return undefined;
  const name = imported === "default" ? undefined : escapeName(imported);
  const fn = new RegExp(
    name
      ? `(?:^|\\n)[ \\t]*(?:export\\s+)?(?:async\\s+)?function\\s*\\*?\\s*${name}\\s*(?:<[^>]*>)?\\s*\\(`
      : `(?:^|\\n)[ \\t]*export\\s+default\\s+(?:async\\s+)?function\\b[^(]*\\(`,
  ).exec(code);
  if (fn) {
    const brace = bodyBrace(code, closeBracket(code, fn.index + fn[0].length - 1));
    return brace === -1 ? undefined : code.slice(fn.index, closeBracket(code, brace));
  }
  const decl = new RegExp(
    name ? `(?:^|\\n)[ \\t]*(?:export\\s+)?(?:const|let|var)\\s+${name}\\b[^=]*=` : `(?:^|\\n)[ \\t]*export\\s+default\\b`,
  ).exec(code);
  if (decl) return code.slice(decl.index, endOfInitializer(code, decl.index + decl[0].length));
  return undefined;
}

/** JSON with comments and trailing commas (tsconfig.json), or undefined. */
export function parseJsonc(text: string): any {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 1;
    } else out += c;
  }
  try {
    return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
  } catch {
    return undefined;
  }
}

interface Alias {
  prefix: string;     // "@/" (from "@/*") or "lib" (exact key)
  wildcard: boolean;
  targets: string[];  // project-relative folders/files, "" for the root
}

const TSCONFIGS = ["tsconfig.json", "tsconfig.app.json", "jsconfig.json"];

/** Aliases from tsconfig "paths"; with no tsconfig paths, @/ and ~/ map to src/ then the project root. */
export function loadAliases(ctx: ProjectContext): Alias[] {
  const aliases: Alias[] = [];
  for (const name of TSCONFIGS) {
    if (!ctx.files.includes(name)) continue;
    const opts = parseJsonc(ctx.read(name))?.compilerOptions;
    if (!opts?.paths || typeof opts.paths !== "object") continue;
    const base = typeof opts.baseUrl === "string" ? opts.baseUrl : ".";
    for (const [key, values] of Object.entries(opts.paths)) {
      if (!Array.isArray(values)) continue;
      const wildcard = key.endsWith("*");
      aliases.push({
        prefix: key.replace(/\*$/, ""),
        wildcard,
        targets: values
          .filter((v): v is string => typeof v === "string")
          .map((v) => posix.normalize(posix.join(base, v.replace(/\*$/, ""))).replace(/^\.\/?$|^\.\//, "")),
      });
    }
  }
  if (aliases.length === 0) {
    for (const prefix of ["@/", "~/"]) aliases.push({ prefix, wildcard: true, targets: ["src/", ""] });
  }
  return aliases;
}

const EXTENSIONS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"];

/** The project file an import points at, or undefined for packages and unknown paths. */
export function resolveImport(fileSet: Set<string>, aliases: Alias[], fromFile: string, spec: string): string | undefined {
  const bases: string[] = [];
  if (spec.startsWith("./") || spec.startsWith("../")) {
    bases.push(posix.normalize(posix.join(posix.dirname(fromFile), spec)));
  } else {
    for (const a of aliases) {
      const rest = a.wildcard ? (spec.startsWith(a.prefix) ? spec.slice(a.prefix.length) : undefined) : spec === a.prefix ? "" : undefined;
      if (rest === undefined) continue;
      for (const t of a.targets) bases.push(posix.normalize(posix.join(t || ".", rest)));
    }
  }
  for (const base of bases) {
    const stems = /\.[cm]?jsx?$/.test(base) ? [base, base.replace(/\.([cm]?)js(x?)$/, ".$1ts$2")] : [base];
    for (const stem of stems) {
      for (const ext of EXTENSIONS) {
        const candidate = (stem + ext).replace(/^\.\//, "");
        if (fileSet.has(candidate)) return candidate;
      }
    }
  }
  return undefined;
}

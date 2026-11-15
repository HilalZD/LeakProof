import { existsSync, readFileSync } from "node:fs";
import { open, readdir, stat } from "node:fs/promises";
import { basename, extname, join, relative, sep } from "node:path";
import type { ProjectContext } from "../contract.js";

// Dependencies, build output and caches, in JS and other languages. Their code
// isn't the app's own, and library test keys there would be false alarms.
// .output is the build folder of Nitro-based frameworks (TanStack Start, Nuxt).
const SKIPPED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".output", "coverage",
  // Python
  ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", "site-packages",
  // Go / PHP / Ruby dependencies, Rust / Java build output, Gradle, CocoaPods
  "vendor", "target", ".gradle", "Pods",
]);

/** Whether the walker skips this folder: a known dependency/build/cache folder, *.egg-info, or any Python virtualenv. */
export function isSkippedDir(name: string, fullPath?: string): boolean {
  if (SKIPPED_DIRS.has(name) || name.endsWith(".egg-info")) return true;
  // A virtualenv under any name (env/, .env-py/…) has a pyvenv.cfg at its root.
  return fullPath !== undefined && existsSync(join(fullPath, "pyvenv.cfg"));
}

const CODE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json",
  ".vue", ".svelte", ".html", ".toml", ".yaml", ".yml",
]);

/**
 * Source and config files in other languages. Only the language-agnostic
 * checks (hardcoded secret keys) read these; route, auth, rate-limit and
 * privacy checks stay JS/TS only. Docs (.md, .txt) are left out on purpose:
 * they're full of example keys.
 */
const OTHER_SOURCE_EXTENSIONS = new Set([
  ".py", ".pyw", ".ipynb", ".go", ".rb", ".php", ".java", ".kt", ".kts", ".scala", ".cs", ".swift",
  ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".dart", ".ex", ".exs", ".lua", ".pl", ".r", ".jl",
  ".sh", ".bash", ".zsh", ".ps1", ".tf", ".tfvars", ".ini", ".cfg", ".conf", ".properties", ".xml", ".gradle", ".sql",
]);
const SOURCE_FILE_NAMES = new Set(["Dockerfile", "Makefile", "Procfile"]);

const LOCKFILES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
  "pnpm-lock.yaml", "bun.lock", "bun.lockb",
  "poetry.lock", "Pipfile.lock", "uv.lock", "Gemfile.lock", "composer.lock", "go.sum", "Cargo.lock",
]);

const MAX_FILE_SIZE = 1024 * 1024;

export function isEnvFile(name: string): boolean {
  return name === ".env" || name.startsWith(".env.");
}

/** Code and config files, minus .env files (they have their own check), lockfiles and minified files. */
export function isCodeFile(name: string): boolean {
  if (name.startsWith(".env")) return false;
  if (LOCKFILES.has(name)) return false;
  if (/\.min\.[a-z]+$/i.test(name)) return false;
  return CODE_EXTENSIONS.has(extname(name).toLowerCase());
}

/** JS/TS code (isCodeFile) or source/config in any other language: what the secret-key check reads. */
export function isSourceFile(name: string): boolean {
  if (isCodeFile(name)) return true;
  if (name.startsWith(".env") || LOCKFILES.has(name) || /\.min\.[a-z]+$/i.test(name)) return false;
  return OTHER_SOURCE_EXTENSIONS.has(extname(name).toLowerCase()) || SOURCE_FILE_NAMES.has(basename(name));
}

/** A path relative to the project, with forward slashes on every OS. */
export function toProjectPath(projectPath: string, filePath: string): string {
  return relative(projectPath, filePath).split(sep).join("/");
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

async function* walk(dir: string, include: (name: string) => boolean): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!isSkippedDir(entry.name, fullPath)) yield* walk(fullPath, include);
    } else if (entry.isFile() && include(entry.name)) {
      yield fullPath;
    }
  }
}

/**
 * Yields the absolute path of every text file under projectPath whose name
 * passes `include`, skipping build/dependency folders, files over 1 MB and
 * binaries.
 */
export async function* walkFiles(projectPath: string, include: (name: string) => boolean): AsyncGenerator<string> {
  for await (const filePath of walk(projectPath, include)) {
    const { size } = await stat(filePath);
    if (size > MAX_FILE_SIZE || (await isBinary(filePath))) continue;
    yield filePath;
  }
}

/**
 * The contract's ProjectContext for one scan: every text file under root
 * (same skips as walkFiles), read on demand and cached. Each file read is
 * added to `filesRead` (project paths), so the report can count them once.
 */
export async function createProjectContext(root: string, filesRead = new Set<string>()): Promise<ProjectContext> {
  const files: string[] = [];
  for await (const filePath of walkFiles(root, () => true)) files.push(toProjectPath(root, filePath));

  const cache = new Map<string, string>();
  const read = (file: string): string => {
    let text = cache.get(file);
    if (text === undefined) {
      try {
        text = readFileSync(join(root, file), "utf8");
      } catch {
        text = ""; // contract: read() never throws; an unreadable file reads as empty
      }
      cache.set(file, text);
    }
    filesRead.add(file);
    return text;
  };

  let packageJson: Record<string, any> | undefined;
  if (files.includes("package.json")) {
    try {
      packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    } catch {
      // Not valid JSON: leave it out.
    }
  }
  return { root, files, read, packageJson };
}

import { open, readdir, stat } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import type { ScanContext } from "../types.js";

// .output is the build folder of Nitro-based frameworks (TanStack Start, Nuxt).
const SKIPPED_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".output", "coverage"]);

const CODE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json",
  ".vue", ".svelte", ".html", ".toml", ".yaml", ".yml",
]);

const LOCKFILES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
  "pnpm-lock.yaml", "bun.lock", "bun.lockb",
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
      if (!SKIPPED_DIRS.has(entry.name)) yield* walk(fullPath, include);
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
export async function* walkFiles(
  projectPath: string,
  include: (name: string) => boolean,
  context?: ScanContext,
): AsyncGenerator<string> {
  for await (const filePath of walk(projectPath, include)) {
    const { size } = await stat(filePath);
    if (size > MAX_FILE_SIZE || (await isBinary(filePath))) continue;
    context?.filesRead.add(filePath);
    yield filePath;
  }
}

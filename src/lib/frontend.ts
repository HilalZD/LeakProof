import { basename, extname } from "node:path";
import type { ProjectContext } from "../contract.js";

// Which files end up in the browser bundle.
//
// Vite apps (Lovable, Bolt): everything under src/ is frontend unless it is
// clearly server-only. Other apps (Next.js and friends): the usual frontend
// folders only.

const SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"]);
const FRONTEND_DIRS = /^(?:src\/)?(?:components|pages|app|routes)\//;
const TEST_FILE = /\.(?:test|spec)\.|\.d\.ts$/i;
const TEST_DIRS = new Set(["__tests__", "__mocks__", "test", "tests", "e2e", "cypress"]);

const SERVER_PATHS = [
  /(?:^|\/)api\//,                                   // API routes: src/routes/api/**, pages/api/**, app/api/**
  /(?:^|\/)routes\/api\./,                           // TanStack flat API routes: routes/api.x.ts
  /\.server\.[a-z]+$/i,                              // client.server.ts
  /(?:^|\/)app\/(?:.+\/)?route\.(?:ts|js|mjs)$/,     // Next.js route handlers
  /^src\/(?:server|entry-server)\.[a-z]+$/,          // server entry files
];

const USE_SERVER = /^\s*["']use server["']/m;
// TanStack Start server functions and middleware. A file that defines these and
// renders nothing (no React import) is server-only.
const SERVER_FN = /\bcreate(?:ServerFn|ServerOnlyFn|Middleware)\s*\(/;
const REACT_IMPORT = /\bfrom\s+["']react(?:-dom)?(?:\/[\w-]+)?["']/;
const SERVER_HANDLERS = /\bserver\s*:\s*\{\s*handlers\b/;
const SERVER_IMPORT = /["']@tanstack\/react-start\/server(?:-entry)?["']|["']server-only["']/;

export function isViteApp(ctx: ProjectContext): boolean {
  const pkg = ctx.packageJson ?? {};
  if (pkg.dependencies?.vite || pkg.devDependencies?.vite) return true;
  return ctx.files.some((f) => /^vite\.config\.[cm]?[jt]s$/.test(f));
}

const isScript = (file: string) => SCRIPT_EXTENSIONS.has(extname(file).toLowerCase());
const isTest = (file: string) => TEST_FILE.test(basename(file)) || file.split("/").some((p) => TEST_DIRS.has(p));

/** Whether a file is server-only, from its path and contents. */
export function isServerOnly(file: string, content: string): boolean {
  if (SERVER_PATHS.some((p) => p.test(file))) return true;
  if (USE_SERVER.test(content) || SERVER_HANDLERS.test(content) || SERVER_IMPORT.test(content)) return true;
  return SERVER_FN.test(content) && !REACT_IMPORT.test(content);
}

/** The files a browser can end up running, with their contents. */
export function frontendFiles(ctx: ProjectContext): { file: string; content: string }[] {
  const vite = isViteApp(ctx);
  const result: { file: string; content: string }[] = [];
  for (const file of ctx.files) {
    if (!isScript(file) || isTest(file)) continue;
    if (!(FRONTEND_DIRS.test(file) || (vite && file.startsWith("src/")))) continue;
    const content = ctx.read(file);
    if (!isServerOnly(file, content)) result.push({ file, content });
  }
  return result;
}

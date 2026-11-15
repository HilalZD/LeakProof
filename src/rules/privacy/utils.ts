import type { Finding, ProjectContext } from "../../contract.js";
import type { ScanFinding } from "../../types.js";
import { PRIVACY_FIXES, type PrivacyFixId } from "./laws.js";

// File types that contain app code. Rules only search these (not images, docs, etc.).
const CODE_EXTENSIONS = [
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".vue", ".svelte", ".astro", ".html", ".sql",
];

export function isCodeFile(file: string): boolean {
  const lower = file.toLowerCase();
  return CODE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export interface Match {
  file: string;  // which file
  line: number;  // which line (counting from 1)
  text: string;  // the line itself
}

/**
 * Removes comments from one line of code, so notes written for humans never trigger a rule.
 * Handles line comments (two slashes), block comments (slash-star ... star-slash),
 * HTML comments (<!-- ... -->), and the middle lines of a multi-line block comment.
 * Keeps web links like https://api.openai.com (the ":" before "//" means it's a link, not a comment).
 */
export function stripComments(line: string): string {
  if (/^\s*\*/.test(line)) return "";       // middle line of a /* ... */ block
  return line
    .replace(/\/\*.*?\*\//g, "")             // /* ... */ on one line (also {/* ... */} in JSX)
    .replace(/<!--.*?-->/g, "")                // <!-- ... --> in HTML
    .replace(/(^|[^:])\/\/.*$/, "$1");          // // ... until the end of the line
}

/**
 * The "LOOK" step: searches every code file, line by line, for any of the patterns.
 * Returns every line that matches.
 */
export function findMatches(ctx: ProjectContext, patterns: RegExp[]): Match[] {
  const matches: Match[] = [];
  for (const file of ctx.files) {
    if (!isCodeFile(file)) continue;
    const lines = ctx.read(file).split(/\r?\n/);
    lines.forEach((text, i) => {
      const code = stripComments(text);
      if (patterns.some((p) => p.test(code))) {
        matches.push({ file, line: i + 1, text: text.trim() });
      }
    });
  }
  return matches;
}

/** True if the whole app contains any of the patterns anywhere. */
export function appContains(ctx: ProjectContext, patterns: RegExp[]): boolean {
  return findMatches(ctx, patterns).length > 0;
}

/**
 * The "REPORT" step: builds a Finding in the exact CONTRACT format.
 * Severity, title and law references always come from the contract table (src/laws.ts).
 */
export function makeFinding(
  id: PrivacyFixId,
  details: { message: string; confidence: Finding["confidence"]; file?: string; line?: number },
): ScanFinding {
  const fix = PRIVACY_FIXES[id];
  return {
    ruleId: id,
    fixId: id,
    severity: fix.severity,
    category: "privacy",
    title: fix.title,
    message: details.message,
    ...(details.file !== undefined && { file: details.file }),
    ...(details.line !== undefined && { line: details.line }),
    lawRefs: [...fix.lawRefs],
    confidence: details.confidence,
    fix: fix.fix, // the scanner's one-line fix: not a contract field (like the security rules' fix)
  };
}

/**
 * Signs that users can sign THEMSELVES up (public account creation). Rules 4 and 5
 * only apply then: accounts an operator creates (staff logins with sign-in only)
 * don't need a self-service delete or export button. Added Nov 15, 2026 (Hilal).
 * A bare register(...) isn't listed: react-hook-form's register("email") would match.
 */
export const SELF_SIGNUP: RegExp[] = [
  /\.signUp\s*\(/,                          // Supabase
  /\bsignUp\.(email|social)\s*\(/,          // better-auth
  /\.signInWithOAuth\s*\(/,                 // Supabase OAuth: creates the user on first login
  /\.signInWithOtp\s*\(/,                   // Supabase magic link: creates the user by default
  /createUserWithEmailAndPassword\s*\(/,    // Firebase
  /<SignUp\b|\buseSignUp\s*\(/,             // Clerk
  /from\s+["']next-auth/,                   // NextAuth / Auth.js (OAuth providers create users)
];

/** Signs that the app has user accounts (sign-up or log-in). */
export const HAS_USER_ACCOUNTS: RegExp[] = [
  /\.signUp\s*\(/,                          // Supabase
  /\.signInWithPassword\s*\(/,              // Supabase
  /\.signInWithOAuth\s*\(/,                 // Supabase (Google/GitHub login)
  /createUserWithEmailAndPassword\s*\(/,    // Firebase
  /<SignUp\b|<SignIn\b|\buseSignUp\s*\(/,   // Clerk
  /from\s+["']next-auth/,                   // NextAuth / Auth.js
];

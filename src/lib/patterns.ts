import type { Severity } from "../types.js";

// Shared by every key pattern: the character before the key must not be part
// of a word, so "task-..." is never read as "sk-...".
const START = "(?<![A-Za-z0-9_-])";

export interface KeyPattern {
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

// Example keys that AWS and Stripe publish in their own documentation. They
// grant no access to anything, so they're never reported. Each key is split
// in two so GitHub's secret scanner doesn't flag this file.
const DOCUMENTED_EXAMPLE_KEYS = new Set([
  "AKIA" + "IOSFODNN7EXAMPLE", // AWS docs
  "AKIA" + "I44QH8DHBEXAMPLE", // AWS docs
  "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc", // Stripe docs
  "sk_test_" + "BQokikJOvBiI2HlWgH4olfQ2", // Stripe docs (older)
]);

export const isDocumentedExampleKey = (value: string) => DOCUMENTED_EXAMPLE_KEYS.has(value);

// Three base64url chunks separated by dots; "eyJ" is base64 for '{"'.
const JWT_REGEX = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

const SERVICE_ROLE_JWT: Omit<KeyPattern, "regex"> = {
  name: "Supabase service_role key",
  severity: "critical",
  fix: "Use the anon or publishable key in frontend code, keep the service_role key server-side, and rotate it now.",
};

export function isServiceRoleJwt(token: string): boolean {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    return payload?.role === "service_role";
  } catch {
    return false;
  }
}

export interface KeyMatch {
  pattern: Omit<KeyPattern, "regex">;
  value: string;
}

/** Every secret key in a piece of text, including service_role JWTs. */
export function findSecretKeys(text: string): KeyMatch[] {
  const matches: KeyMatch[] = [];
  for (const pattern of KEY_PATTERNS) {
    for (const match of text.matchAll(pattern.regex)) {
      if (!isDocumentedExampleKey(match[0])) matches.push({ pattern, value: match[0] });
    }
  }
  for (const match of text.matchAll(JWT_REGEX)) {
    if (isServiceRoleJwt(match[0])) matches.push({ pattern: SERVICE_ROLE_JWT, value: match[0] });
  }
  return matches;
}

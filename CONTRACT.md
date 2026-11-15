# THE LEAKPROOF CONTRACT (v1.3, updated Nov 15, 2026)

The three parts of scanner v0.2 are built separately, on three different computers, and joined at the end. They fit together only because everyone follows this contract exactly.
**Never rename or delete anything here.** If you need a new fix ID, add it under "Proposed" at the bottom and tell Hilal. Hilal is the only one who changes this file.

## 1. Language and tools
- TypeScript, Node.js 18 or newer.
- No paid services. Avoid extra libraries unless they're really needed.

## 2. The Finding format (every problem the scanner reports looks exactly like this)
```ts
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  ruleId: string;          // which check found it, e.g. "PRIV_NO_PRIVACY_POLICY"
  fixId: string;           // key into the fix library (Part C). Usually the same as ruleId.
  severity: Severity;
  category: "security" | "privacy";
  title: string;           // short, plain English: "No privacy policy found"
  message: string;         // what we found and why it matters, 1–2 sentences
  file?: string;           // path relative to the project root, if known
  line?: number;           // line number, if known
  lawRefs?: string[];      // privacy only, e.g. ["GDPR Art. 13", "PIPEDA Principle 4.8"]
  confidence: "high" | "medium" | "low";  // how sure we are this is real
}
```

## 3. The Rule format (every check is written like this)
```ts
export interface ProjectContext {
  root: string;                  // absolute path to the project being scanned
  files: string[];               // relative paths, excluding node_modules, .git, dist, build
  read(file: string): string;    // returns a file's text contents
  packageJson?: Record<string, any>;
}

export interface Rule {
  id: string;                    // must equal the ruleId of the Findings it produces
  category: "security" | "privacy";
  description: string;
  run(ctx: ProjectContext): Finding[] | Promise<Finding[]>;
}
```
A rule pack is a folder whose `src/index.ts` does `export const rules: Rule[] = [...]`.

## 4. Fix links (scanner → landing page)
The scanner prints one link containing the fix IDs only, never code, file paths or user data:
```
https://<SITE_URL>/fix?f=SEC_SUPABASE_RLS_DISABLED,PRIV_NO_PRIVACY_POLICY
```
`SITE_URL` is a placeholder until Yara's site is live (e.g. `leakproof.pages.dev`).

## 5. Master list of fix IDs

**Severity rule:** the severity in these tables is the default and the maximum. A rule may *lower* it when a case is clearly less dangerous (e.g. test keys), never raise it.

### Security (Part A, Hilal)
| fixId | Severity | Meaning |
|---|---|---|
| SEC_SECRET_HARDCODED | critical | An API key is written directly in the code (test keys like sk_test_ are lowered to high) |
| SEC_SECRET_CLIENT_EXPOSED | critical | A secret key can be reached by the browser (frontend file or VITE_/NEXT_PUBLIC_ variable) |
| SEC_ENV_COMMITTED | critical | A .env file with secrets is committed to the repo |
| SEC_ENV_COMMITTED_PUBLIC_ONLY | low | A committed .env that contains only public values (e.g. the Supabase anon key) |
| SEC_ENV_NOT_GITIGNORED | medium | A .env with secrets isn't committed, but isn't in .gitignore either |
| SEC_STRIPE_WEBHOOK_UNSIGNED | critical | A Stripe webhook doesn't verify its signature |
| SEC_SUPABASE_RLS_DISABLED | critical | A Supabase table has Row Level Security turned off |
| SEC_SUPABASE_RLS_PERMISSIVE | critical | A security rule exists but lets everyone in (e.g. `using (true)`) |
| SEC_SUPABASE_SERVICE_ROLE_CLIENT | critical | The Supabase admin (service_role) key is in frontend code |
| SEC_SUPABASE_RLS_UNVERIFIED | info | The database rules aren't in the repo, so they couldn't be checked |
| SEC_API_ROUTE_NO_AUTH | high | A server API route has no login/auth check |
| SEC_API_NO_RATE_LIMIT | high | A public API route has no rate limiting, so anyone can spam it |

### Privacy (Part B, Serena)
| fixId | Severity | Meaning | Laws (Serena must verify each one) |
|---|---|---|---|
| PRIV_NO_PRIVACY_POLICY | high | App collects personal data but has no privacy policy page | GDPR Art. 13; PIPEDA Principle 4.8 |
| PRIV_TRACKER_BEFORE_CONSENT | high | Analytics/ad trackers load with no consent banner | ePrivacy Directive Art. 5(3); GDPR Art. 7; PIPEDA Principle 4.3 |
| PRIV_PII_TO_THIRD_PARTY | medium | Personal data is sent to a third party (AI API, analytics) | GDPR Art. 13(1)(e), Art. 28; PIPEDA Principle 4.1.3 |
| PRIV_NO_ACCOUNT_DELETION | medium | Users can't delete their account/data | GDPR Art. 17; PIPEDA Principles 4.3.8, 4.5.3 |
| PRIV_NO_DATA_EXPORT | low | Users can't get a copy of their data | GDPR Art. 15, Art. 20; PIPEDA Principle 4.9 |
| PRIV_PII_IN_LOGS | medium | Personal data (email, phone, password) is printed to logs | GDPR Art. 5(1)(f), Art. 32; PIPEDA Principle 4.7 |

### Proposed (add new IDs here, tell Hilal)
_(empty)_

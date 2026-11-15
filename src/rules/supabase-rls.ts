import { isPersonalColumn, isPersonalTable } from "../lib/personal.js";
import { applyStatements, splitStatements, type Policy, type TableState } from "../lib/sql.js";
import { buildFixLink } from "../summary.js";
import type { ProjectContext, ScanFinding, ScannerRule, Severity } from "../types.js";

const RULE_ID = "supabase-rls";

const MIGRATION = /^supabase\/migrations\/[^/]+\.sql$/i;
const SCHEMA = /^supabase\/schema\.sql$/i;


const FIX_DISABLED = (table: string) =>
  `Run ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; then add policies so each user only sees their own rows, e.g. USING (auth.uid() = user_id).`;
const FIX_PERMISSIVE =
  "Replace USING (true) with a real check such as USING (auth.uid() = user_id), or drop the policy if nobody should have this access.";
const ADVISOR_TIP =
  "Check your tables in the Supabase dashboard's Security Advisor, or run `supabase db pull` to save your schema into the repo so LeakProof can check it.";
const FIX_UNVERIFIED = ADVISOR_TIP;
const UPSELL = "Leakproof Cloud will check your live database rules, with your permission. Join early access:";
const UNVERIFIED_LINK = buildFixLink([{ fixId: "SEC_SUPABASE_RLS_UNVERIFIED", severity: "info" }]) ?? "";

const shortName = (t: TableState) => t.key.split(".")[1];
const personalColumns = (t: TableState) => [...new Set(t.columns.filter((c) => isPersonalColumn(c, shortName(t))))];

interface PersonalData {
  text: string;      // column list, or the guess wording
  guessed: boolean;  // from the table name only: the repo doesn't show its columns
}

const GUESSED = "a table that usually holds personal data";

/** What personal data the table holds, or undefined if none is known. */
function personalData(t: TableState): PersonalData | undefined {
  const cols = personalColumns(t);
  if (cols.length > 0) return { text: cols.join(", "), guessed: false };
  // Tables that hold people even when the repo doesn't show their columns
  // (created in the dashboard, or by Lovable outside the migrations).
  if (t.columns.length === 0 && isPersonalTable(shortName(t))) return { text: GUESSED, guessed: true };
  return undefined;
}

/** " (personal data: email, phone)" or " (a table that usually holds personal data)". */
const piiSuffix = (pii?: PersonalData) => (!pii ? "" : pii.guessed ? ` (${GUESSED})` : ` (personal data: ${pii.text})`);

/** Expression with spaces and parentheses removed, lowercased. */
const squash = (expr: string | undefined) => (expr ?? "").toLowerCase().replace(/[\s()]/g, "");
const isTrue = (expr: string | undefined) => /^(?:true|1=1|'t'|'true')$/.test(squash(expr));
// auth.role() = 'authenticated', (select auth.role()) = ..., auth.uid() is not null, auth.jwt() ->> 'role' = ...
const isAnyLoggedIn = (expr: string | undefined) =>
  /^(?:select)?auth\.role(?:select)?='authenticated'$|^(?:select)?auth\.uidisnotnull$|^(?:select)?auth\.jwt->>'role'='authenticated'$/.test(squash(expr));
const isServiceRoleCheck = (expr: string | undefined) => /'service_role'/.test(squash(expr));

/** The expression that decides who the policy lets in for its command. */
function gate(p: Policy): string | undefined {
  if (p.command === "INSERT") return p.withCheck ?? p.using;
  if (p.command === "SELECT" || p.command === "DELETE") return p.using;
  return p.using ?? p.withCheck; // UPDATE, ALL: USING decides which rows can be touched
}

const ACTION: Record<Policy["command"], string> = {
  ALL: "read, add, change and delete",
  SELECT: "read",
  INSERT: "add",
  UPDATE: "change",
  DELETE: "delete",
};

function finding(fixId: string, severity: Severity, title: string, message: string, fix: string, file?: string, line?: number): ScanFinding {
  return { ruleId: RULE_ID, fixId, category: "security", severity, confidence: "medium", title, message, fix, file, line };
}

const SERVICE_ROLES = new Set(["service_role", "postgres", "supabase_admin"]);

/** How open a permissive policy is: "anyone", "logged-in" (any logged-in user), or undefined (a real check). */
function openness(p: Policy): "anyone" | "logged-in" | undefined {
  if (p.restrictive) return undefined;
  if (p.roles.length > 0 && p.roles.every((r) => SERVICE_ROLES.has(r))) return undefined;
  const expr = gate(p);
  if (isServiceRoleCheck(expr)) return undefined;
  const loggedIn = isAnyLoggedIn(expr);
  if (!isTrue(expr) && !loggedIn) return undefined;
  return loggedIn || p.roles.every((r) => r === "authenticated") ? "logged-in" : "anyone";
}

/** Whether some policy lets anon or logged-in users read every row of the table. */
const hasOpenRead = (t: TableState) =>
  [...t.policies.values()].some((p) => (p.command === "SELECT" || p.command === "ALL") && openness(p) !== undefined);

function permissive(t: TableState, p: Policy): ScanFinding | undefined {
  const open = openness(p);
  if (!open) return undefined;
  const who = open === "logged-in" ? "every logged-in user" : "anyone";
  const where = `Policy "${p.name}" on ${t.key}`;
  const pii = personalData(t);
  const make = (severity: Severity, message: string) =>
    finding("SEC_SUPABASE_RLS_PERMISSIVE", severity, "Supabase security rule lets everyone in", message, FIX_PERMISSIVE, p.file, p.line);

  // A public form (waitlist, contact): adding rows is fine as long as nobody can read them back.
  if (p.command === "INSERT" && !hasOpenRead(t)) {
    return make("medium", `${where} lets ${who} add rows: fine for a public form, add a rate limit or captcha.`);
  }
  if (p.command !== "SELECT") {
    return make("critical", `${where} lets ${who} ${ACTION[p.command]} any row${piiSuffix(pii)}.`);
  }
  if (open === "logged-in") {
    return make("high", `${where} uses no ownership check: every logged-in user can read everyone's rows${piiSuffix(pii)}.`);
  }
  if (pii?.guessed) return make("critical", `Anyone can read every row in ${shortName(t)} (${GUESSED}). Policy: "${p.name}".`);
  if (pii) return make("critical", `${where} lets anyone read every row, including personal data (${pii.text}).`);
  return make("low", `${where} lets anyone read every row. Fine if it's meant to be public.`);
}

// Python dependency files that can list supabase-py.
const PYTHON_DEPS = /^(requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/;
const SUPABASE_PY = /^\s*["']?supabase\b/im;

export function usesSupabase(ctx: ProjectContext): boolean {
  const deps = { ...(ctx.packageJson?.dependencies ?? {}), ...(ctx.packageJson?.devDependencies ?? {}) };
  if (Object.keys(deps).some((d) => d.startsWith("@supabase/") || d === "supabase")) return true;
  if (ctx.files.some((f) => f.startsWith("supabase/"))) return true;
  // Non-JS apps (e.g. Python with supabase-py) have no package.json entry.
  return ctx.files.some((f) => PYTHON_DEPS.test(f) && SUPABASE_PY.test(ctx.read(f)));
}

export const supabaseRlsRule: ScannerRule = {
  id: RULE_ID,
  category: "security",
  description: "Supabase Row Level Security",
  passedLabel: "Supabase tables have Row Level Security with real policies",
  // With Supabase but no SQL files the check reports "couldn't verify", so this only fires without either.
  notApplicable: (ctx) =>
    ctx.files.some((f) => SCHEMA.test(f) || MIGRATION.test(f)) || usesSupabase(ctx) ? undefined : "no Supabase found",
  run(ctx) {
    // schema.sql first as the base, then migrations in timestamp (file name) order: later statements win.
    const sqlFiles = [
      ...ctx.files.filter((f) => SCHEMA.test(f)),
      ...ctx.files.filter((f) => MIGRATION.test(f)).sort((a, b) => a.localeCompare(b)),
    ];
    if (sqlFiles.length === 0) {
      if (!usesSupabase(ctx)) return [];
      return [
        finding(
          "SEC_SUPABASE_RLS_UNVERIFIED",
          "info",
          "Supabase security rules aren't in the repo",
          `This app uses Supabase, but there are no SQL files in supabase/migrations, so LeakProof couldn't check whether your tables have Row Level Security. ${ADVISOR_TIP} ${UPSELL} ${UNVERIFIED_LINK}`,
          FIX_UNVERIFIED,
        ),
      ];
    }

    const tables = new Map<string, TableState>();
    for (const file of sqlFiles) applyStatements(tables, file, splitStatements(ctx.read(file)));

    const findings: ScanFinding[] = [];
    for (const t of tables.values()) {
      if (!t.key.startsWith("public.")) continue;
      // A table this repo never creates may have RLS turned on in the dashboard; only an explicit DISABLE counts.
      const off = !t.rls && (t.created || t.disabledAt);
      if (off) {
        const at = t.disabledAt ?? t.created!;
        const pii = personalData(t);
        findings.push(
          finding(
            "SEC_SUPABASE_RLS_DISABLED",
            "critical",
            "Supabase table has Row Level Security turned off",
            `Table ${t.key} has Row Level Security off, so anyone with your public anon key can read and change every row${!pii ? "" : pii.guessed ? `. It's ${GUESSED}` : `. It holds personal data: ${pii.text}`}.`,
            FIX_DISABLED(t.key),
            at.file,
            at.line,
          ),
        );
        continue; // its policies don't apply while RLS is off
      }
      for (const p of t.policies.values()) {
        const f = permissive(t, p);
        if (f) findings.push(f);
      }
    }
    return findings.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
  },
};

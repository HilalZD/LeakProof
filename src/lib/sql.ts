// A small SQL reader for Supabase migrations: just enough to follow tables,
// Row Level Security and policies. It never runs SQL or connects anywhere.

export interface SqlStatement {
  text: string; // comments blanked out, whitespace collapsed
  line: number; // 1-based line where the statement starts
}

/**
 * Splits SQL into statements on top-level semicolons. Comments (-- and
 * /* *\/) are dropped; '...' strings, "..." identifiers and $tag$...$tag$
 * bodies are kept whole, so a ; inside a function body doesn't split.
 */
export function splitStatements(sql: string): SqlStatement[] {
  const statements: SqlStatement[] = [];
  let current = "";
  let startLine = -1;
  let line = 1;
  const push = () => {
    const text = current.replace(/\s+/g, " ").trim();
    if (text) statements.push({ text, line: startLine });
    current = "";
    startLine = -1;
  };
  const add = (s: string) => {
    if (startLine === -1 && /\S/.test(s)) startLine = line;
    current += s;
  };

  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      while (i < sql.length && sql[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && next === "*") {
      i += 2;
      while (i < sql.length && !(sql[i] === "*" && sql[i + 1] === "/")) {
        if (sql[i] === "\n") line++;
        i++;
      }
      i += 2;
      add(" ");
      continue;
    }
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === c && sql[j + 1] === c) j += 2; // '' or "" escape
        else if (sql[j] === c) break;
        else j++;
      }
      const chunk = sql.slice(i, j + 1);
      add(chunk);
      line += chunk.split("\n").length - 1;
      i = j + 1;
      continue;
    }
    if (c === "$") {
      const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        const end = sql.indexOf(tag[0], i + tag[0].length);
        const stop = end === -1 ? sql.length : end + tag[0].length;
        const chunk = sql.slice(i, stop);
        add(chunk);
        line += chunk.split("\n").length - 1;
        i = stop;
        continue;
      }
    }
    if (c === ";") {
      push();
      i++;
      continue;
    }
    if (c === "\n") line++;
    add(c);
    i++;
  }
  push();
  return statements;
}

// An identifier: "Quoted Name" (case kept) or bare_name (lowercased by Postgres).
const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;
/** schema.table or table, as two capture groups. */
export const QUALIFIED = String.raw`(?:(${IDENT})\s*\.\s*)?(${IDENT})`;

/** Postgres folding: bare names are lowercased, quoted ones keep their case. */
export function normalizeIdent(raw: string): string {
  return raw.startsWith('"') ? raw.slice(1, -1).replace(/""/g, '"') : raw.toLowerCase();
}

/** "public.invites" style key; tables without a schema are in public. */
export function tableKey(schema: string | undefined, table: string): string {
  return `${schema ? normalizeIdent(schema) : "public"}.${normalizeIdent(table)}`;
}

/** The text inside the parenthesis that opens at `open`, or undefined if unbalanced. */
export function balanced(text: string, open: number): { inner: string; end: number } | undefined {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return { inner: text.slice(open + 1, i), end: i };
  }
  return undefined;
}

/** Splits on commas that aren't inside parentheses or quotes. */
export function splitTopLevel(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(text.slice(start));
  return parts.map((p) => p.trim()).filter(Boolean);
}

export type PolicyCommand = "ALL" | "SELECT" | "INSERT" | "UPDATE" | "DELETE";

export interface Policy {
  name: string;
  command: PolicyCommand;
  roles: string[]; // lowercased; ["public"] when no TO clause
  using?: string;
  withCheck?: string;
  restrictive: boolean;
  file: string;
  line: number;
}

export interface TableState {
  key: string; // public.invites
  created?: { file: string; line: number };
  columns: string[];
  rls: boolean;
  /** Where RLS was last turned off explicitly (ALTER TABLE ... DISABLE). */
  disabledAt?: { file: string; line: number };
  policies: Map<string, Policy>;
}

const CONSTRAINT_START = /^(?:constraint|primary|foreign|unique|check|exclude|like)\b/i;

function tableFor(tables: Map<string, TableState>, key: string): TableState {
  let t = tables.get(key);
  if (!t) {
    t = { key, columns: [], rls: false, policies: new Map() };
    tables.set(key, t);
  }
  return t;
}

/** The expression in "KEYWORD ( ... )" starting the search at `from`. */
function clause(text: string, keyword: RegExp): string | undefined {
  const m = keyword.exec(text);
  if (!m) return undefined;
  const open = text.indexOf("(", m.index + m[0].length - 1);
  return open === -1 ? undefined : balanced(text, open)?.inner.trim();
}

const USING = /\busing\s*\(/i;
const WITH_CHECK = /\bwith\s+check\s*\(/i;

function rolesOf(text: string): string[] | undefined {
  const m = /\bto\s+((?:"?[\w$]+"?\s*,\s*)*"?[\w$]+"?)(?=\s+(?:using|with)\b|\s*$)/i.exec(text);
  return m ? m[1].split(",").map((r) => normalizeIdent(r.trim())) : undefined;
}

/**
 * Applies statements in order to the table state: CREATE/DROP TABLE, ALTER
 * TABLE (RLS on/off, ADD COLUMN, RENAME), CREATE/ALTER/DROP POLICY. Later
 * statements win. Tables and policies are keyed by normalized names.
 */
export function applyStatements(tables: Map<string, TableState>, file: string, statements: SqlStatement[]): void {
  for (const { text, line } of statements) {
    let m: RegExpExecArray | null;

    m = new RegExp(String.raw`^create\s+(?:(?:global|local)\s+)?(?:(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?${QUALIFIED}\s*\(`, "i").exec(text);
    if (m) {
      const key = tableKey(m[1], m[2]);
      const t: TableState = { key, created: { file, line }, columns: [], rls: false, policies: new Map() };
      const body = balanced(text, m.index + m[0].length - 1);
      for (const part of splitTopLevel(body?.inner ?? "")) {
        if (CONSTRAINT_START.test(part)) continue;
        const col = new RegExp(`^(${IDENT})`).exec(part);
        if (col) t.columns.push(normalizeIdent(col[1]));
      }
      tables.set(key, t);
      continue;
    }

    m = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$`, "i").exec(text);
    if (m) {
      for (const name of splitTopLevel(m[1])) {
        const n = new RegExp(`^${QUALIFIED}$`).exec(name.trim());
        if (n) tables.delete(tableKey(n[1], n[2]));
      }
      continue;
    }

    m = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QUALIFIED}\s+(.*)$`, "i").exec(text);
    if (m) {
      const key = tableKey(m[1], m[2]);
      const rest = m[3];
      const rename = new RegExp(`^rename\\s+to\\s+(${IDENT})`, "i").exec(rest);
      if (rename) {
        const t = tables.get(key);
        if (t) {
          tables.delete(key);
          t.key = `${key.split(".")[0]}.${normalizeIdent(rename[1])}`;
          tables.set(t.key, t);
        }
        continue;
      }
      const t = tableFor(tables, key);
      for (const action of splitTopLevel(rest)) {
        if (/^enable\s+row\s+level\s+security$/i.test(action) || /^force\s+row\s+level\s+security$/i.test(action)) {
          t.rls = true;
          t.disabledAt = undefined;
        } else if (/^disable\s+row\s+level\s+security$/i.test(action)) {
          t.rls = false;
          t.disabledAt = { file, line };
        }
        const add = new RegExp(`^add\\s+(?:column\\s+)?(?:if\\s+not\\s+exists\\s+)?(${IDENT})`, "i").exec(action);
        if (add && !CONSTRAINT_START.test(action.replace(/^add\s+/i, ""))) t.columns.push(normalizeIdent(add[1]));
      }
      continue;
    }

    m = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+${QUALIFIED}(.*)$`, "i").exec(text);
    if (m) {
      const rest = m[4];
      const cmd = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest);
      const policy: Policy = {
        name: normalizeIdent(m[1]),
        command: (cmd ? cmd[1].toUpperCase() : "ALL") as PolicyCommand,
        roles: rolesOf(rest.split(/\busing\s*\(|\bwith\s+check\s*\(/i)[0]) ?? ["public"],
        using: clause(rest, USING),
        withCheck: clause(rest, WITH_CHECK),
        restrictive: /\bas\s+restrictive\b/i.test(rest),
        file,
        line,
      };
      tableFor(tables, tableKey(m[2], m[3])).policies.set(policy.name, policy);
      continue;
    }

    m = new RegExp(String.raw`^alter\s+policy\s+(${IDENT})\s+on\s+${QUALIFIED}(.*)$`, "i").exec(text);
    if (m) {
      const t = tableFor(tables, tableKey(m[2], m[3]));
      const name = normalizeIdent(m[1]);
      const p = t.policies.get(name);
      if (!p) continue;
      const rest = m[4];
      const rename = new RegExp(`^\\s*rename\\s+to\\s+(${IDENT})`, "i").exec(rest);
      if (rename) {
        t.policies.delete(name);
        p.name = normalizeIdent(rename[1]);
        t.policies.set(p.name, p);
        continue;
      }
      const roles = rolesOf(rest.split(/\busing\s*\(|\bwith\s+check\s*\(/i)[0]);
      if (roles) p.roles = roles;
      const using = clause(rest, USING);
      if (using !== undefined) p.using = using;
      const check = clause(rest, WITH_CHECK);
      if (check !== undefined) p.withCheck = check;
      p.file = file;
      p.line = line;
      continue;
    }

    m = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+${QUALIFIED}`, "i").exec(text);
    if (m) tables.get(tableKey(m[2], m[3]))?.policies.delete(normalizeIdent(m[1]));
  }
}

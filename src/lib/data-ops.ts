import { closeBracket } from "./imports.js";
import { isPersonalColumn, isPersonalTable } from "./personal.js";

// What a piece of server code does with the database: creates rows, changes
// or deletes them, or reads them, and whether those reads return personal data.

export type OpKind = "create" | "write" | "read";

export interface DataOp {
  kind: OpKind;
  table?: string;
  args: string;   // the call's arguments
  start: number;  // index of the call's "(" + 1
  end: number;    // index of its ")"
  /** For reads: the personal fields it returns. */
  personal: string[];
}

export interface DataSummary {
  data: boolean;
  creates: boolean;
  writes: boolean;
  reads: boolean;
  personal: string[];
  /** A create whose data is the raw request body (or the given body names). */
  rawCreate: boolean;
}

const CLIENT = String.raw`(?:prisma|db|tx|client|database|orm|ctx\.prisma|context\.prisma)`;
const PRISMA_OP = new RegExp(
  String.raw`\b${CLIENT}\.([\w$]+)\.(createManyAndReturn|createMany|create|updateMany|update|upsert|deleteMany|delete|find\w*|count|aggregate|groupBy)\s*\(`,
  "g",
);
const SUPABASE_OP = /\.from\s*(?:<[^>]*>)?\(\s*["'`]([\w.]+)["'`]\s*\)\s*\.(insert|upsert|update|delete|select)\s*\(/g;
const DRIZZLE_OP = /\bdb\.(select|insert|update|delete)\s*\(/g;
const SQL_CALL = /\b(?:db|pool|client|knex|conn|connection|sql)\.(?:query|execute|unsafe)\s*\(|\bsql\s*`/g;
const RPC = /\.rpc\s*\(/g;
const AUTH_ADMIN = /\.auth\.admin\.(listUsers|getUserById|getUser|createUser|inviteUserByEmail|updateUserById|deleteUser)\s*\(/g;
const BARE_FROM = /(?<!\b(?:storage|Array|Buffer|Uint8Array))\.from\s*\(\s*["'`]([\w.]+)["'`]/g;

const PRISMA_KIND = (op: string): OpKind =>
  op.startsWith("create") ? "create" : /^(?:update|upsert|delete)/.test(op) ? "write" : "read";
const SUPABASE_KIND: Record<string, OpKind> = { insert: "create", upsert: "write", update: "write", delete: "write", select: "read" };

const firstString = (text: string) => /["'`]((?:\\.|[^"'`\\])*)["'`]/.exec(text)?.[1];
const tokens = (text: string) => text.match(/[A-Za-z_][\w]*/g) ?? [];
const unique = (xs: string[]) => [...new Set(xs)];

/** Personal columns in a column list ("id, email, profiles(full_name)"), or the whole table for "*". */
function personalInColumns(columns: string | undefined, table: string | undefined): string[] {
  if (columns === undefined || /^\s*\*?\s*$/.test(columns) || /(?:^|,)\s*\*\s*(?:,|$)/.test(columns)) {
    return table && isPersonalTable(table) ? [`all columns of ${table}`] : [];
  }
  return unique(tokens(columns).filter((t) => isPersonalColumn(t, table) || (t !== table && isPersonalTable(t) && new RegExp(`\\b${t}\\s*\\(`).test(columns))));
}

/** Keys of the object literal after `key:` in text, e.g. the fields of `select: { email: true }`. */
function blockKeys(text: string, key: string): string[] | undefined {
  const m = new RegExp(`\\b${key}\\s*:\\s*\\{`).exec(text);
  if (!m) return undefined;
  const open = m.index + m[0].length - 1;
  return [...text.slice(open, closeBracket(text, open)).matchAll(/([\w$]+)\s*:/g)].map((k) => k[1]);
}

function personalInPrismaRead(model: string, args: string): string[] {
  const select = blockKeys(args, "select");
  if (select) return unique(select.filter((k) => isPersonalColumn(k, model) || isPersonalTable(k)));
  const relations = (blockKeys(args, "include") ?? []).filter((k) => isPersonalTable(k));
  return unique([...(isPersonalTable(model) ? [`all fields of ${model}`] : []), ...relations]);
}

/** Classifies a SQL string: INSERT → create, UPDATE/DELETE → write, SELECT → read. */
function sqlOp(sql: string): { kind: OpKind; table?: string; personal: string[] } | undefined {
  let m = /\binsert\s+into\s+([\w."]+)/i.exec(sql);
  if (m) return { kind: "create", table: m[1], personal: [] };
  m = /\bupdate\s+([\w."]+)\s+set\b/i.exec(sql) ?? /\bdelete\s+from\s+([\w."]+)/i.exec(sql);
  if (m) return { kind: "write", table: m[1], personal: [] };
  m = /\bselect\b([\s\S]*?)\bfrom\s+([\w."]+)/i.exec(sql);
  if (m) return { kind: "read", table: m[2], personal: personalInColumns(m[1].trim(), m[2].replace(/"/g, "")) };
  return undefined;
}

function argsAt(code: string, openParen: number): { args: string; start: number; end: number } {
  const close = closeBracket(code, openParen);
  return { args: code.slice(openParen + 1, close - 1), start: openParen + 1, end: close - 1 };
}

/** Every database call in the code, in order. */
export function dataOps(code: string): DataOp[] {
  const ops: DataOp[] = [];

  for (const m of code.matchAll(PRISMA_OP)) {
    const a = argsAt(code, m.index! + m[0].length - 1);
    const kind = PRISMA_KIND(m[2]);
    ops.push({ kind, table: m[1], ...a, personal: kind === "read" ? personalInPrismaRead(m[1], a.args) : [] });
  }
  for (const m of code.matchAll(SUPABASE_OP)) {
    const a = argsAt(code, m.index! + m[0].length - 1);
    const kind = SUPABASE_KIND[m[2]];
    ops.push({ kind, table: m[1], ...a, personal: kind === "read" ? personalInColumns(firstString(a.args), m[1]) : [] });
  }
  for (const m of code.matchAll(DRIZZLE_OP)) {
    const a = argsAt(code, m.index! + m[0].length - 1);
    const kind = SUPABASE_KIND[m[1]];
    const table = kind === "read" ? /^\s*\.from\s*\(\s*([\w$]+)/.exec(code.slice(a.end + 1))?.[1] : tokens(a.args)[0];
    const keys = [...a.args.matchAll(/([\w$]+)\s*:/g)].map((k) => k[1]);
    const personal = kind !== "read" ? [] : keys.length > 0 ? unique(keys.filter((k) => isPersonalColumn(k, table))) : table && isPersonalTable(table) ? [`all columns of ${table}`] : [];
    ops.push({ kind, table, ...a, personal });
  }
  for (const m of code.matchAll(SQL_CALL)) {
    const isTemplate = m[0].endsWith("`");
    const start = m.index! + m[0].length - 1;
    const a = isTemplate ? { args: code.slice(start + 1, code.indexOf("`", start + 1)), start: start + 1, end: code.indexOf("`", start + 1) } : argsAt(code, start);
    const sql = isTemplate ? a.args : firstString(a.args) ?? "";
    const op = sqlOp(sql) ?? { kind: "read" as OpKind, personal: [] };
    ops.push({ ...op, ...a });
  }
  for (const m of code.matchAll(RPC)) ops.push({ kind: "read", ...argsAt(code, m.index! + m[0].length - 1), personal: [] });
  for (const m of code.matchAll(AUTH_ADMIN)) {
    const kind: OpKind = /^(?:list|get)/.test(m[1]) ? "read" : /^(?:create|invite)/.test(m[1]) ? "create" : "write";
    ops.push({ kind, table: "auth.users", ...argsAt(code, m.index! + m[0].length - 1), personal: kind === "read" ? ["auth users"] : [] });
  }
  // A .from("table") that isn't followed by a known operation: a read of unknown columns.
  for (const m of code.matchAll(BARE_FROM)) {
    // Already counted when a known operation follows it: .from("t").select(...) starts a few characters later.
    if (ops.some((o) => o.table === m[1] && o.start > m.index! && o.start - m.index! < m[0].length + 80)) continue;
    ops.push({ kind: "read", table: m[1], args: "", start: m.index!, end: m.index!, personal: personalInColumns(undefined, m[1]) });
  }
  return ops.sort((a, b) => a.start - b.start);
}

/** Names that hold the raw request body: const body = await req.json(), req.body. */
export function bodyNames(code: string): string[] {
  return unique(
    [...code.matchAll(/(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:await\s+)?(?:req|request|c\.req|event)\.(?:json|body|formData)\b/g)].map((m) => m[1]),
  );
}

/** Whether a create's arguments are the raw body: insert(body), insert({ ...body }), create({ data: body }). */
export function isRawCreate(args: string, names: string[]): boolean {
  const alts = [...names.map((n) => n.replace(/\$/g, "\\$")), String.raw`req\.body`, String.raw`(?:await\s+)?(?:req|request)\.json\(\s*\)`].join("|");
  return (
    new RegExp(String.raw`^\s*\[?\s*(?:${alts})\s*\]?\s*$`).test(args) ||
    new RegExp(String.raw`\.\.\.\s*(?:${alts})\b`).test(args) ||
    new RegExp(String.raw`\bdata\s*:\s*(?:${alts})\s*[,}]`).test(args)
  );
}

/** Personal keys in the objects a route sends back: Response.json({ email }), res.json({ phone: ... }). */
function personalInResponses(code: string): string[] {
  const keys: string[] = [];
  for (const m of code.matchAll(/\.json\s*\(/g)) {
    const { args } = argsAt(code, m.index! + m[0].length - 1);
    for (const k of args.matchAll(/([\w$]+)\s*:/g)) if (isPersonalColumn(k[1], "")) keys.push(k[1]);
  }
  return unique(keys);
}

/** Summary of the database work in `code`. `extraBodyNames` are names known to hold the raw body. */
export function summarize(code: string, extraBodyNames: string[] = [], responses = false): DataSummary {
  const ops = dataOps(code);
  const names = [...bodyNames(code), ...extraBodyNames];
  // Response keys count only outside create/update arguments (the fields a form saves aren't a read).
  let readContext = code;
  for (const o of ops.filter((o) => o.kind !== "read").sort((a, b) => b.start - a.start)) {
    readContext = readContext.slice(0, o.start) + " ".repeat(Math.max(0, o.end - o.start)) + readContext.slice(o.end);
  }
  const reads = ops.filter((o) => o.kind === "read");
  return {
    data: ops.length > 0,
    creates: ops.some((o) => o.kind === "create"),
    writes: ops.some((o) => o.kind === "write"),
    reads: reads.length > 0,
    personal: unique([...reads.flatMap((o) => o.personal), ...(responses && reads.length > 0 ? personalInResponses(readContext) : [])]),
    rawCreate: ops.some((o) => o.kind === "create" && isRawCreate(o.args, names)),
  };
}

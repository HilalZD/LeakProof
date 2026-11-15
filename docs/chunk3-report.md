# Chunk 3 report (overnight run, Nov 15, 2026)

## 1. What got built
- **3A Supabase RLS checks** (`55670b5`): `src/lib/sql.ts` reads `supabase/schema.sql` and then `supabase/migrations/*.sql` in timestamp order. It handles comments, `$$` bodies, several statements per file, quoted/schema-qualified/any-case names, CREATE/DROP/ALTER TABLE (ENABLE/DISABLE RLS, ADD COLUMN, RENAME) and CREATE/ALTER/DROP POLICY. `src/rules/supabase-rls.ts` emits SEC_SUPABASE_RLS_DISABLED, SEC_SUPABASE_RLS_PERMISSIVE (critical/high/low as specced; service_role-only and RESTRICTIVE policies are skipped) and SEC_SUPABASE_RLS_UNVERIFIED (info).
- **3B API route auth** (`616eafb`): `src/rules/api-auth.ts` emits SEC_API_ROUTE_NO_AUTH (high) for TanStack `routes/api`, Next `app/api/**/route.ts`, `pages/api` and Supabase edge functions that touch data (`.from("t")`, `.rpc`, `auth.admin`, prisma, db/pool queries, sql``) with no auth check. It reuses rate-limit's LOGIN_CHECKS, now exported, and also accepts imported auth middleware.
- **3C follow-up** (`19d8dba`): project-wide middleware/`proxy.ts` now covers only the paths in its `matcher`.
- **Final checks** (`2c5b20d`): a check with an info ("couldn't verify") finding no longer shows a ✓. Answer key "Expected results" updated.

## 2. Status
274 tests pass (247 → 274, +27). Typecheck clean. Build OK. Ran after every part.

## 3. NoteNest
Broken (full output, 99 lines: `docs/chunk3-notenest-broken-output.txt`):
```
Score 0/100 · Grade F · 7 critical, 3 high, 1 medium      (exit 1)
CRITICAL stripe-webhook.ts:7 · invites.sql:2 RLS_DISABLED (#7) · public_profiles.sql:2 RLS_PERMISSIVE (#8)
         AdminStats.tsx:7 · .env:10 (+TitleSuggest.tsx:13) · src/lib/ai.ts:1 · .env:8
HIGH     src/routes/api/users.ts:8 API_ROUTE_NO_AUTH (#10) · summarize-note.ts:10 · .env:9 (+.env:7, payments.ts:14)
MEDIUM   send-invite.ts:16
```
All 8 earlier findings are unchanged. No decoys flagged. #7, #8 and #10 are new.
Main: `Score 99/100 · Grade A · 1 low` + 1 "Couldn't verify" (RLS_UNVERIFIED), exit 0. NoteNest is left on `broken`.

## 4. 3C real apps (read-only scans)
| App | Stack | Findings | Real | FP |
|---|---|---|---|---|
| App 1 | Next 16 + Supabase (schema.sql, 13 API routes) | 0 | 0 | 0 |
| App 2 | Next, static site | 0 | 0 | 0 |
| App 3 | Next + Prisma/SQLite (4 API routes) | 0 | 0 | 0 |

FP rate per rule: 0/0 for every rule (no findings). I hand-checked for misses:
- App 1: RLS is on for all 4 tables with no policies, so it's correct not to flag. The public routes (login, PIN unlock, rate-limited AI read) are public on purpose. The rest call `requireClinician`.
- App 3: no Supabase. Its routes are public on purpose (booking, availability, certificates) or better-auth.
- App 2: no server code or secrets.

No rule was noisy, so there is no "Reduce false positives" commit. Reviewing App 1 exposed a gap in my own rule: any auth middleware hid every route, whatever its matcher said. Fixed in `19d8dba`.
**Caveat:** these apps barely exercise the new rules. App 1 and App 3 reach data through `lib/` helpers, which the API-auth rule doesn't follow, so 0 FP here says little about precision.

## 5. Decisions I made
1. schema.sql is applied first, then migrations by file name, so later statements win (a migration is newer than the base).
2. Tables the repo never creates (e.g. NoteNest's `profiles`) are only RLS_DISABLED on an explicit DISABLE, since RLS may be on in the dashboard. Their policies are still checked.
3. Personal data = column names (email, phone, address, name variants, *_id of users/owners/patients, dob, ip…). If columns are unknown, people-ish table names count (profiles, users, customers…). That's what makes #8 critical.
4. Writes with USING/WITH CHECK (true) are critical even TO authenticated (anyone can sign up). The authenticated → high rule applies to SELECT only. INSERT is judged by WITH CHECK, UPDATE/ALL by USING.
5. When RLS is off, that table's policies aren't reported (the RLS finding covers them).
6. RLS findings: confidence medium. API-auth: high with the admin client, medium otherwise.
7. API-auth reports the handler line (`GET: async`), not the query line. That matches answer-key line 8.
8. Routes under `api/public/` are skipped unless they use the admin client (Lovable's public-route convention). Paths containing "webhook" and signature-verifying files are skipped too.
9. `storage.from()` and `Array/Buffer.from("…")` don't count as data access.
10. Main now shows 1 info finding (UNVERIFIED). Spec 3A.4 requires it, and it doesn't touch score or exit code, so I treated it as correct and not a "new finding" bug.
11. The full broken output is in a separate file to keep this report under 80 lines.

## 6. Skipped / needs your call
- NoteNest main's real policies/routes: there are none in its repo (no migrations, only the verified webhook), so this couldn't really be tested.
- Known gaps: data access through helpers in other files; `createServerFn`; Express/Hono routes; `supabase/schemas/*.sql`; GRANT statements aren't used (e.g. `GRANT … TO anon` could raise confidence).
- INSERT `WITH CHECK (true)` for public forms (waitlists, contact forms) will be critical per the spec. On real Lovable apps that may be noisy. Consider lowering it when the table has no SELECT policy.
- Message wording for #8 when the personal data is guessed from the table name reads a bit awkwardly.

## 7. Proposed new fixIds (not added)
None. Every case fits the existing IDs by lowering severity.

# Chunk 3 progress

## Done
- 3A Supabase RLS checks (`src/lib/sql.ts`, `src/rules/supabase-rls.ts`). NoteNest broken: #7 → RLS_DISABLED critical, #8 → RLS_PERMISSIVE critical.
- 3B API route auth check (`src/rules/api-auth.ts`). NoteNest broken: #10 → SEC_API_ROUTE_NO_AUTH high at src/routes/api/users.ts:8. Broken now: 11 findings (7 critical, 3 high, 1 medium).
- 3C real-app accuracy scans: 0 findings on all 3 apps, each checked by hand as a true negative. No rule was noisy, so there was no FP commit. Fixed an API-auth gap found while reviewing (middleware matcher, proxy.ts).
- Final checks: broken matches the answer key; main is 99/A with 1 low + 1 info. Fixed the ✓ that showed for a check that couldn't verify. Answer key updated.
- Chunk 3 report: docs/chunk3-report.md (full NoteNest broken output in docs/chunk3-notenest-broken-output.txt).

## In progress
- Nothing

## Next
- Hilal: review the decisions and proposals in the report

## Chunk 3D (Nov 15, 2026)
- Done: server functions, helper/alias following (one level), public-form INSERT → medium, Couldn't-verify upsell, #8 wording. Planted #11 on NoteNest broken (src/lib/members.ts:5), caught.
- Real apps: App 3 now gets 2 SEC_API_ROUTE_NO_AUTH false positives (public availability + booking form, data through @/lib helpers). Not tuned yet: needs Hilal's call.

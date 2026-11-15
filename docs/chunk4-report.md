# Chunk 4 report (overnight run, Nov 15, 2026)

## 1. What got built
- **Setup**: `Bash(npm publish:*)` added to deny in `.claude/settings.local.json` (gitignored, not committed).
- **Step 0** (`56eed12`): answer key #10/#11 now quote the current titles and messages.
- **4A** (`50ca97d`): `--fail-on <critical|high|medium|low>` (default medium). `--format text|json|github`: annotations plus a Markdown job summary written to `$GITHUB_STEP_SUMMARY` (`src/github.ts`). `action.yml` composite action, `docs/github-action.md`. `scan` is now the default command.
- **4B** (`4e4bef0`): v0.2.0 (package.json, lockfile, action.yml). Not published. Launch README, `CHANGELOG.md`, `docs/demo.tape`.
- **4C** (`33b1cd4`): `src/telemetry.ts`, `leakproof telemetry on|off|status`, `LEAKPROOF_TELEMETRY`, `TELEMETRY_URL` placeholder, footer hint, `docs/telemetry.md`.

## 2. Status
344 tests pass (324 after 4A, 344 after 4C; 298 at the start of the run). Typecheck clean, build OK after every part. No part needed a revert.
Final checks: NoteNest broken has the same 12 findings (7 critical, 4 high, 1 medium), Score 0/F, exit 1. Main: 99/A, 1 low + 1 info, exit 0. NoteNest is back on `broken`. Real apps (read-only, `git status` the same before and after): a clinic app 100/A, a static coaching site 100/A, a booking site 99/A with 1 low (see 5).

## 3. `--format github` on NoteNest broken (first 15 of 17 lines, cut at 120 chars here)
```
::error file=src/routes/api/public/stripe-webhook.ts,line=7::Stripe webhook doesn't verify signatures: Anyone can send…
::error file=supabase/migrations/20261114120000_invites.sql,line=2::Supabase table has Row Level Security turned off: …
::error file=supabase/migrations/20261114120100_public_profiles.sql,line=2::Supabase security rule lets everyone in: …
::error file=src/components/AdminStats.tsx,line=7::Supabase service_role key in frontend code: The key eyJhbGci****0001…
::error file=.env,line=10::Secret key exposed to the browser: VITE_OPENAI_API_KEY is shipped to the browser: sk-proj-****6iO8
::error file=src/components/TitleSuggest.tsx,line=13::Secret key exposed to the browser: same secret as .env:10. …
::error file=src/lib/ai.ts,line=1::Secret key exposed to the browser: OpenAI API key in frontend code, … sk-proj-****W1xY
::error file=.env,line=8::.env file with secrets committed: SUPABASE_SERVICE_ROLE_KEY is committed to git: eyJhbGci****2345
::error file=src/lib/members.ts,line=5::Server function has no login check: This server function reads user data with …
::error file=src/routes/api/users.ts,line=8::API route has no login check: This route reads user data with the Supabase …
::error file=src/routes/api/summarize-note.ts,line=10::Endpoint has no rate limit: This endpoint calls OpenAI with no …
::error file=.env,line=9::Secret key exposed to the browser: VITE_STRIPE_SECRET_KEY is shipped to the browser: sk_test_****M5wZ
::error file=.env,line=7::Secret key exposed to the browser: same secret as .env:9. VITE_STRIPE_SECRET_KEY is shipped …
::error file=src/lib/payments.ts,line=14::Secret key exposed to the browser: same secret as .env:9. …
::warning file=src/routes/api/send-invite.ts,line=16::Endpoint has no rate limit: This endpoint sends email through Resend…
```
Lines 16–17: `Leakproof: Score 0/100 · Grade F · 7 critical, 4 high, 1 medium` and `Fixes: <fix link>`.

## 4. Decisions
1. **`scan` is the default command.** `npx @leakproof/cli <path>` failed before ("unknown command"), and the action and README both need that form. `leakproof scan <path>` still works.
2. `--format` wins over `--json`; `--json` stays as a shortcut. JSON and GitHub output never have colors.
3. info never fails a scan; `--fail-on info` is rejected (exit 2). info annotations are `::notice`.
4. Each "also at" place gets its own annotation ("same secret as …"), so every leaking line gets an annotation in the PR.
5. A failed `$GITHUB_STEP_SUMMARY` write prints one stderr line. It doesn't change the exit code.
6. action.yml has no setup-node step (hosted runners ship Node 20+). Inputs go through env vars, so they can't inject shell commands. A test keeps the pinned version equal to package.json.
7. README: the example is a real scan with the middle trimmed and marked "…". The old SVG demos are no longer referenced (files kept). CHANGELOG marks 0.2.0 "unreleased".
8. demo.tape warms up npx off camera. It needs 0.2.0 on npm, or the commented local `dist` line.
9. Telemetry: `LEAKPROOF_TELEMETRY=0` beats the config file. CI means any of 8 common CI vars. A broken config counts as off. Rule counts are per reported finding (ignored findings not counted). Stack detection is a new `ScanResult.stack`.
10. When telemetry is on, the footer stops saying "Nothing was sent anywhere". The job summary now says "Your code never left the runner." The opt-in hint appears only in the text report, only when off, and never in CI.
11. Sending starts after the report prints and isn't awaited, but Node can stay alive up to 1.5s for it. Any non-https or placeholder URL sends nothing.
12. A stray masked scan output was left in a scratch folder outside the repo from my first run (a mistake). It holds no full keys. Not deleted, per the no-delete rule.

## 5. Left for 4D / needs your call
- **The booking site, 1 low** ("Public route reads data without login"): it comes from a change made before tonight. Chunk 4 changed no rule or lib file. The chunk 3 report's "0 findings" is stale for this app. The route is public on purpose, so consider allowlisting such routes, or accept the low.
- Join Serena's privacy rules (`PRIV_*`), then change README "coming in v0.2" to the real list. Join Yara's site: set `SITE_URL`.
- `TELEMETRY_URL`: needs a real endpoint, and a privacy note on the site, before anything is sent.
- Tag `v0.2` (plus `v0.2.0`) after review so `HilalZD/LeakProof@v0.2` resolves. Publish `@leakproof/cli@0.2.0` yourself (npm publish is denied here). Record the GIF, then swap the README placeholder.
- Review: the annotation line format (title in the message, no `title=` property, as specced), and whether the extra "also at" annotations are too noisy.

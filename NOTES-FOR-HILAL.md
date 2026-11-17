# Notes for Hilal (from Serena's output-polish branch)

Things I noticed while changing the default terminal output on `serena/output-polish`. I didn't change any of them unless a note says so.

## Decisions made in this branch (please check)

1. **"Couldn't verify" items aren't counted as problems.** The short summary counts critical, high, medium and low findings, both security and privacy. Info findings such as SEC_SUPABASE_RLS_UNVERIFIED are left out of the count, and one line at the end says "N check(s) couldn't run. See --details." As a result:
   - An app whose only finding is "Couldn't verify" still prints only `No problems found` (Serena asked to keep it that way), so the Supabase RLS tip doesn't appear without `--details`.
   - The fix link still includes the info fix ID (e.g. `e8`). I used `summarize().fixLink` as it is and didn't touch `fix-order.ts`.
   - Checks skipped with `CheckSkipped` (e.g. git missing) aren't in the "couldn't run" count. They only show up with `--details`.
2. **`--verbose` still prints the full report** (and adds the checks list). Otherwise `--verbose` would do nothing without `--details`.
3. **Renaming "Leakproof Cloud" changed `--json` and GitHub output text.** The sentence lives in the finding message (`UPSELL` in `src/rules/supabase-rls.ts`), so the message field now says "Leakproof will check your live database rules…". I asked Serena and she chose to rename it everywhere. Nothing else in `--json` or GitHub output changed, and exit codes are the same.

## Only shown with `--details` now

4. **The telemetry opt-in hint** ("Help improve Leakproof…"). The summary's second line is "Scanned on your computer. Nothing was uploaded." when telemetry is off. When it's on, that line is replaced by the same "anonymous usage counts are on (`leakproof telemetry off`)" notice the full report uses, and the notice also appears under `No problems found`. I checked `src/` for network calls: the only one is `sendTelemetry`, and it runs only when telemetry is on.
5. **Skipped-check warnings (⚠ … skipped) and the "N ignored" count.**
6. **The `--details` hint always says `npx @leakproof/cli --details`**, even when the user scanned another folder (e.g. `npx @leakproof/cli ./my-app`).

## Not changed, worth a look

7. **`npm ci` reported 7 high-severity vulnerabilities** (`npm audit`).
8. **npm's allow-scripts didn't run esbuild's install script** (`esbuild@0.28.2 postinstall`). The build still worked.
9. **`docs/broken-app-answer-key.md` line 83 still says "Leakproof Cloud".** It's an old test note, not printed text.
10. **Demo images are out of date.** `docs/demo.gif` and the images made by `scripts/demo.mjs` show the old full report as the default output. The demo would need `--details` to show the full report again.
11. **CHANGELOG.md isn't updated for this change.** I left it for you, since you publish.
12. **`npx @leakproof/cli --help` lists only the commands, not the scan options.** That was already the case before this branch. `--details` and all the other flags appear under `npx @leakproof/cli scan --help`.

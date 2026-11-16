# Changelog

## 0.2.0 (unreleased)

- **Fix links use `#f=`** (`/fix#f=ID1,ID2`): the IDs after `#` are never sent to a server.

### New checks
- **Secrets the browser can reach** (`SEC_SECRET_CLIENT_EXPOSED`): secret keys in frontend files and in `VITE_` / `NEXT_PUBLIC_` variables. Test keys are lowered to high.
- **Supabase admin key in the frontend** (`SEC_SUPABASE_SERVICE_ROLE_CLIENT`): the `service_role` key used in browser code.
- **Supabase Row Level Security** (`SEC_SUPABASE_RLS_DISABLED`, `SEC_SUPABASE_RLS_PERMISSIVE`, `SEC_SUPABASE_RLS_UNVERIFIED`): reads `supabase/schema.sql` and `supabase/migrations/*.sql` in order. Flags tables with RLS off and policies that let everyone in, ranked by whether the table holds personal data. Says "Couldn't verify" when there are no SQL files, with the Security Advisor tip.
- **Login checks** (`SEC_API_ROUTE_NO_AUTH`): TanStack API routes, Next.js `app/api` and `pages/api` routes, Supabase edge functions and TanStack server functions (`createServerFn`) that touch user data with no auth check. Writes and personal data rank higher than reads. Respects middleware and `proxy.ts` matchers.
- **Rate limits** (`SEC_API_NO_RATE_LIMIT`): public endpoints that call paid AI APIs or send email/SMS with no rate limit. Medium when login is required.
- **Committed `.env` with only public values** (`SEC_ENV_COMMITTED_PUBLIC_ONLY`) is now its own low warning.

### New privacy checks (Part B, by Serena)
Possible gaps against GDPR and PIPEDA, shown in their own section with law references, a one-line fix for high/medium, and "(low confidence)" where it applies. They never change the score or exit code unless `--fail-on-privacy` is set. Not legal advice.
- `PRIV_NO_PRIVACY_POLICY` (high): personal data leaves the browser at a public form, sign-up or API route and there's no privacy page, link, or privacy section in the terms. Admin pages, webhooks, local-only forms and SQL columns don't count.
- `PRIV_TRACKER_BEFORE_CONSENT` (high): an analytics or ad tracker loads with no consent tool, one finding per tracker.
- `PRIV_PII_TO_THIRD_PARTY` (medium): personal data in analytics `identify` calls, or a file that calls an AI API and uses personal data (low confidence).
- `PRIV_NO_ACCOUNT_DELETION` (medium) and `PRIV_NO_DATA_EXPORT` (low): users can sign themselves up but can't delete their account or download their data. Operator-created accounts don't count.
- `PRIV_PII_IN_LOGS` (medium): a log call prints a variable named like email, phone, password, address, token or user, one finding per line.

### New report
- Security score out of 100 and a grade (A–F), from security findings only. Any critical caps the score at 39, any high at 59.
- Privacy gaps get their own "PRIVACY GAPS (possible)" section, a "Privacy: N possible gaps (not legal advice)" line under the score, and "This is not legal advice." once.
- One-line fix for every critical and high finding, and one fix link with the fix IDs only (never code, paths or values).
- One finding per leak: when several checks flag the same line, the most specific wins. The same secret found in several places is grouped, with "also at" lines.
- "Couldn't verify" section for checks that had nothing to read. These never get a ✓ and don't affect the score.
- The header no longer shows the folder name, so screenshots don't leak project names.

### New options
- `leakproof [path]`: `scan` is now the default command, so `npx @leakproof/cli` works on its own. `leakproof scan [path]` still works.
- `--json` / `--format json`: machine-readable output with summary, findings and skipped checks.
- `--format github`: GitHub Actions annotations (`::error` for critical/high, `::warning` for medium/low) and a Markdown job summary in `$GITHUB_STEP_SUMMARY`.
- `--fail-on <critical|high|medium|low>`: choose which security severity fails the scan. Default: `medium`.
- `--fail-on-privacy <high|medium|low>`: also fail on privacy gaps at that severity or worse. Off by default.
- JSON summary has `security: {score, grade, counts}` and `privacy: {count, bySeverity}`. The top-level `score`, `grade` and `counts` are the security values. In `--format github`, privacy gaps are always `::notice`.
- `.leakproofignore`: ignore by fix ID, by path or glob, or by `path:fixId`.

### GitHub Action
- `action.yml` composite action: `uses: HilalZD/LeakProof@v0.2` with `fail-on` and `path` inputs. See `docs/github-action.md`.

### Opt-in anonymous usage counts
- Off by default. `leakproof telemetry on|off|status`, or `LEAKPROOF_TELEMETRY=1`. Never on in CI unless the env var is set.
- Sends only the CLI version, OS, which fix IDs came up and how often, a files-checked range and vite/next/supabase yes/no. No paths, code, values, names or IDs. See `docs/telemetry.md`.
- The endpoint is still a placeholder, so nothing is sent yet.

### Any language
- The secret-key check reads every text source and config file (Python, Go, Ruby, PHP, Java, shell, Terraform, `.ipynb`, `Dockerfile`…), not only JS/TS. Outside JS/TS its fix says to move the key into an environment variable. Docs (`.md`, `.txt`) and lockfiles are skipped.
- Dependency and cache folders in other languages are skipped (`.venv`, `venv`, any virtualenv, `__pycache__`, `.pytest_cache`, `site-packages`, `*.egg-info`, `vendor`, `target`, `.gradle`, `Pods`).
- Supabase "Couldn't verify" also spots `supabase` in `requirements.txt`, `pyproject.toml` or `Pipfile`.
- Committed `.env` checks already worked in any language. Route, auth, rate-limit, webhook and privacy checks stay JS/TS only.
- On a project with no JS/TS code, those checks don't run and show as "– Not checked: <check> (no JS/TS code found)" in the report, the GitHub summary and JSON (`notChecked`), never as ✓. The privacy line says "Privacy: not checked".
- ✓ only for checks that inspected something. A check that found nothing to inspect shows as "– Not applicable: <check> (no Supabase found)" (no Stripe webhook, no API routes or server functions, no paid or sensitive endpoints, no frontend code or `.env` files, no personal data collection, no trackers, no self sign-up, no log calls…), in the report, `--verbose`, the GitHub summary and JSON (`notChecked` with `reason: "not-applicable"` and a `detail`). When every privacy check is not applicable the privacy line says "Privacy: not applicable".
- The fix-link label now reads "Copy-paste fixes for Lovable, Bolt, Cursor, Claude Code or Codex:".

### Other
- Documented example keys (AWS's and Stripe's docs) are never flagged.
- Requires Node.js 20 or newer.

## 0.1.0

- First release: leaked secret keys in code, committed `.env` files, Stripe webhook signature verification.

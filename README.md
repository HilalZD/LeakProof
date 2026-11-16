# Leakproof

**Find the leaks AI coding tools leave behind. One command, runs locally, sends nothing.**

![Leakproof scanning a test app](https://raw.githubusercontent.com/HilalZD/LeakProof/main/docs/demo.gif)

## Quick start

Run it inside your project folder:

```sh
npx @leakproof/cli
```

Or point it at another folder:

```sh
npx @leakproof/cli ./my-app
```

Requires Node.js 20 or newer. No account, no signup.

Works on apps built with any AI tool (Lovable, Bolt, v0, Replit, Cursor, Claude Code, Codex…) or by hand. The secret and `.env` checks work in any language; the rest are JS/TS for now (see [Which checks run on which code](#which-checks-run-on-which-code)).

## Example output

A real scan of NoteNest, a test app with deliberate leaks (keys are fake and masked, the middle is trimmed):

```text
Leakproof v0.2.0 · 101 files checked · 1.1s

Security 0/100 · Grade F · 7 critical, 4 high, 1 medium
Privacy: 3 possible gaps (not legal advice)

── CRITICAL (7) ────────────────────────────────────────────────────────────────

  Stripe webhook doesn't verify signatures
  src/routes/api/public/stripe-webhook.ts:7
    Anyone can send a fake 'payment completed' event and unlock paid features
    for free.
    → Fix: Verify the stripe-signature header with
           stripe.webhooks.constructEvent(rawBody, signature,
           STRIPE_WEBHOOK_SECRET) before trusting the event. Use the raw request
           body, not parsed JSON.

  Supabase table has Row Level Security turned off
  supabase/migrations/20261114120000_invites.sql:2
    Table public.invites has Row Level Security off, so anyone with your public
    anon key can read and change every row. It holds personal data: inviter_id,
    email.
    → Fix: Run ALTER TABLE public.invites ENABLE ROW LEVEL SECURITY; then add
           policies so each user only sees their own rows, e.g. USING
           (auth.uid() = user_id).

  Supabase service_role key in frontend code
  src/components/AdminStats.tsx:7
    The key eyJhbGci****0001 skips Row Level Security, so anyone who opens the
    site can read or change every table.
    → Fix: Use the anon or publishable key in the browser. Keep the service_role
           key in server-only code (an API route or server function) and rotate
           it now.

  … 4 more critical findings …

── HIGH (4) ────────────────────────────────────────────────────────────────────

  Server function has no login check
  src/lib/members.ts:5
    This server function reads user data with the Supabase admin client, which
    skips Row Level Security, and never checks who is calling: anyone can call
    it over HTTP and get the data.
    → Fix: Add an auth middleware to the server function (e.g.
           .middleware([requireSupabaseAuth])) or check supabase.auth.getUser()
           first, and only return the caller's own rows.

  … 3 more high findings, 1 medium …

── PRIVACY GAPS (possible) (3) ─────────────────────────────────────────────────

  Users can't delete their account
  src/routes/auth.tsx:38
    Possible gap: users can create their own accounts in this app (sign-up in
    src/routes/auth.tsx, line 38) but we couldn't find a way for users to delete
    their account and data.
    GDPR Art. 17 · PIPEDA 4.3.8 · PIPEDA 4.5.3
    → Fix: Add a "Delete my account" option that removes the user's account and
           their data on the server.

  … 2 more possible gaps …

This is not legal advice.

Copy-paste fixes for Lovable, Bolt, Cursor, Claude Code or Codex:
https://SITE_URL_PLACEHOLDER/fix#f=SEC_STRIPE_WEBHOOK_UNSIGNED,SEC_SUPABASE_RLS_DISABLED,…

Scanned locally. Nothing was sent anywhere.
Help improve Leakproof: `leakproof telemetry on` shares anonymous counts (never code).
```

The security score starts at 100 and loses points per security finding (critical 25, high 10, medium 4, low 1). Any critical caps it at 39 (grade F), any high at 59 (grade D). Privacy gaps are listed separately and never change the score.

## What it checks

### Security

| Check | What it finds | Severity |
|---|---|---|
| Secret keys in code | API keys written straight into your code, in any language: OpenAI, Anthropic, Stripe, Supabase `service_role` and `sb_secret_`, AWS, GitHub | Critical (Stripe test keys: High) |
| Secrets the browser can reach | Secret keys in frontend files, or in `VITE_` / `NEXT_PUBLIC_` variables, which get bundled into the site visitors download | Critical (test keys: High) |
| Supabase admin key in the frontend | The `service_role` key, which skips every database rule, used in browser code | Critical |
| Committed `.env` files | A `.env` with real secrets committed to git (Critical), or not committed but missing from `.gitignore` (Medium). A committed `.env` with only public values (Supabase URL, anon key) is a Low warning | Critical · Medium · Low |
| Stripe webhooks | Webhook handlers that never verify the Stripe signature, so anyone can fake a "payment completed" event | Critical |
| Supabase Row Level Security | Tables in `supabase/schema.sql` or `supabase/migrations/` with RLS turned off, and policies that let everyone in (e.g. `USING (true)`). Tables with personal data rank higher | Critical, down to Low for read-only public data |
| Login checks | API routes (TanStack, Next.js `app/api` and `pages/api`, Supabase edge functions) and TanStack server functions that read or change user data without checking who is calling | High |
| Rate limits | Public endpoints that call a paid AI API or send email/SMS with no rate limit, so anyone can run up your bill in a loop | High (Medium when login is required) |

Public keys are never flagged: Stripe publishable keys (`pk_`), Supabase anon and publishable keys, and the example keys from AWS's and Stripe's own docs.

### Which checks run on which code

| Any language (Python, Go, Ruby, PHP, Java, …) | JS/TS only for now |
|---|---|
| Secret keys in code (every text source and config file; not docs like `.md`) | Secrets the browser can reach (`VITE_` / `NEXT_PUBLIC_`) |
| Committed `.env` files | Supabase admin key in the frontend |
| Supabase Row Level Security (reads the SQL; "Couldn't verify" also spots `supabase` in `requirements.txt` / `pyproject.toml`) | Stripe webhooks, login checks, rate limits |
| | All six privacy checks |

On a project with no JS/TS code, the JS/TS-only checks don't run and are listed as `– Not checked: <check> (no JS/TS code found)` in the report, the GitHub summary and JSON (`notChecked`). They never get a ✓.

A ✓ means the check found something to inspect and it was safe. A check with nothing to inspect (no Supabase, no Stripe webhook, no API routes, no `.env` files, no sign-up…) is listed as `– Not applicable: <check> (no Supabase found)` instead, and in JSON as `{"reason": "not-applicable", "detail": "no Supabase found"}`. Neither changes the score or exit code.

Dependency, build and cache folders are skipped in every language: `node_modules`, `.venv` / `venv` (and any virtualenv), `__pycache__`, `vendor`, `target`, `dist`, `build` and the like.

### Privacy (possible gaps)

Six checks look for common gaps against GDPR (EU) and PIPEDA (Canada). Each finding is a **possible gap**: code can't see everything (a policy on another website, deletion handled by email), so read them as questions to check, not verdicts. They're shown in their own section with the laws they relate to, and they **never change your score or fail the scan** unless you ask with `--fail-on-privacy`. This is not legal advice.

| Check | What it finds | Severity | Laws |
|---|---|---|---|
| No privacy policy | Personal data leaves the browser at a public form, sign-up or API route, and there's no privacy page, link, or privacy section in your terms | High | GDPR Art. 13 · PIPEDA 4.8 |
| Trackers before consent | Google Analytics, Meta Pixel, PostHog, Mixpanel, Segment, Hotjar or TikTok loads and there's no consent tool | High | ePrivacy Art. 5(3) · GDPR Art. 7 · PIPEDA 4.3 |
| Personal data to third parties | Analytics `identify` calls with email or name, or a file that calls an AI API and also uses personal data (low confidence) | Medium | GDPR Art. 13(1)(e), Art. 28 · PIPEDA 4.1.3 |
| No account deletion | Users can sign themselves up, but there's no way to delete the account | Medium | GDPR Art. 17 · PIPEDA 4.3.8, 4.5.3 |
| No data export | Users can sign themselves up, but there's no way to download their data (low confidence) | Low | GDPR Art. 15, Art. 20 · PIPEDA 4.9 |
| Personal data in logs | A log call prints a variable named like email, phone, password, address, token or user | Medium | GDPR Art. 5(1)(f), Art. 32 · PIPEDA 4.7 |

Known limits: the consent check confirms a consent tool exists, not that trackers wait for it; admin pages and accounts that only an operator creates aren't checked; forms that send data through a helper in another file can be missed.

## What it does NOT check

Leakproof reads the files in your project. That's it. It does **not**:

- **Look at your live database.** It can only judge Supabase rules that are saved as SQL in the repo. Rules you set in the dashboard are invisible to it.
- **Run your app.** It doesn't test runtime behaviour, call your endpoints, or check what your deployed site actually does.
- **Audit your dependencies.** Use `npm audit` or Dependabot for vulnerable packages.
- **Read git history.** A key you deleted is still in your history, and Leakproof only sees your current files.
- **Catch everything.** It looks for common mistakes AI builders make, with known gaps: only Stripe webhooks are checked; data access through helpers in other files isn't always followed; Express/Hono routes aren't checked; Vite variables read through destructuring are missed; made-up key-shaped strings in test files can be flagged.
- **Check routes outside JS/TS.** Python route checks (login, rate limits, webhooks, privacy in Flask, FastAPI, Django): planned. Go, Ruby and PHP routes aren't checked either.
- **Find framework secrets without a known prefix.** The key check looks for provider keys (OpenAI, Stripe, AWS…). A framework secret like Django's `SECRET_KEY = "..."` or Rails' `secret_key_base` has no prefix to recognize, so it isn't flagged.
- **Read every kind of secrets file.** Only `.env` and `.env.*` count as env files. `.flaskenv`, or secrets kept in a `config.py` / `settings.py`, aren't checked as env files (a provider key inside them is still caught by the key check).

A clean scan means none of these checks found a problem. It doesn't mean your app is secure.
Found a gap or a false alarm? Please [open an issue](https://github.com/HilalZD/LeakProof/issues).

## "Couldn't verify"

Some checks need files that aren't in every repo. When your app uses Supabase but has no SQL files in `supabase/migrations`, Leakproof can't see your Row Level Security rules, so it says **Couldn't verify** instead of giving you a ✓. These don't change your score or fail the scan.

**Tip:** open your project in the Supabase dashboard and run the **Security Advisor**. It checks your live tables for RLS that's off. Or run `supabase db pull` to save your schema into the repo so Leakproof can check it next time.

## Options

| Option | What it does |
|---|---|
| `--json` | Machine-readable JSON (summary, findings, skipped checks). Same as `--format json` |
| `--format <text\|json\|github>` | Output format. `github` prints GitHub Actions annotations and writes a job summary |
| `--fail-on <critical\|high\|medium\|low>` | Exit 1 only for security findings at this severity or worse. Default: `medium` |
| `--fail-on-privacy <high\|medium\|low>` | Also exit 1 for privacy gaps at this severity or worse. Off by default: privacy never fails the scan |
| `--verbose` | Also list every check that ran |

Exit codes: `0` no security findings at the `--fail-on` level (and no privacy gaps at the `--fail-on-privacy` level, if set), `1` findings, `2` Leakproof couldn't run (bad usage or scanner error).

### Ignoring findings: `.leakproofignore`

Put a `.leakproofignore` file in your project root. One entry per line, `#` starts a comment:

```gitignore
# 1. A fix ID: ignored everywhere
SEC_ENV_COMMITTED_PUBLIC_ONLY

# 2. A path or glob: every finding in matching files
src/legacy/**
*.test.ts

# 3. path:fixId: that fix ID in matching files only
.env.example:SEC_ENV_COMMITTED
```

Ignored findings don't count toward the score or exit code. The summary shows how many were ignored.

## GitHub Action

```yaml
- uses: HilalZD/LeakProof@v0.2
  with:
    fail-on: high
```

Findings show up as annotations on your pull request, with a summary on the job page. Full copy-paste workflow: [docs/github-action.md](docs/github-action.md).

## Privacy and safety

- **Runs locally.** Your code never leaves your machine.
- **Read-only.** Leakproof never changes, moves or deletes your files, and never connects to your database.
- **Keys are masked.** Reports only show the start and end of a key (`sk-proj-****W1xY`), never the full value, including in `--json` and GitHub output.
- **Telemetry is off unless you turn it on.** `leakproof telemetry on` shares anonymous counts (which fix IDs came up, how many files, which stack). Never code, paths, values or names. See [docs/telemetry.md](docs/telemetry.md) for the exact payload.

`npx` downloads Leakproof from npm the first time you run it. After that, the scan itself works offline.

## Not legal advice

Leakproof points out common security mistakes. It isn't a security audit or legal advice, and a clean scan doesn't mean your app meets any law or standard.

## Contributing

Issues and pull requests are welcome:

```sh
git clone https://github.com/HilalZD/LeakProof.git
cd LeakProof
npm install
npm run build
npm test
```

Please never commit real keys, including in tests. Build fake keys at runtime (for example `"sk_" + "live_" + "x".repeat(24)`) so GitHub's secret scanning doesn't block the push.

## License

MIT © Hilal Zeidan

# LeakProof

**Find the leaks AI coding tools leave behind. One command, no signup.**

![LeakProof report showing 6 leaks: an unverified Stripe webhook, a hardcoded OpenAI key, secrets in a committed .env, and a Vite-exposed Stripe key](https://raw.githubusercontent.com/HilalZD/LeakProof/main/docs/demo-leaks.svg)

And when your app is clean:

![LeakProof report showing no leaks and one low-risk warning](https://raw.githubusercontent.com/HilalZD/LeakProof/main/docs/demo-clean.svg)

## Quick start

Run it inside your project folder:

```sh
npx @leakproof/cli scan
```

Or point it at another folder:

```sh
npx @leakproof/cli scan ./my-app
```

Requires Node.js 20 or newer.

## What it checks

| Check | What it finds | Severity | Example |
|---|---|---|---|
| Stripe webhooks | Webhook handlers that never verify the Stripe signature, so anyone can fake a "payment completed" event | Critical | `JSON.parse(body)` with no `constructEvent` |
| Secret keys in code | Secret API keys hardcoded in your code (OpenAI, Anthropic, Stripe, Supabase `service_role` and `sb_secret_`, AWS, GitHub) and secrets exposed to the browser through `VITE_` variables | Critical (Stripe test keys and `VITE_` secrets: High) | `const openai = new OpenAI({ apiKey: "sk-proj-…" })` |
| Committed .env files | `.env` files with real secrets that are committed to git, or not git-ignored | Critical (committed) · Medium (not ignored) | `STRIPE_SECRET_KEY=sk_live_…` in a committed `.env` |

It also shows a **Low** warning when a committed `.env` only holds public values (like your Supabase URL and anon key). That's safe today, but any secret you add later will be public. Low warnings don't fail the scan.

Public keys are never flagged: Stripe publishable keys (`pk_`), Supabase anon and publishable keys, and the example keys from AWS's and Stripe's own docs.

## Why

AI app builders make it easy to ship a working app before anyone looks at its security. We sampled 38 public Lovable and Bolt apps with Stripe webhook code (October 2026): **4 of 38 (about 1 in 10) didn't verify webhook signatures**, so anyone could unlock paid features for free. That's a small sample, but the fix takes minutes once you know the problem is there.

## Example output

From a test app with deliberate leaks:

```text
LeakProof v0.1.0 · scanning notenest-three-and-free
90 files checked in 0.3s

✗ 6 leaks found · 5 critical · 1 high

── CRITICAL (5) ────────────────────────────────────────────────────────────────

  src/routes/api/public/stripe-webhook.ts:7
    Stripe webhook doesn't verify signatures: anyone can send a fake 'payment
    completed' event and unlock paid features for free
    → Verify the stripe-signature header with
      stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET)
      before trusting the event. Use the raw request body, not parsed JSON.

  src/lib/ai.ts:1
    OpenAI API key hardcoded: sk-proj-****W1xY
    → Move this key to a server-side function and rotate it now.

  .env:7
    STRIPE_SECRET_KEY is committed to git: sk_test_****M5wZ
  .env:8
    SUPABASE_SERVICE_ROLE_KEY is committed to git: eyJhbGci****2345
  .env:9
    VITE_STRIPE_SECRET_KEY is committed to git and shipped to the browser:
    sk_test_****M5wZ
    → Remove .env from git (git rm --cached .env), add .env to .gitignore, and
      rotate this key; it stays in git history even after deletion.

── HIGH (1) ────────────────────────────────────────────────────────────────────

  src/lib/payments.ts:14
    Secret exposed to the browser through Vite:
    import.meta.env.VITE_STRIPE_SECRET_KEY
    → Vite ships every VITE_ variable to the browser: drop the VITE_ prefix, use
      STRIPE_SECRET_KEY only in server-side code, and rotate it.
```

## Private by design

- **Runs locally.** Your code never leaves your machine. LeakProof makes no network requests.
- **No account.** Nothing to sign up for.
- **No telemetry.** No analytics, no tracking.
- **Keys are masked.** Reports only show the start and end of a key (`sk-proj-****W1xY`), never the full value, including in `--json` output.

`npx` downloads LeakProof from npm the first time you run it. After that, the scan itself is fully offline.

## Use it in CI

LeakProof exits with a code your CI can act on:

| Exit code | Meaning |
|---|---|
| `0` | No leaks (Low warnings may still be shown) |
| `1` | Leaks found |
| `2` | LeakProof couldn't run (bad usage or scanner error) |

Add `--json` for machine-readable output:

```sh
npx @leakproof/cli scan --json
```

Minimal GitHub Actions workflow (`.github/workflows/leakproof.yml`):

```yaml
name: LeakProof
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: lts/*
      - run: npx --yes @leakproof/cli scan
```

The job fails when leaks are found.

## What it doesn't check (yet)

LeakProof v0.1 catches a focused set of common leaks, not all of them. It does **not** yet check:

- **Database security.** Supabase table permissions (Row Level Security) and storage bucket rules aren't checked.
- **Git history.** A `.env` file or key you deleted is still in your git history, and LeakProof only looks at your current files.
- **Other payment providers.** Only Stripe webhooks are checked, not Lemon Squeezy, Paddle or PayPal.
- **Your built app.** LeakProof scans your source code, not the built files in `dist/` that visitors download.
- **Every kind of secret.** Only the key types listed above are detected. Database connection strings with passwords are only caught in `.env` files, not in code or in `.env.example`.
- **Some code patterns:**
  - Vite variables read through destructuring (`const { VITE_SECRET } = import.meta.env`).
  - Webhook handlers whose event names or body reading live in another file.
  - Handlers that read the signature header but never actually check it.
- **Debug endpoints** that return your environment variables.

It can also flag things that aren't real problems:

- Made-up key-shaped strings in test files.
- A webhook route file that never runs because another file handles the same path and verifies it.

Found a gap or a false alarm? Please [open an issue](https://github.com/HilalZD/LeakProof/issues).

## Contributing

Issues and pull requests are welcome. To work on LeakProof locally:

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

---

⭐ Star the repo to follow updates.

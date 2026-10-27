Answer key
Line numbers are in the committed broken branch.

Leaks

#	File	Line	Type
1a	src/lib/ai.ts	1	OpenAI secret key (sk-proj-) hardcoded in frontend code. It is used on line 8 in a browser fetch, and notes.tsx calls it at line 61 via the Summarize button.
1b	src/lib/payments.ts	14	Stripe secret key read from import.meta.env.VITE_STRIPE_SECRET_KEY and sent to the Stripe API from the browser.
2a	.env	7	Committed Stripe secret key (STRIPE_SECRET_KEY, sk_test_).
2b	.env	8	Committed Supabase service-role key (JWT-shaped).
2c	.env	9	Committed VITE_STRIPE_SECRET_KEY (sk_test_). The VITE_ prefix ships it to the browser bundle.
3	src/routes/api/public/stripe-webhook.ts	7	Webhook with no signature verification. It trusts request.json() and then sets is_pro from it.
Decoys (safe, must not be flagged)

File	Line	Type
.env	2	Supabase publishable key (SUPABASE_PUBLISHABLE_KEY)
.env	3	Supabase URL
.env	5	Supabase publishable key (VITE_SUPABASE_PUBLISHABLE_KEY)
.env	6	Supabase URL (VITE_SUPABASE_URL)
src/integrations/supabase/client.ts	52–53	Reads the Supabase URL and publishable key
src/integrations/supabase/client.ts	65	createClient call using the publishable key
src/routes/pricing.tsx	9	Stripe publishable key (pk_test_FAKE…)
src/routes/pricing.tsx	12	Decoy use of that key, in initStripe()
Pass-through: pricing.tsx line 51 passes the publishable key to payments.ts line 9, which only forwards it as metadata. It is not a key literal, but a loose scanner could trip on it.
Other .env lines: .env lines 1 and 4 are the Supabase project ID (SUPABASE_PROJECT_ID, VITE_SUPABASE_PROJECT_ID). They are not secrets.
Supabase files: the other src/integrations/supabase/* files only reference sb_publishable_ as a string prefix check, with no key values.

## Scanner notes (learned while building the test app)

- Webhooks can live in app server routes (src/routes/api/...), not only in supabase/functions/
- Signature verification has many forms: stripe-signature header read, hand-written HMAC, or constructEvent / constructEventAsync. Detect any of them.
- A committed .env is only a leak if it contains secrets. Lovable commits .env with safe values by default.
- Supabase keys: anon / publishable (sb_publishable_) are SAFE. service_role JWT and sb_secret_ are SECRET.
- VITE_-prefixed variables end up in the browser bundle, so any secret with a VITE_ name is a leak.
- Watch for pass-through: a publishable key passed into a function that also handles a secret.
- Known gap (leaked-keys check): destructured Vite env vars such as `const { VITE_STRIPE_SECRET_KEY } = import.meta.env` are not detected yet. Only `import.meta.env.VITE_X` and `import.meta.env["VITE_X"]` are.
- Idea for later: scan built bundles (.output/, dist/) for secrets. This is what visitors actually download, and it's the same technique as the URL-only free scan on a live site.
- Known gap: .env files deleted from git but still in git history aren't detected yet.
- Known gap: connection strings with passwords hardcoded in code files (not .env) aren't detected yet.
- Known gap: Rule 3 is skipped for example files, so a real non-localhost password in .env.example isn't caught.
- Known gap: only Stripe webhooks are checked. Other providers (Lemon Squeezy, Paddle, PayPal) come later. A handler that reads the signature header but never actually compares it can be missed.
- Known gap: a webhook handler that only uses event names imported from another file (e.g. a constants file) has no event name string of its own, so it isn't recognized as a handler.
- Documented example keys (AWS's published example access keys, Stripe's docs example keys) are allowlisted in src/lib/patterns.ts and never flagged.
- Known gap: made-up key-shaped strings in test files are flagged.
- Known gap: a webhook route file that never runs, because the server entry handles the same path first and verifies it, is still flagged (seen in round 2's savebite-singapore). Routes aren't matched across files.
- Known gap: helpers that read the request body are not followed across files (v0.2).
- How to recognize the builder: lovable-tagger (older Lovable), @lovable.dev/vite-tanstack-config (newer Lovable), .bolt/ folder (Bolt).
- Idea for v0.2: debug endpoints/functions (like env-debug) that return environment variables.

## Expected results
- notenest broken branch: 6 leaks (5 critical, 1 high), 0 low, exit 1. These are 1a, 1b, 2a, 2b, 2c and 3, with 0 decoys flagged.
- notenest main branch: 0 leaks, 1 low-risk warning, exit 0. The warning is the committed .env with public values only.
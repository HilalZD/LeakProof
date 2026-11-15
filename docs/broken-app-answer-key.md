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
4	src/routes/api/summarize-note.ts	10	HIGH. Server endpoint that calls OpenAI (fetch to api.openai.com with process.env.OPENAI_API_KEY) with no rate limit and no login check. The message ends with "It also doesn't require login."
5	src/routes/api/send-invite.ts	16	MEDIUM. Server endpoint that sends email through Resend (fetch to api.resend.com) with no rate limit. It does check login (supabase.auth.getUser), which doesn't change a MEDIUM finding.

v0.2 leaks (planted Nov 14, 2026)

#	File	Line	fixId
6	.env	10	SEC_SECRET_CLIENT_EXPOSED
6	src/components/TitleSuggest.tsx	13	SEC_SECRET_CLIENT_EXPOSED
7	supabase/migrations/20261114120000_invites.sql	2	SEC_SUPABASE_RLS_DISABLED
8	supabase/migrations/20261114120100_public_profiles.sql	2	SEC_SUPABASE_RLS_PERMISSIVE
9	src/components/AdminStats.tsx	7	SEC_SUPABASE_SERVICE_ROLE_CLIENT
10	src/routes/api/users.ts	8	SEC_API_ROUTE_NO_AUTH (title "API route has no login check". Message: "This route reads user data with the Supabase admin client, which skips Row Level Security, and never checks who is calling: anyone can call it and get the data.")

Chunk 3D leak (planted Nov 15, 2026)

#	File	Line	fixId
11	src/lib/members.ts	5	SEC_API_ROUTE_NO_AUTH (TanStack server function listMembers: returns every profile through supabaseAdmin with no auth check. It's imported by src/routes/_authenticated/members.tsx, whose layout only guards the page in the browser; the server function can still be called directly over HTTP. Title "Server function has no login check". Message: "This server function reads user data with the Supabase admin client, which skips Row Level Security, and never checks who is calling: anyone can call it over HTTP and get the data.")

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
src/routes/api/rewrite-note.ts	20	OpenAI endpoint rate limited with @upstash/ratelimit (10 requests per minute per IP). Must not get a rate-limit finding.
src/lib/ai.ts	4	Browser fetch to api.openai.com. It's frontend code, so the rate-limit check must not flag it (1a already covers its hardcoded key).
src/routes/api/public/stripe-webhook.ts	7	Webhook handler. The rate-limit check skips webhooks, so it only gets finding 3.
.env	11	VITE_SUPABASE_ANON_KEY (role "anon", meant to be public)
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
- Known gap: only AI and email/SMS/auth endpoints are checked for rate limiting.
- Known gap (rate-limit check): an endpoint that calls an AI or email provider through a helper in another file (e.g. src/lib/openai.ts) isn't followed, and TanStack server functions (createServerFn) aren't treated as endpoints.
- Rate-limit test endpoints need @upstash/ratelimit and @upstash/redis in NoteNest's package.json. They were copied into node_modules without bun, so bun.lock wasn't updated; run `bun install` once if bun is available.

## Notes for chunk 2
- The v0.2 migrations in supabase/migrations/ are files for the scanner to read only. Never run `supabase db push` or apply them anywhere.
- Leaks #6 and #9 are each caught by an old rule today: .env:10 as SEC_ENV_COMMITTED (committed-env) and AdminStats.tsx:7 as SEC_SECRET_HARDCODED (leaked-keys). In chunk 2, one leak must produce ONE finding, and the most specific fixId wins: SEC_SECRET_CLIENT_EXPOSED for #6 and SEC_SUPABASE_SERVICE_ROLE_CLIENT for #9.

## Expected results
- notenest broken branch, with chunk 3D (server functions, helpers, public forms, upsell) and leak #11: 12 findings (7 critical, 4 high, 1 medium), 0 low, 0 info, Score 0/100 Grade F, exit 1, 0 decoys flagged. Same as the chunk 3 run below, plus:
  - SEC_API_ROUTE_NO_AUTH (high, confidence high): src/lib/members.ts:5 (#11, the createServerFn line)
  - #8's message now reads "Anyone can read every row in profiles (a table that usually holds personal data). Policy: …"
- notenest main branch, with chunk 3D: unchanged (Score 99/100 Grade A, 1 low, 1 info, exit 0). The "Couldn't verify" message now adds the Security Advisor tip and the Leakproof Cloud early-access link.
- notenest broken branch, with chunk 3 (Supabase RLS, API route auth): 11 findings (7 critical, 3 high, 1 medium), 0 low, 0 info, Score 0/100 Grade F, exit 1, 0 decoys flagged. Everything from the report-polish run below is unchanged, plus:
  - SEC_SUPABASE_RLS_DISABLED (critical): supabase/migrations/20261114120000_invites.sql:2 (#7, names inviter_id and email)
  - SEC_SUPABASE_RLS_PERMISSIVE (critical): supabase/migrations/20261114120100_public_profiles.sql:2 (#8; profiles isn't created in the repo, so it counts as personal data by its table name)
  - SEC_API_ROUTE_NO_AUTH (high): src/routes/api/users.ts:8 (#10, the GET handler line; confidence high because it uses supabaseAdmin)
- notenest main branch, with chunk 3: Score 99/100 Grade A, 0 leaks, 1 low, 1 info ("Couldn't verify": SEC_SUPABASE_RLS_UNVERIFIED, since main has no supabase/migrations), exit 0. The RLS check gets no ✓ on main because it couldn't verify.
- notenest broken branch, with report polish (grade caps, same-secret grouping, test-key severity): 8 findings (5 critical, 2 high, 1 medium), 0 low, Score 0/100 Grade F, exit 1, 0 decoys flagged. All 11 locations below still show: 3 of them as "also at" lines.
  - SEC_STRIPE_WEBHOOK_UNSIGNED (critical): src/routes/api/public/stripe-webhook.ts:7 (3)
  - SEC_SUPABASE_SERVICE_ROLE_CLIENT (critical): src/components/AdminStats.tsx:7 (#9)
  - SEC_SECRET_CLIENT_EXPOSED (critical): .env:10, also at src/components/TitleSuggest.tsx:13 (#6, same VITE_OPENAI_API_KEY)
  - SEC_SECRET_CLIENT_EXPOSED (critical): src/lib/ai.ts:1 (1a)
  - SEC_ENV_COMMITTED (critical): .env:8 (2b)
  - SEC_API_NO_RATE_LIMIT (high): src/routes/api/summarize-note.ts:10 (4)
  - SEC_SECRET_CLIENT_EXPOSED (high: test key): .env:9, also at .env:7 and src/lib/payments.ts:14 (2c + 2a + 1b, the same sk_test_ value; also shows the SEC_ENV_COMMITTED fix)
  - SEC_API_NO_RATE_LIMIT (medium): src/routes/api/send-invite.ts:16 (5)
  - #7, #8 and #10 aren't detected yet.
- notenest main branch, with report polish: Score 99/100 Grade A, 0 leaks, 1 low, exit 0.
- notenest broken branch, scanner with chunk 2A (client-exposed, service-role-client, dedupe): 11 leaks (7 critical, 3 high, 1 medium), 0 low, exit 1, no duplicate file+line, 0 decoys flagged.
  - SEC_ENV_COMMITTED (critical): .env:7 (2a), .env:8 (2b)
  - SEC_SECRET_CLIENT_EXPOSED: .env:9 (2c, high: test key), .env:10 (#6, critical), src/components/TitleSuggest.tsx:13 (#6, critical), src/lib/ai.ts:1 (1a, critical: src/lib is frontend in a Vite app and ai.ts is imported by notes.tsx), src/lib/payments.ts:14 (1b, high: test key)
  - SEC_SUPABASE_SERVICE_ROLE_CLIENT (critical): src/components/AdminStats.tsx:7 (#9)
  - SEC_STRIPE_WEBHOOK_UNSIGNED (critical): src/routes/api/public/stripe-webhook.ts:7 (3)
  - SEC_API_NO_RATE_LIMIT: src/routes/api/summarize-note.ts:10 (4, high), src/routes/api/send-invite.ts:16 (5, medium)
  - #7, #8 and #10 aren't detected yet.
- notenest broken branch, scanner v0.2.1 (before chunk 2A): 10 leaks (7 critical, 2 high, 1 medium), 0 low, exit 1. These are 1a, 1b, 2a, 2b, 2c, 3, 4, 5, plus .env:10 and AdminStats.tsx:7 under their old fixIds, with 0 decoys flagged. #7, #8 and #10 aren't detected yet.
- notenest broken branch, before the v0.2 leaks were planted: 8 leaks (5 critical, 2 high, 1 medium). These are 1a, 1b, 2a, 2b, 2c, 3, 4 and 5.
- notenest main branch: 0 leaks, 1 low-risk warning, exit 0. The warning is the committed .env with public values only.
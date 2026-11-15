# Notes for Serena (Part B integration)

## Contract v1.3 (Nov 15, 2026): PRIV_NO_ACCOUNT_DELETION law references
Hilal decided: lawRefs are now `["GDPR Art. 17", "PIPEDA Principle 4.3.8", "PIPEDA Principle 4.5.3"]`
(4.5 → 4.5.3; 4.3.8 stays, for withdrawing consent). CONTRACT.md and `src/laws.ts` are updated, and your 13 tests still pass.

Please update your own copies to match (only text, no rule logic changed):
- `docs/law-check.md` lines 36–37, 53 and 60–61: mark 4.3.8 as kept for consent withdrawal, and add a 4.5.3 row
  (data no longer needed is destroyed, erased or made anonymous). The result becomes 17 checked, 17 fit.
- `README.md` line 42: "PIPEDA 4.3.8, 4.5" → "PIPEDA 4.3.8, 4.5.3".
- `src/rules/noAccountDeletion.ts` line 7 (comment only): "4.3.8 and 4.5" → "4.3.8 and 4.5.3".
- `src/laws.ts` header comment still says "THE LEAKPROOF CONTRACT (v1)".

## Real-app check (step 5, Nov 15, 2026): rule behaviour worth a look
Apps are named by type only. No rule logic was changed.

1. **PRIV_NO_PRIVACY_POLICY points at the wrong "first seen" place.** On a Next.js booking site, the public booking API
   collects name, email and phone and there's no privacy page, so the finding is right. But it points at
   `app/(admin)/admin/settings/page.tsx:24`: the owner's own notification-email field in the admin panel. Users never see that form.
   Idea: prefer public forms or API routes over admin/settings paths when picking the location.
2. **PRIV_NO_PRIVACY_POLICY on an email field that sends nothing.** On a static Next.js site, the trigger is an email
   `<input>` whose form only does `e.preventDefault(); setNotified(true)`: the email never leaves the page. The site's
   terms page also has a "Data protection & privacy" section. That's a false alarm on both counts. Ideas: (a) count a
   privacy section inside terms/legal pages as a policy; (b) only treat a form as collecting data when its submit handler sends it somewhere.
3. **PRIV_NO_ACCOUNT_DELETION / PRIV_NO_DATA_EXPORT on staff-only logins.** A clinic app has only `signInWithPassword`
   for clinicians (no sign-up; accounts are created by the operator). Both rules fire. Technically true (no delete or export path in code),
   but for staff accounts set up by an admin this is mostly noise. Idea: lower confidence or skip when there's sign-in but no sign-up.

## Changes Hilal made to your rules (step 6, Nov 15, 2026)
Hilal asked for these after the real-app check above. Everything else in your rules is unchanged, and your 13 tests still pass.

1. **PRIV_NO_PRIVACY_POLICY** (`rules/noPrivacyPolicy.ts`, rewritten around your structure):
   - Counts a collection point only where personal data **leaves the browser**: a sign-up call (`.signUp(`, `signUp.email(`,
     `createUserWithEmailAndPassword(`); a personal-data field (`type`, `name`, now also `autoComplete` / `inputMode`) in a file
     that also sends data (`fetch`, `axios`, `<form action=…>`, `.insert/.upsert`, `"use server"`, `useMutation`); or an API route /
     edge function that reads the request and names email/phone/name.
   - Dropped as triggers: a SQL column alone, and a form that only keeps the value in local state.
   - Skips `admin/`, `(admin)/` and `dashboard/` paths (the operator's own data) and webhook routes (data sent by a provider, e.g. Stripe).
     *(Replaced after your review: `dashboard/` is no longer skipped. See "Serena's review: done" below.)*
   - Points at API routes first, then sign-up calls, then forms.
   - Also counts as a policy: a terms/legal page (`terms`, `legal`, `conditions`, `tos`, `imprint`) with a privacy or data-protection section.
2. **PRIV_NO_ACCOUNT_DELETION / PRIV_NO_DATA_EXPORT** now use a new `SELF_SIGNUP` list (in `utils.ts`) instead of `HAS_USER_ACCOUNTS`:
   `.signUp(`, `signUp.email/social(`, `signInWithOAuth`, `signInWithOtp`, `createUserWithEmailAndPassword`, Clerk `<SignUp>` /
   `useSignUp`, NextAuth. Sign-in only (operator-created accounts) no longer fires. A bare `register(` isn't listed, because react-hook-form
   uses `register("email")`. The message now says "users can create their own accounts in this app (sign-up in …)".
   `HAS_USER_ACCOUNTS` is unused now but kept.
3. **One-line fixes** were added to `laws.ts` (`fix` field) and `makeFinding` copies them onto the finding. **Reviewed by Serena (Nov 15, 2026); two texts changed, see below.** Original wording:
   - PRIV_NO_PRIVACY_POLICY: Add a privacy policy page (e.g. /privacy) that says what you collect, why, who you share it with and how to reach you, and link it from your forms and footer.
   - PRIV_TRACKER_BEFORE_CONSENT: Add a consent banner and only load this tracker after the user clicks Accept (or use the tool's own consent mode).
   - PRIV_PII_TO_THIRD_PARTY: Send an anonymous ID instead of the email or name, or name this service in your privacy policy and sign its data processing agreement.
   - PRIV_NO_ACCOUNT_DELETION: Add a "Delete my account" option that removes the user's account and their data on the server.
   - PRIV_NO_DATA_EXPORT: Add a "Download my data" option that gives users their data as a JSON or CSV file.
   - PRIV_PII_IN_LOGS: Log a user ID or a short message instead of the email, phone or password.
4. Regression tests for every case above are in `test/privacy-precision.test.ts`.

New known limit for your README: a form that sends data through a helper in another file (e.g. `onSubmit={submitBooking}` imported
from `lib/`) isn't seen as sending. The rule then relies on a sign-up call or an API route to find the collection point.

### "Not applicable" (Nov 15, 2026)
Each rule now also says when it had nothing to inspect, so the report never implies a check passed when it found
nothing to look at. Your rule logic is unchanged: I only added `export` to `collectionPoints` (noPrivacyPolicy),
`TRACKERS`, `IDENTIFY_CALLS` / `AI_SERVICES` and `LOG_CALL`, and `src/rules/privacy-applies.ts` uses them:
- Privacy policy: no collection point → "no personal data collection found"
- Trackers before consent: no tracker pattern → "no trackers found"
- Personal data to third parties: no identify or AI call → "no analytics identify or AI API calls found"
- Account deletion / Data export: no `SELF_SIGNUP` match → "no self sign-up found"
- Personal data in logs: no log call → "no log calls found"
It's only asked when the rule returned no findings, so it can't hide one. Please check the wording.

### How the scanner shows your findings now
- In their own "PRIVACY GAPS (possible)" section after the security findings, with the law references on one line
  (shown as "PIPEDA 4.8"; JSON keeps "PIPEDA Principle 4.8"), "→ Fix:" for high/medium, "(low confidence)" when it applies,
  and "This is not legal advice." once.
- They never change the score, grade or exit code unless the user passes `--fail-on-privacy <high|medium|low>`.
  In GitHub output they're always `::notice`. Low-confidence findings are shown, not hidden.
- The fix link lists each fix ID once. Telemetry (opt-in) counts per fix ID only.

### Fix cards
Hilal writes the fix cards on the site; Serena reviews the 6 privacy ones.

## Serena's review: done (Nov 15, 2026)
Applied by Hilal:
1. **PRIV_NO_PRIVACY_POLICY no longer skips `dashboard/` paths.** Only `admin/` and `(admin)/` stay skipped
   (`ADMIN_PATH` in `rules/noPrivacyPolicy.ts`), for both forms and sign-up calls. New regression test in
   `test/privacy-precision.test.ts`: a profile form under `app/dashboard/profile/` that sends an email counts as a collection point.
2. **Fix texts in `laws.ts`:**
   - PRIV_NO_PRIVACY_POLICY: "Add a privacy policy page (e.g. /privacy) that says what you collect, why, who you share it with,
     how long you keep it, how users can ask for deletion and how to reach you, and link it from your forms and footer."
   - PRIV_TRACKER_BEFORE_CONSENT: "Add a consent banner and only load this tracker after the user clicks Accept."
3. **"Not checked" vs "Not applicable" wording stays as it is.** They mean different things (the check can't run on this
   language, vs. the check ran but found nothing to inspect), and neither shows ✓.
4. The "For Yara" section is replaced by "Fix cards" above.
5. Re-scan of NoteNest (main and broken) and the 3 real apps, before and after: same findings, scores, grades and
   exit codes everywhere (NoteNest broken 0/F with 12 findings, main 99/A; a clinic app 100/A; a static coaching site 100/A;
   a booking site 99/A). The only difference is the longer PRIV_NO_PRIVACY_POLICY fix text, on NoteNest (both
   branches) and the booking site. The `dashboard/` change added no findings on these apps. `git status` was the same
   in every repo before and after.

## Leakproof site scan (Part C step 7, Nov 15, 2026)
Scanned `leakproof-site` (Next.js static export) with `node dist/index.js`. No rule logic was changed.

1. **False alarm: PRIV_PII_IN_LOGS on build output.** Two findings in `out/_next/static/chunks/*.js`, which is the
   minified Next.js/React bundle that `next build` writes with `output: "export"`. It's git-ignored and none of it is our code.
   The cause is in the file walker, not your rule: `out` isn't in `SKIPPED_DIRS` (`src/lib/files.ts`), while `.next`, `dist`
   and `build` are. Suggest adding `out` (Hilal owns that file). A clean clone of the site, without `out/`, scans with zero findings.
2. **The known "helper in another file" limit, seen in a real app.** The waitlist and fix-unlock forms
   (`<input type="email">`) send through `submitToFormspree()` in `lib/formspree.ts`, so "Privacy policy" reports
   "Not applicable (no personal data collection found)" even though emails do leave the browser. The site has a
   `/privacy` page anyway. Maybe worth catching later: a form-service URL (`formspree.io/f/`, `getform.io`, `api.web3forms.com`)
   in any code file, plus an email field anywhere in the project, would count as a collection point.
3. **Design question, not a bug:** PRIV_PII_TO_THIRD_PARTY only looks for analytics identify calls and AI APIs. Form
   services such as Formspree also receive emails. Should they count?

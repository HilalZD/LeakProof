# Chunk 4 progress (overnight run, Nov 15, 2026)

- [x] Setup: `Bash(npm publish:*)` added to deny in .claude/settings.local.json (gitignored, not committed)
- [x] Step 0: answer key #10/#11 wording (`56eed12`)
- [x] 4A: GitHub Action + --fail-on. Tests 324 pass, typecheck OK, build OK
- [x] 4B: README, version, changelog, demo script. Tests 324 pass, typecheck OK, build OK
- [x] 4C: opt-in usage counts. Tests 344 pass, typecheck OK, build OK
- [x] Final checks (see chunk4-report.md)
- [x] Report: docs/chunk4-report.md

## Decisions so far
- `scan` is now the default command, so `leakproof <path>` and `npx @leakproof/cli` work (the action and README need it). `leakproof scan <path>` still works.
- `--format text|json|github`. `--format` wins over `--json`; `--json` stays as a shortcut.
- info findings never fail, whatever --fail-on is; `--fail-on info` is rejected (exit 2).
- Annotations: info → `::notice`. Each "also at" place gets its own annotation ("same secret as …").
- After the annotations, stdout gets one plain summary line and the fix link.
- A failing $GITHUB_STEP_SUMMARY write prints one stderr line and doesn't change the exit code.
- action.yml: no setup-node step (hosted runners ship Node 20+). Inputs go through env vars (no script injection). The pinned CLI version is checked against package.json by a test.
- Left a stray scratch file in a scratch folder outside the repo (a NoteNest scan output, masked values only) from the first baseline run. Not deleted, per the no-delete rule.

## 4B decisions
- Version 0.2.0 in package.json, package-lock.json and action.yml (a test keeps action.yml in step). Not published.
- README example is a real NoteNest broken scan with the middle trimmed and marked "…" (the full report is ~100 lines).
- The old demo SVGs aren't referenced by the README any more (a GIF placeholder replaces them). The files stay.
- Privacy section says "coming in v0.2" as asked, and says plainly the checks aren't in this release.
- CHANGELOG lists 0.2.0 as "unreleased" since it isn't published.
- demo.tape warms up npx off camera (`npx --yes … --version`) so the install prompt doesn't show. It needs 0.2.0 on npm, or the commented local-dist line.

## 4C decisions
- Config is `~/.leakproof/config.json` `{ "telemetry": true|false }`; other keys are kept. A broken file counts as off.
- LEAKPROOF_TELEMETRY accepts 1/true/on and 0/false/off. =0 beats the config file. CI = CI, GITHUB_ACTIONS, GITLAB_CI, CIRCLECI, BUILDKITE, TF_BUILD, JENKINS_URL, TEAMCITY_VERSION (CI=false/0/empty doesn't count).
- Rule counts use ruleId per reported finding (after grouping; ignored findings not counted). Stack is detected in runScan from package.json deps and vite/next config files / supabase folder, and added to ScanResult as `stack`.
- No "Nothing was sent anywhere" claim when telemetry is on: the footer says code never leaves the machine and counts are on. The GitHub job summary now says "Your code never left the runner." in every case.
- The opt-in hint shows only in the text report, only when off, and not in CI (where `telemetry on` wouldn't help).
- Sending happens after the report is printed. The fetch isn't awaited, but Node may keep the process alive until it ends (max 1.5s). Never runs while TELEMETRY_URL is the placeholder.
- The placeholder check also refuses any non-https URL.

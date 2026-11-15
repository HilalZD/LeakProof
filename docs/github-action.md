# Leakproof GitHub Action

Scan every push and pull request. Findings show up as annotations on the
changed lines, and the job summary gets the score, grade, a findings table and
the fix link. The scan runs on the GitHub runner. Nothing is sent anywhere.

## Copy-paste workflow

Save this as `.github/workflows/leakproof.yml`:

```yaml
name: Leakproof

on: [push, pull_request]

jobs:
  leakproof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HilalZD/LeakProof@v0.2
        with:
          fail-on: high
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `fail-on` | `medium` | Fail the job for findings at this severity or worse: `critical`, `high`, `medium` or `low`. "Couldn't verify" (info) never fails. |
| `path` | `.` | Folder to scan, relative to the repository root. |

With `fail-on: high`, critical and high findings fail the job. Medium and low
findings still show as warnings but let the job pass.

## What you'll see

- `::error` annotations for critical and high findings, `::warning` for medium
  and low, `::notice` for "couldn't verify" and for every privacy gap. A secret
  found in several places gets an annotation at each place.
- Privacy gaps never fail the job, unless you run the CLI yourself with
  `--fail-on-privacy <high|medium|low>`.
- A job summary with the score, grade, every finding and the fix link.
- Secrets are always masked (e.g. `sk_live_****abcd`), in annotations and the summary.

## Ignoring findings

Add a `.leakproofignore` file to the repo root (see the README). Ignored
findings don't show and don't fail the job.

## Running it without the action

The action is one command, so any CI can run it:

```bash
npx @leakproof/cli . --format github --fail-on high
```

Node 20 or newer is needed. GitHub's hosted runners already have it.

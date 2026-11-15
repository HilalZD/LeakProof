# Anonymous usage counts (opt-in)

Leakproof sends **nothing** unless you turn this on. It's off by default, and
in CI it stays off unless you set `LEAKPROOF_TELEMETRY=1` yourself.

## Turning it on and off

```sh
leakproof telemetry on      # share anonymous counts
leakproof telemetry off     # stop
leakproof telemetry status  # see what's set, and why
```

Your choice is saved in `~/.leakproof/config.json` as `{ "telemetry": true }`
or `{ "telemetry": false }`.

The `LEAKPROOF_TELEMETRY` environment variable overrides the file:

| Setting | Result |
|---|---|
| nothing set | off |
| `leakproof telemetry on` | on (except in CI) |
| `LEAKPROOF_TELEMETRY=1` (or `true`, `on`) | on, also in CI |
| `LEAKPROOF_TELEMETRY=0` (or `false`, `off`) | off, whatever the file says |
| CI (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, …) without the env var | off, whatever the file says |

## The exact payload

One JSON object per scan, and nothing else:

```json
{
  "version": "0.2.0",
  "os": "linux",
  "fixIds": { "SEC_SECRET_CLIENT_EXPOSED": 3, "SEC_SUPABASE_RLS_DISABLED": 1, "PRIV_NO_PRIVACY_POLICY": 1 },
  "filesChecked": "100-1000",
  "stack": { "vite": true, "next": false, "supabase": true }
}
```

| Field | What it is |
|---|---|
| `version` | The Leakproof version |
| `os` | Node's `process.platform` (`linux`, `darwin`, `win32`) |
| `fixIds` | Which fix IDs (security and privacy) came up, and how many findings each. Ignored findings aren't counted |
| `filesChecked` | A range: `0-100`, `100-1000`, `1000-10000` or `10000+` |
| `stack` | Whether the project uses Vite, Next.js and Supabase: yes or no |

**Never sent:** file paths, code, key values (not even masked ones), project
or package names, repo URLs, usernames, or any user or device ID. There's no
ID at all, so two scans can't be linked to each other.

## How it's sent

- After the report is printed, as one HTTPS POST. Fire-and-forget: the scan
  never waits for it, and the request gives up after 1.5 seconds.
- If it fails, nothing is printed and the exit code doesn't change.
- Until the endpoint is live, the address in `src/config.ts` is a placeholder
  and Leakproof sends nothing even when this is on.

## Why

Counts tell us which checks find real problems and which stacks to support
next. They never tell us anything about your code.

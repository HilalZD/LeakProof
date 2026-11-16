# Release: v0.2.0 launch day

Hilal's steps, in order. Don't skip the checks. Run every command from the LeakProof folder.

## 1. Set SITE_URL, build and test

Use the live address of the site (from Serena's deploy, e.g. `https://leakproof.pages.dev`).

```bash
# src/config.ts
export const SITE_URL = "https://<live site>";
```

Also replace the placeholder in the same change:
- `README.md` line 94: `https://SITE_URL_PLACEHOLDER/fix?...` → the live address.
- `CONTRACT.md` section 4: say the site is live and give its address.
- `CHANGELOG.md`: `## 0.2.0 (unreleased)` → `## 0.2.0 (<launch date>)`.

```bash
npm run typecheck
npm test
npm run build
git add -A src README.md CONTRACT.md CHANGELOG.md
git commit -m "Set SITE_URL for launch"
```

(The tests read `SITE_URL` from `src/config.ts`, so they don't need changing.)

Check: `grep -rn SITE_URL_PLACEHOLDER src README.md CONTRACT.md test` prints nothing, and `node dist/index.js <any app>` prints a fix link with the live address.

## 2. Push main (ONLY main)

**Push `main` and nothing else. Never `git push --all`, never `git push --mirror`, never `backup-before-cleanup`
(it holds the old history with client names).**

```bash
git rev-list --count origin/main..main   # how many commits will go up; read their list first:
git log --oneline origin/main..main
git push origin main
```

Check: on GitHub, the latest commit on `main` matches `git log -1 --oneline`, and there is no `backup-before-cleanup` branch.

## 3. Make the GitHub repo public

GitHub → the LeakProof repo → Settings → General → Danger Zone → Change visibility → Public.

Check: open the repo in a private browser window (signed out); it loads.

## 4. Tag v0.2.0 and v0.2, push the tags

```bash
git tag v0.2.0
git tag v0.2
git push origin v0.2.0 v0.2
```

`v0.2` is a moving tag: it always points at the latest 0.2.x release, so people can use `HilalZD/LeakProof@v0.2`
in their workflows. For every future 0.2.x release, move it with `git tag -f v0.2` and `git push -f origin v0.2`.
That tag is the only thing that's ever force-pushed.

Check: `git ls-remote --tags origin` shows `v0.1.0`, `v0.2.0` and `v0.2`.

## 5. Publish to npm

```bash
npm whoami                 # signed in as the account that owns the @leakproof scope
npm pack --dry-run         # file list: dist/, README.md, LICENSE, CHANGELOG.md, package.json only
npm publish --access public
```

`prepublishOnly` runs typecheck, tests and build again before publishing.

Check: https://www.npmjs.com/package/@leakproof/cli shows 0.2.0.

## 6. Confirm with the published package

```bash
cd ../notenest-three-and-free
git checkout broken
npx @leakproof/cli@0.2.0 .
```

Check: the same result as before launch (NoteNest broken: Score 0/100, Grade F, 12 findings, exit 1), and the fix link
uses the live address. Then go back: `cd ../LeakProof`.

## 7. Record the demo GIF, commit, push

Follow the steps at the top of `docs/demo.tape`, then:

```bash
vhs docs/demo.tape
git add docs/demo.gif
git commit -m "Add demo GIF"
git push origin main
```

Check: the README on GitHub shows the GIF (it loads `docs/demo.gif` from `main`).

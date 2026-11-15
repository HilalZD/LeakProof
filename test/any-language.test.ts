// The secret and .env checks work on projects in any language; the
// route/auth/rate-limit/privacy checks stay JS/TS only.
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext, isCodeFile, isSkippedDir, isSourceFile } from "../src/lib/files.js";
import { ENV_VAR_FIX } from "../src/rules/leaked-keys.js";
import { runScan } from "../src/scan.js";

const openaiKey = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0".repeat(2);
const stripeKey = "sk_" + "live_" + "x".repeat(24);

let dir: string | undefined;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
});

async function project(files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-lang-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(dir, path, ".."), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return dir;
}

const git = (cwd: string, ...args: string[]) => execFileSync("git", args, { cwd, stdio: "ignore" });

describe("which files the secret check reads", () => {
  it("reads source in other languages, but not docs, lockfiles or .env files", () => {
    for (const name of ["app.py", "notebook.ipynb", "main.go", "index.php", "App.java", "deploy.sh", "settings.ini", "Dockerfile", "seed.sql"]) {
      expect(isSourceFile(name), name).toBe(true);
    }
    for (const name of ["README.md", "notes.txt", "poetry.lock", "go.sum", ".env", "image.png"]) expect(isSourceFile(name), name).toBe(false);
    // The JS-only checks keep their old list.
    expect(isCodeFile("app.py")).toBe(false);
  });

  it("skips Python, Go, PHP and Rust dependency and cache folders", () => {
    for (const name of [".venv", "venv", "__pycache__", ".pytest_cache", "site-packages", "vendor", "target", "gotrain.egg-info"]) {
      expect(isSkippedDir(name), name).toBe(true);
    }
    expect(isSkippedDir("src")).toBe(false);
  });
});

describe("Python project", () => {
  it("flags a key in a .py file, with a language-neutral fix", async () => {
    const root = await project({ "app/llm.py": `import openai\nclient = openai.OpenAI(api_key="${openaiKey}")\n` });
    const [finding, ...rest] = (await runScan(root)).findings;
    expect(rest).toEqual([]);
    expect(finding).toMatchObject({ fixId: "SEC_SECRET_HARDCODED", severity: "critical", file: "app/llm.py", line: 2 });
    expect(finding.fix).toBe(ENV_VAR_FIX);
    expect(finding.message).not.toContain(openaiKey);
  });

  it("keeps the JS fix for JS files", async () => {
    const root = await project({ "src/llm.ts": `const key = "${openaiKey}";\n` });
    expect((await runScan(root)).findings[0].fix).not.toBe(ENV_VAR_FIX);
  });

  it("ignores keys in a virtualenv (any name), docs and caches", async () => {
    const line = `KEY = "${stripeKey}"\n`;
    const root = await project({
      ".venv/lib/python3.12/site-packages/stripe/test_keys.py": line,
      "env/pyvenv.cfg": "home = /usr/bin\n",
      "env/lib/stripe_demo.py": line,
      "__pycache__/x.py": line,
      "README.md": `Example: ${stripeKey}\n`,
      "app.py": "print('hi')\n",
    });
    expect((await runScan(root)).findings).toEqual([]);
  });

  it("flags a committed .env in a project with no package.json", async () => {
    const root = await project({ ".env": `STRIPE_SECRET_KEY=${stripeKey}\n`, "main.py": "import os\n", "requirements.txt": "flask\n" });
    git(root, "init", "-q");
    git(root, "add", "-f", ".");
    git(root, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-q", "-m", "init");
    const findings = (await runScan(root)).findings;
    expect(findings.map((f) => `${f.fixId} ${f.file}:${f.line}`)).toEqual(["SEC_ENV_COMMITTED .env:1"]);
    expect(findings[0].message).toContain("committed to git");
    expect(findings[0].message).not.toContain("browser");
  });

  it("says 'Couldn't verify' for a Python Supabase app with no SQL in the repo", async () => {
    const root = await project({ "requirements.txt": "flask==3.0\nsupabase>=2.0\n", "app.py": "from supabase import create_client\n" });
    expect((await runScan(root)).findings.map((f) => f.fixId)).toEqual(["SEC_SUPABASE_RLS_UNVERIFIED"]);
  });

  it("doesn't run the JS-only route, rate-limit or privacy checks on Python code", async () => {
    const flask = `@app.post("/api/summarize")
def summarize():
    email = request.json["email"]
    print(email)
    return openai.chat.completions.create(model="gpt-4o", messages=[])
`;
    expect((await runScan(await project({ "app.py": flask }))).findings).toEqual([]);
  });
});

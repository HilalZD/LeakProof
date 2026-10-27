import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { classify, committedEnvCheck, parseEnv } from "../src/checks/committed-env.js";
import { mask } from "../src/lib/mask.js";
import { runScan } from "../src/scan.js";
import { CheckSkipped } from "../src/types.js";

// Fake keys are assembled at runtime so no full key literal appears in this
// file. Otherwise GitHub's secret scanner would block pushes.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (payload: object) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.${"s1g".repeat(10)}`;

const STRIPE_TEST = "sk_" + "test_" + "y".repeat(24);
const OPENAI = "sk-" + "proj-" + "A1b2C3d4".repeat(6);
const SERVICE_ROLE = jwt({ iss: "supabase", role: "service_role" });
const ANON = jwt({ iss: "supabase", role: "anon" });
const PUBLISHABLE = "sb_" + "publishable_" + "x_mvACpFwJ2iHWOQcP1I0w_IezmI1lH";
const DB_PASSWORD = "Hunter2" + "-Rq9vLm4Tz";
const DB_URL = `postgres://app:${DB_PASSWORD}@db.internal:5432/notes`;
const RANDOM_TOKEN = "tok" + "9fQ2mZ7rL4pX8wK1";

// Isolate git from this machine's global/system config (e.g. a global
// excludesFile that ignores .env would change the results).
const savedEnv = { ...process.env };
let emptyConfig: string;

beforeAll(async () => {
  emptyConfig = join(await mkdtemp(join(tmpdir(), "leakproof-gitconfig-")), "empty");
  await writeFile(emptyConfig, "");
  process.env.GIT_CONFIG_GLOBAL = emptyConfig;
  process.env.GIT_CONFIG_NOSYSTEM = "1";
});

afterAll(async () => {
  process.env = savedEnv;
  await rm(dirname(emptyConfig), { recursive: true, force: true });
});

describe("parseEnv", () => {
  it("handles quotes, comments, export, blank lines, CRLF and a BOM", () => {
    const content = [
      "﻿# a comment",
      "",
      "PLAIN=value1",
      'DOUBLE="value 2"',
      "SINGLE='value3'",
      "export EXPORTED=value4",
      "INLINE=value5 # trailing comment",
      'HASH="value#6"',
      "EMPTY=",
      "  SPACED = value7  ",
      "not a line",
    ].join("\r\n");

    expect(parseEnv(content)).toEqual([
      { line: 3, name: "PLAIN", value: "value1" },
      { line: 4, name: "DOUBLE", value: "value 2" },
      { line: 5, name: "SINGLE", value: "value3" },
      { line: 6, name: "EXPORTED", value: "value4" },
      { line: 7, name: "INLINE", value: "value5" },
      { line: 8, name: "HASH", value: "value#6" },
      { line: 9, name: "EMPTY", value: "" },
      { line: 10, name: "SPACED", value: "value7" },
    ]);
  });
});

describe("classify", () => {
  const secret = (name: string, value: string, example = false) =>
    classify({ line: 1, name, value }, example) !== undefined;

  it("Rule 1: flags real-shaped keys whatever the name", () => {
    expect(secret("STRIPE_SECRET_KEY", STRIPE_TEST)).toBe(true);
    expect(secret("SUPABASE_SERVICE_ROLE_KEY", SERVICE_ROLE)).toBe(true);
    expect(secret("SOMETHING", OPENAI)).toBe(true);
    // A safe-sounding name doesn't hide a real key.
    expect(secret("VITE_SUPABASE_ANON_KEY", SERVICE_ROLE)).toBe(true);
    expect(secret("NEXT_PUBLIC_KEY", STRIPE_TEST)).toBe(true);
  });

  it("Rule 2: flags secret-sounding names with real values", () => {
    for (const name of ["JWT_SECRET", "SUPABASE_SERVICE_ROLE", "PRIVATE_KEY", "DB_PASSWORD", "GITHUB_TOKEN", "RESEND_API_KEY"]) {
      expect(secret(name, RANDOM_TOKEN), name).toBe(true);
    }
  });

  it("Rule 2: ignores empty values and placeholders", () => {
    const placeholders = [
      "", "your-api-key", "your_secret_here", "xxx", "XXXXXXXX", "sk_test_xxx", "changeme", "change-me",
      "<paste key here>", "sk-...", "placeholder", "example-secret", "TODO", "${OTHER_SECRET}",
    ];
    for (const value of placeholders) {
      expect(secret("API_SECRET", value), value).toBe(false);
    }
  });

  it("never flags safe names or safe values", () => {
    expect(secret("SUPABASE_PUBLISHABLE_KEY", PUBLISHABLE)).toBe(false);
    expect(secret("VITE_SUPABASE_PUBLISHABLE_KEY", PUBLISHABLE)).toBe(false);
    expect(secret("SUPABASE_ANON_KEY", ANON)).toBe(false);
    expect(secret("SUPABASE_URL", "https://xbqofkbhoapvf.supabase.co")).toBe(false);
    expect(secret("VITE_SUPABASE_URL", "https://example.supabase.co")).toBe(false);
    expect(secret("SUPABASE_PROJECT_ID", "xbqofkbhoapvf")).toBe(false);
    expect(secret("NEXT_PUBLIC_SECRET_TOKEN", RANDOM_TOKEN)).toBe(false);
    expect(secret("PORT", "3000")).toBe(false);
  });

  it("Rule 3: flags URLs with embedded passwords whatever the name", () => {
    expect(secret("DATABASE_URL", DB_URL)).toBe(true);
    expect(secret("REDIS", `redis://:${DB_PASSWORD}@cache:6379`)).toBe(true);
    expect(secret("VITE_DB_URL", `mysql://root:${DB_PASSWORD}@localhost`)).toBe(true);
  });

  it("Rule 3: ignores URLs without a password or with a placeholder password", () => {
    expect(secret("DATABASE_URL", "postgres://db.internal:5432/notes")).toBe(false);
    expect(secret("DATABASE_URL", "postgres://app@db.internal/notes")).toBe(false);
    expect(secret("DATABASE_URL", "postgres://app:your-password@db.internal/notes")).toBe(false);
    expect(secret("DATABASE_URL", "postgres://app:${DB_PASSWORD}@db.internal/notes")).toBe(false);
    expect(secret("DATABASE_URL", "postgres://app:<password>@db.internal/notes")).toBe(false);
    expect(secret("SITE_URL", "https://example.supabase.co")).toBe(false);
  });

  it("Rule 3: masks only the password", () => {
    const result = classify({ line: 1, name: "DATABASE_URL", value: DB_URL }, false);
    expect(result?.masked).toBe("postgres://app:****@db.internal:5432");

    const atSign = classify({ line: 1, name: "DATABASE_URL", value: `postgres://app:p@ss${DB_PASSWORD}@db/x` }, false);
    expect(atSign?.masked).toBe("postgres://app:****@db");
  });

  it("never flags the example keys from AWS and Stripe docs", () => {
    const stripeDocs = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc";
    expect(secret("STRIPE_SECRET_KEY", stripeDocs)).toBe(false); // Rule 1 and Rule 2
    expect(secret("AWS_ACCESS_KEY_ID", "AK" + "IA" + "IOSFODNN7EXAMPLE")).toBe(false);
  });

  it("example files are only flagged for real-shaped keys", () => {
    expect(secret("STRIPE_SECRET_KEY", STRIPE_TEST, true)).toBe(true);
    expect(secret("JWT_SECRET", RANDOM_TOKEN, true)).toBe(false);
    expect(secret("DATABASE_URL", DB_URL, true)).toBe(false);
  });
});

describe("mask", () => {
  it("hides short values completely and keeps 4 characters of medium ones", () => {
    expect(mask("hunter2")).toBe("****");
    expect(mask("abcdefghijk")).toBe("****");
    expect(mask("abcdefghijklmnop")).toBe("abcd****");
    expect(mask("sk-" + "proj-" + "x".repeat(30) + "a1b2")).toBe("sk-proj-****a1b2");
  });
});

describe("committedEnvCheck in real git repos", () => {
  let dir: string;

  afterEach(async () => {
    delete process.env.GIT_CEILING_DIRECTORIES;
    process.env.PATH = savedEnv.PATH;
    await rm(dir, { recursive: true, force: true });
  });

  const run = (args: string[]) =>
    execFileSync("git", ["-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", ...args], {
      cwd: dir,
      stdio: "pipe",
    });

  async function project(
    files: Record<string, string>,
    git: { commit?: string[]; stage?: string[] } | false = {},
  ): Promise<string> {
    dir = await mkdtemp(join(tmpdir(), "leakproof-env-"));
    for (const [path, content] of Object.entries(files)) {
      await mkdir(dirname(join(dir, path)), { recursive: true });
      await writeFile(join(dir, path), content);
    }
    if (git === false) return dir;

    run(["init", "-q", "-b", "main"]);
    if (git.commit?.length) {
      run(["add", "-f", "--", ...git.commit]);
      run(["commit", "-q", "-m", "init"]);
    }
    if (git.stage?.length) run(["add", "-f", "--", ...git.stage]);
    return dir;
  }

  const secretEnv = [
    'SUPABASE_URL="https://xbqofkbhoapvf.supabase.co"',
    `SUPABASE_PUBLISHABLE_KEY="${PUBLISHABLE}"`,
    `STRIPE_SECRET_KEY=${STRIPE_TEST}`,
    `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE}`,
    `VITE_STRIPE_SECRET_KEY=${STRIPE_TEST}`,
  ].join("\n");

  it("tracked .env: one CRITICAL finding per secret line", async () => {
    const findings = await committedEnvCheck.run(await project({ ".env": secretEnv }, { commit: [".env"] }));

    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [3, "critical"],
      [4, "critical"],
      [5, "critical"],
    ]);
    expect(findings[0].message).toBe("STRIPE_SECRET_KEY is committed to git: sk_test_****yyyy");
    expect(findings[2].message).toBe("VITE_STRIPE_SECRET_KEY is committed to git and shipped to the browser: sk_test_****yyyy");

    // Every line in the file shares one fix, so the report can print it once.
    const fix =
      "Remove .env from git (git rm --cached .env), add .env to .gitignore, and rotate this key; it stays in git history even after deletion.";
    expect(findings.map((f) => f.fix)).toEqual([fix, fix, fix]);
  });

  it("tracked .env that is also in .gitignore is still CRITICAL", async () => {
    const files = { ".env": `STRIPE_SECRET_KEY=${STRIPE_TEST}`, ".gitignore": ".env\n" };
    const findings = await committedEnvCheck.run(await project(files, { commit: [".env", ".gitignore"] }));
    expect(findings.map((f) => f.severity)).toEqual(["critical"]);
  });

  it("staged but not yet committed counts as tracked", async () => {
    const findings = await committedEnvCheck.run(
      await project({ ".env": `STRIPE_SECRET_KEY=${STRIPE_TEST}`, "a.txt": "a" }, { commit: ["a.txt"], stage: [".env"] }),
    );
    expect(findings.map((f) => f.severity)).toEqual(["critical"]);
  });

  it("untracked and ignored: no findings", async () => {
    const findings = await committedEnvCheck.run(await project({ ".env": secretEnv, ".gitignore": ".env\n" }));
    expect(findings).toEqual([]);
  });

  it("untracked and not ignored: one MEDIUM finding per file", async () => {
    const findings = await committedEnvCheck.run(await project({ ".env.local": secretEnv }));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "medium", file: ".env.local", line: 3 });
    expect(findings[0].message).toContain("3 secrets (STRIPE_SECRET_KEY=sk_test_****yyyy, SUPABASE_SERVICE_ROLE_KEY=");
    expect(findings[0].message).toMatch(
      /not in \.gitignore, one git add away from being committed\. VITE_STRIPE_SECRET_KEY is also shipped to the browser\.$/,
    );
    expect(findings[0].fix).toBe("Add .env.local to .gitignore before it gets committed.");
  });

  it("MEDIUM without VITE_ secrets has no browser sentence", async () => {
    const findings = await committedEnvCheck.run(await project({ ".env.local": `STRIPE_SECRET_KEY=${STRIPE_TEST}` }));
    expect(findings[0].message).toMatch(/one git add away from being committed\.$/);
  });

  describe("LOW: committed .env with only safe values", () => {
    const safe = [
      'SUPABASE_PROJECT_ID="xbqofkbhoapvf"',
      `SUPABASE_PUBLISHABLE_KEY="${PUBLISHABLE}"`,
      'VITE_SUPABASE_URL="https://example.supabase.co"',
      `SUPABASE_ANON_KEY=${ANON}`,
      "API_SECRET=your-secret-here",
    ].join("\n");

    it("tracked + safe: one LOW finding for the file, without git rm advice", async () => {
      const findings = await committedEnvCheck.run(await project({ ".env": safe }, { commit: [".env"] }));
      expect(findings).toEqual([
        {
          checkId: "committed-env",
          severity: "low",
          file: ".env",
          message: ".env is committed to git. It's safe right now (public values only), but any secret you add here becomes public.",
          fix: "Keep secrets out of this file: store them in your platform's secrets manager (e.g. Lovable or Supabase secrets) or in a git-ignored .env.local.",
        },
      ]);
      expect(findings[0].fix).not.toContain("git rm");
    });

    it("uses the real file name", async () => {
      const findings = await committedEnvCheck.run(await project({ ".env.production": safe }, { commit: [".env.production"] }));
      expect(findings[0].message).toMatch(/^\.env\.production is committed to git\./);
    });

    it("tracked + secrets: only CRITICAL findings, never LOW", async () => {
      const findings = await committedEnvCheck.run(await project({ ".env": `${safe}\nSTRIPE_SECRET_KEY=${STRIPE_TEST}` }, { commit: [".env"] }));
      expect(findings.map((f) => f.severity)).toEqual(["critical"]);
    });

    it("tracked example file: no LOW", async () => {
      expect(await committedEnvCheck.run(await project({ ".env.example": safe }, { commit: [".env.example"] }))).toEqual([]);
    });

    it("tracked but empty or comments only: no LOW", async () => {
      expect(await committedEnvCheck.run(await project({ ".env": "# nothing here\n\n" }, { commit: [".env"] }))).toEqual([]);
    });

    it("untracked, ignored or not: no LOW", async () => {
      expect(await committedEnvCheck.run(await project({ ".env": safe }))).toEqual([]);
      await rm(dir, { recursive: true, force: true });
      expect(await committedEnvCheck.run(await project({ ".env": safe, ".gitignore": ".env\n" }))).toEqual([]);
    });
  });

  it("example files never get the 'shipped to the browser' wording", async () => {
    const example = `VITE_STRIPE_SECRET_KEY=${STRIPE_TEST}`;
    const tracked = await committedEnvCheck.run(await project({ ".env.example": example }, { commit: [".env.example"] }));
    await rm(dir, { recursive: true, force: true });
    const untracked = await committedEnvCheck.run(await project({ ".env.example": example }));

    expect(tracked).toHaveLength(1);
    expect(untracked).toHaveLength(1);
    for (const finding of [...tracked, ...untracked]) expect(finding.message).not.toContain("browser");
  });

  it("tracked example files are only flagged for a real-shaped key", async () => {
    const example = ["JWT_SECRET=" + RANDOM_TOKEN, "DATABASE_URL=" + DB_URL, "STRIPE_SECRET_KEY=" + STRIPE_TEST].join("\n");
    const findings = await committedEnvCheck.run(
      await project({ ".env.example": example, ".env.sample": example, ".env.local.template": example }, {
        commit: [".env.example", ".env.sample", ".env.local.template"],
      }),
    );
    expect(findings.map((f) => `${f.file}:${f.line}`)).toEqual([".env.example:3", ".env.local.template:3", ".env.sample:3"]);
    expect(findings[0].fix).toMatch(/^Replace the real value in \.env\.example with a placeholder/);
  });

  it("nested .env files and skipped folders", async () => {
    const leak = `STRIPE_SECRET_KEY=${STRIPE_TEST}`;
    const findings = await committedEnvCheck.run(
      await project(
        { "apps/web/.env": leak, "node_modules/pkg/.env": leak, "dist/.env": leak },
        { commit: ["apps/web/.env", "node_modules/pkg/.env", "dist/.env"] },
      ),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toBe("apps/web/.env");
    expect(findings[0].fix).toContain("git rm --cached apps/web/.env");
  });

  it("CRLF .env files report the right lines", async () => {
    const findings = await committedEnvCheck.run(
      await project({ ".env": `# comment\r\n\r\nexport DB_PASSWORD="${DB_PASSWORD}"\r\n` }, { commit: [".env"] }),
    );
    expect(findings).toMatchObject([{ line: 3, message: "DB_PASSWORD is committed to git: Hunter2-****m4Tz" }]);
  });

  it("never puts a full value in a finding", async () => {
    const values = [STRIPE_TEST, SERVICE_ROLE, OPENAI, DB_PASSWORD, RANDOM_TOKEN];
    const env = [
      `STRIPE_SECRET_KEY=${STRIPE_TEST}`,
      `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE}`,
      `OPENAI_API_KEY="${OPENAI}"`,
      `DATABASE_URL=${DB_URL}`,
      `GITHUB_TOKEN=${RANDOM_TOKEN}`,
    ].join("\n");

    const tracked = await committedEnvCheck.run(await project({ ".env": env }, { commit: [".env"] }));
    await rm(dir, { recursive: true, force: true });
    const untracked = await committedEnvCheck.run(await project({ ".env": env }));

    expect(tracked).toHaveLength(5);
    expect(untracked).toHaveLength(1);
    const serialized = JSON.stringify([...tracked, ...untracked]);
    for (const value of values) expect(serialized).not.toContain(value);
  });

  it("not a git repo: skips with a clear reason", async () => {
    await project({ ".env": secretEnv }, false);
    process.env.GIT_CEILING_DIRECTORIES = dirname(dir);

    await expect(committedEnvCheck.run(dir)).rejects.toThrow(CheckSkipped);
    await expect(committedEnvCheck.run(dir)).rejects.toThrow("Not a git repository");

    const result = await runScan(dir);
    expect(result.skipped.map((s) => s.check.id)).toEqual(["committed-env"]);
  });

  it("git not installed: skips with a clear reason", async () => {
    await project({ ".env": secretEnv }, false);
    process.env.PATH = "";
    await expect(committedEnvCheck.run(dir)).rejects.toThrow("git is not installed");
  });

  it("no .env files: no findings and no git needed", async () => {
    await project({ "src/app.ts": "export {};" }, false);
    process.env.PATH = "";
    expect(await committedEnvCheck.run(dir)).toEqual([]);
  });
});

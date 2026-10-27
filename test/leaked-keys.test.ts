import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { leakedKeysCheck, mask, scanContent } from "../src/checks/leaked-keys.js";

// Fake keys are assembled at runtime so no full key literal appears in this
// file. Otherwise GitHub's secret scanner would block pushes.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (payload: object) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.${"s1g".repeat(10)}`;

const KEYS = {
  openaiProject: "sk-" + "proj-" + "A1b2C3d4".repeat(6),
  openaiLegacy: "sk-" + "A1b2C3".repeat(8),
  anthropic: "sk-" + "ant-" + "api03-" + "x9Y8w7".repeat(6),
  stripeLive: "sk_" + "live_" + "x".repeat(24),
  stripeTest: "sk_" + "test_" + "y".repeat(24),
  stripeRestrictedLive: "rk_" + "live_" + "z".repeat(24),
  stripeRestrictedTest: "rk_" + "test_" + "w".repeat(24),
  supabaseSecret: "sb_" + "secret_" + "Ab1_Cd2-".repeat(4),
  aws: "AK" + "IA" + "ABCDEFGHIJ234567",
  githubClassic: "gh" + "p_" + "a1B2".repeat(9),
  githubFineGrained: "github_" + "pat_" + "11ABCDEFG0" + "_x1y2z3".repeat(6),
  serviceRoleJwt: jwt({ iss: "supabase", role: "service_role" }),
};

const EXPECTED: Record<keyof typeof KEYS, { name: string; severity: string }> = {
  openaiProject: { name: "OpenAI API key", severity: "critical" },
  openaiLegacy: { name: "OpenAI API key", severity: "critical" },
  anthropic: { name: "Anthropic API key", severity: "critical" },
  stripeLive: { name: "Stripe live secret key", severity: "critical" },
  stripeTest: { name: "Stripe test secret key", severity: "high" },
  stripeRestrictedLive: { name: "Stripe live secret key", severity: "critical" },
  stripeRestrictedTest: { name: "Stripe test secret key", severity: "high" },
  supabaseSecret: { name: "Supabase secret key", severity: "critical" },
  aws: { name: "AWS access key", severity: "critical" },
  githubClassic: { name: "GitHub token", severity: "critical" },
  githubFineGrained: { name: "GitHub token", severity: "critical" },
  serviceRoleJwt: { name: "Supabase service_role key", severity: "critical" },
};

const onLine3 = (code: string) => `// first line\n// second line\n${code}\n`;

describe("Detection A: hardcoded keys", () => {
  for (const [id, key] of Object.entries(KEYS) as [keyof typeof KEYS, string][]) {
    it(`flags ${id}`, () => {
      const findings = scanContent("src/app.ts", onLine3(`const key = "${key}";`));

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        checkId: "leaked-keys",
        file: "src/app.ts",
        line: 3,
        severity: EXPECTED[id].severity,
      });
      expect(findings[0].message).toContain(EXPECTED[id].name);
      expect(findings[0].fix).toBeTruthy();
    });
  }

  it("does not report sk_live_, sk_test_ or sk-ant- keys as OpenAI keys", () => {
    for (const key of [KEYS.stripeLive, KEYS.stripeTest, KEYS.anthropic]) {
      const findings = scanContent("a.ts", `"${key}"`);
      expect(findings.some((f) => f.message.includes("OpenAI"))).toBe(false);
    }
  });

  it("does not match a key prefix inside a longer word", () => {
    expect(scanContent("a.ts", `const x = "task-${"A1b2C3".repeat(8)}";`)).toEqual([]);
  });

  it("reports the right line numbers with Windows line endings", () => {
    const findings = scanContent("a.ts", `// one\r\n// two\r\n"${KEYS.aws}"\r\n`);
    expect(findings[0].line).toBe(3);
  });
});

describe("safe decoys are never flagged", () => {
  const decoys = {
    stripePublishableLive: "pk_" + "live_" + "x".repeat(24),
    stripePublishableTest: "pk_" + "test_" + "FAKE51Nq8xKLmPzR4tVbW7yHcJ2dGfA9sXeU6oIuY3nTqM5wZ",
    supabasePublishable: "sb_" + "publishable_" + "x_mvACpFwJ2iHWOQcP1I0w_IezmI1lH",
    anonJwt: jwt({ iss: "supabase", role: "anon" }),
    undecodableJwt: "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "!!notbase64json" + ".sig",
    garbagePayloadJwt: "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zzzzzzzz" + ".sig",
  };

  for (const [id, value] of Object.entries(decoys)) {
    it(`ignores ${id}`, () => {
      expect(scanContent("a.ts", `const key = "${value}";`)).toEqual([]);
    });
  }

  describe("example keys published in AWS and Stripe docs", () => {
    const documented = [
      "AK" + "IA" + "IOSFODNN7EXAMPLE",
      "AK" + "IA" + "I44QH8DHBEXAMPLE",
      "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc",
      "sk_" + "test_" + "BQokikJOvBiI2HlWgH4olfQ2",
    ];

    for (const value of documented) {
      it(`ignores ${value.slice(0, 8)}****`, () => {
        expect(scanContent("test/fixtures.test.ts", `const key = "${value}";`)).toEqual([]);
      });
    }

    it("still flags a key that differs from a documented one by one character", () => {
      const nearMiss = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dd";
      expect(scanContent("a.ts", `const key = "${nearMiss}";`)).toHaveLength(1);
    });

    it("still flags a longer key that starts with a documented one", () => {
      const extended = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc" + "Z9";
      expect(scanContent("a.ts", `"${extended}"`)).toHaveLength(1);
    });

    it("still flags made-up key-shaped strings in test files (known gap)", () => {
      expect(scanContent("test/scanner.test.ts", `"${"sk-" + "abcdefghij".repeat(3)}"`)).toHaveLength(1);
    });
  });

  it("ignores a bare sb_secret_ prefix check", () => {
    const code = "return value.startsWith('sb_" + "publishable_') || value.startsWith('sb_" + "secret_');";
    expect(scanContent("a.ts", code)).toEqual([]);
  });
});

describe("Detection B: secrets exposed through Vite", () => {
  const flagged = [
    "import.meta.env.VITE_STRIPE_SECRET_KEY",
    'import.meta.env["VITE_STRIPE_SECRET_KEY"]',
    "import.meta.env['VITE_SUPABASE_SERVICE_ROLE_KEY']",
    "import.meta.env.VITE_PRIVATE_TOKEN",
    "import.meta.env.VITE_DB_PASSWORD",
  ];
  for (const code of flagged) {
    it(`flags ${code}`, () => {
      const findings = scanContent("src/lib/payments.ts", onLine3(`fetch(url, { key: ${code} });`));
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ severity: "high", line: 3 });
    });
  }

  const safe = [
    "import.meta.env.VITE_SUPABASE_URL",
    "import.meta.env['VITE_SUPABASE_PUBLISHABLE_KEY']",
    "import.meta.env.MODE",
    "readonly VITE_STRIPE_SECRET_KEY: string;", // type declaration in vite-env.d.ts
    "process.env.STRIPE_SECRET_KEY", // server-side, not shipped by Vite
  ];
  for (const code of safe) {
    it(`ignores ${code}`, () => {
      expect(scanContent("a.ts", code)).toEqual([]);
    });
  }
});

describe("masking", () => {
  it("shows the first 8 and last 4 characters only", () => {
    expect(mask("sk-" + "proj-" + "x".repeat(30) + "a1b2")).toBe("sk-proj-****a1b2");
  });

  it("never puts a full key in a finding", () => {
    for (const key of Object.values(KEYS)) {
      const [finding] = scanContent("a.ts", `"${key}"`);
      const serialized = JSON.stringify(finding);

      expect(serialized).not.toContain(key);
      expect(finding.message).toContain(key.slice(0, 8) + "****" + key.slice(-4));
    }
  });
});

describe("file walking", () => {
  let dir: string;

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function project(files: Record<string, string | Buffer>): Promise<string> {
    dir = await mkdtemp(join(tmpdir(), "leakproof-keys-"));
    for (const [path, content] of Object.entries(files)) {
      await mkdir(dirname(join(dir, path)), { recursive: true });
      await writeFile(join(dir, path), content);
    }
    return dir;
  }

  const leak = `const key = "${KEYS.stripeLive}";\n`;

  it("scans nested files and reports paths with forward slashes", async () => {
    const findings = await leakedKeysCheck.run(await project({ "src/lib/ai.ts": `\n${leak}` }));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ file: "src/lib/ai.ts", line: 2 });
  });

  it("scans every supported extension", async () => {
    const exts = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "json", "vue", "svelte", "html", "toml", "yaml", "yml"];
    const files = Object.fromEntries(exts.map((ext) => [`src/file.${ext}`, leak]));
    const findings = await leakedKeysCheck.run(await project(files));
    expect(findings).toHaveLength(exts.length);
  });

  it("skips ignored folders, .env files, lockfiles, minified, binary, large and unsupported files", async () => {
    const binary = Buffer.concat([Buffer.from(leak), Buffer.from([0, 1, 2, 3])]);
    const large = leak + "// padding\n".repeat(100_000); // just over 1 MB

    const findings = await leakedKeysCheck.run(
      await project({
        "src/real.ts": leak, // control: the only file that should be reported
        "node_modules/pkg/index.js": leak,
        ".git/hooks/pre-commit.js": leak,
        "dist/index.js": leak,
        "build/index.js": leak,
        ".next/server/page.js": leak,
        ".output/public/assets/index.js": leak,
        "coverage/report.json": leak,
        "src/nested/node_modules/pkg/index.js": leak,
        ".env": leak,
        ".env.local": leak,
        ".env.production.json": leak,
        "package-lock.json": leak,
        "npm-shrinkwrap.json": leak,
        "yarn.lock": leak,
        "pnpm-lock.yaml": leak,
        "bun.lock": leak,
        "public/vendor.min.js": leak,
        "src/binary.js": binary,
        "src/large.js": large,
        "notes.md": leak,
        "notes.txt": leak,
      }),
    );

    expect(findings.map((f) => f.file)).toEqual(["src/real.ts"]);
  });
});

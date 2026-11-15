import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { globToRegExp, isIgnored, loadIgnoreFile, parseIgnoreFile } from "../src/lib/ignore.js";

const at = (file: string | undefined, fixId: string) => ({ file, fixId });

describe("parseIgnoreFile", () => {
  const entries = parseIgnoreFile(
    [
      "# LeakProof ignore file",
      "",
      "SEC_ENV_COMMITTED_PUBLIC_ONLY        # a fixId: everywhere",
      "src/legacy/                          # a folder",
      "**/*.stories.tsx                     # a glob",
      "docs/demo.ts:SEC_SECRET_HARDCODED     # path:fixId",
      "fixtures/**:SEC_SECRET_CLIENT_EXPOSED # glob:fixId",
      "   # indented comment",
    ].join("\r\n"),
  );

  it("reads all three formats and skips comments and blank lines", () => {
    expect(entries.map((e) => [e.fixId ?? null, e.path ? e.source.split(":")[0] : null])).toEqual([
      ["SEC_ENV_COMMITTED_PUBLIC_ONLY", null],
      [null, "src/legacy/"],
      [null, "**/*.stories.tsx"],
      ["SEC_SECRET_HARDCODED", "docs/demo.ts"],
      ["SEC_SECRET_CLIENT_EXPOSED", "fixtures/**"],
    ]);
  });

  it("a fixId entry ignores that fixId anywhere, including findings with no file", () => {
    expect(isIgnored(at(".env", "SEC_ENV_COMMITTED_PUBLIC_ONLY"), entries)).toBe(true);
    expect(isIgnored(at(undefined, "SEC_ENV_COMMITTED_PUBLIC_ONLY"), entries)).toBe(true);
    expect(isIgnored(at(".env", "SEC_ENV_COMMITTED"), entries)).toBe(false);
  });

  it("a path or glob entry ignores every finding in matching files", () => {
    expect(isIgnored(at("src/legacy/old.ts", "SEC_SECRET_HARDCODED"), entries)).toBe(true);
    expect(isIgnored(at("src/legacy/deep/er.ts", "SEC_ENV_COMMITTED"), entries)).toBe(true);
    expect(isIgnored(at("src/components/Button.stories.tsx", "SEC_SECRET_HARDCODED"), entries)).toBe(true);
    expect(isIgnored(at("src/legacyish.ts", "SEC_SECRET_HARDCODED"), entries)).toBe(false);
    expect(isIgnored(at(undefined, "SEC_SECRET_HARDCODED"), entries)).toBe(false);
  });

  it("a path:fixId entry ignores only that fixId in matching files", () => {
    expect(isIgnored(at("docs/demo.ts", "SEC_SECRET_HARDCODED"), entries)).toBe(true);
    expect(isIgnored(at("docs/demo.ts", "SEC_SECRET_CLIENT_EXPOSED"), entries)).toBe(false);
    expect(isIgnored(at("src/demo.ts", "SEC_SECRET_HARDCODED"), entries)).toBe(false);
    expect(isIgnored(at("fixtures/a/b.ts", "SEC_SECRET_CLIENT_EXPOSED"), entries)).toBe(true);
  });

  it("an empty or comment-only file ignores nothing", () => {
    expect(parseIgnoreFile("")).toEqual([]);
    expect(parseIgnoreFile("# nothing\n\n  # still nothing\n")).toEqual([]);
  });
});

describe("globToRegExp", () => {
  it("* stays in one folder, ** crosses folders, ? is one character", () => {
    expect(globToRegExp("src/*.ts").test("src/a.ts")).toBe(true);
    expect(globToRegExp("src/*.ts").test("src/x/a.ts")).toBe(false);
    expect(globToRegExp("src/**/*.ts").test("src/a.ts")).toBe(true);
    expect(globToRegExp("src/**/*.ts").test("src/x/y/a.ts")).toBe(true);
    expect(globToRegExp("src/?.ts").test("src/a.ts")).toBe(true);
    expect(globToRegExp("src/?.ts").test("src/ab.ts")).toBe(false);
  });

  it("a name with no slash matches at any depth; one with a slash is from the project root", () => {
    expect(globToRegExp(".env.example").test("apps/web/.env.example")).toBe(true);
    expect(globToRegExp("web/.env").test("apps/web/.env")).toBe(false);
    expect(globToRegExp("./web/.env").test("web/.env")).toBe(true);
    expect(globToRegExp("/web/.env").test("web/.env")).toBe(true);
  });

  it("treats regex characters literally", () => {
    expect(globToRegExp("a+b(1).ts").test("a+b(1).ts")).toBe(true);
    expect(globToRegExp("a.ts").test("abts")).toBe(false);
  });
});

describe("loadIgnoreFile", () => {
  it("reads .leakproofignore from the project root, or returns nothing if it's missing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "leakproof-ignore-"));
    try {
      expect(loadIgnoreFile(dir)).toEqual([]);
      await writeFile(join(dir, ".leakproofignore"), "SEC_ENV_COMMITTED\n");
      expect(loadIgnoreFile(dir).map((e) => e.fixId)).toEqual(["SEC_ENV_COMMITTED"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

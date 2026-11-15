import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createProjectContext } from "../src/lib/files.js";
import { hasRateLimit, rateLimitRule, scanContent } from "../src/rules/rate-limit.js";

// The rule runs on a ProjectContext; these tests pass a folder.
const rateLimitCheck = { run: async (dir: string) => rateLimitRule.run(await createProjectContext(dir)) };


const FIX =
  "Add a per-user or per-IP rate limit before the expensive call (for example @upstash/ratelimit), and require login for anything that costs money.";

/** 1-based line of the first line containing `needle`. */
const lineOf = (code: string, needle: string) => code.split("\n").findIndex((l) => l.includes(needle)) + 1;

// An OpenAI call through the SDK, as a fetch-style handler body.
const OPENAI_SDK = `import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const result = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: prompt }] });
  return Response.json(result);
}
`;
const OPENAI_CALL = "openai.chat.completions.create";

describe("Step A: endpoint styles", () => {
  const styles: Record<string, string> = {
    "Next.js app router": "app/api/chat/route.ts",
    "Next.js app router under src": "src/app/api/chat/route.ts",
    "Next.js pages router": "pages/api/chat.ts",
    "TanStack Start route folder": "src/routes/api/chat.ts",
    "TanStack Start flat route": "src/routes/api.chat.ts",
    "Supabase edge function": "supabase/functions/chat/index.ts",
    "Netlify function": "netlify/functions/chat.ts",
    "Vercel function": "api/chat.ts",
  };

  for (const [style, file] of Object.entries(styles)) {
    it(`flags ${style} (${file})`, () => {
      const finding = scanContent(file, OPENAI_SDK);
      expect(finding).toMatchObject({ ruleId: "rate-limit", severity: "high", file, line: lineOf(OPENAI_SDK, OPENAI_CALL) });
    });
  }

  it("flags an Express handler anywhere in the project", () => {
    const code = `import express from "express";
import OpenAI from "openai";
const app = express();
const openai = new OpenAI();
app.post("/chat", async (req, res) => {
  const result = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: req.body.messages });
  res.json(result);
});
`;
    expect(scanContent("server/routes.ts", code)).toMatchObject({ severity: "high", line: lineOf(code, OPENAI_CALL) });
  });

  it("flags a Hono handler anywhere in the project", () => {
    const code = `import { Hono } from "hono";
import { Resend } from "resend";
const app = new Hono();
const resend = new Resend(process.env.RESEND_API_KEY);
app.post("/invite", async (c) => {
  await resend.emails.send({ from: "a@b.c", to: (await c.req.json()).email, subject: "Hi", text: "Hi" });
  return c.json({ ok: true });
});
`;
    expect(scanContent("src/worker.ts", code)).toMatchObject({ severity: "medium", line: lineOf(code, "resend.emails.send") });
  });

  it("does not flag Express-style calls without an Express or Hono import", () => {
    // e.g. an axios instance named api in frontend code
    const code = `import OpenAI from "openai";\napi.post("/chat", body);\nawait new OpenAI().chat.completions.create({});\n`;
    expect(scanContent("src/lib/client.ts", code)).toBeUndefined();
  });

  it("skips Supabase _shared helpers", () => {
    expect(scanContent("supabase/functions/_shared/openai.ts", OPENAI_SDK)).toBeUndefined();
  });

  it("does not flag generic endpoints", () => {
    const code = `export async function GET() {\n  const rows = await db.select().from(notes);\n  return Response.json(rows);\n}\n`;
    expect(scanContent("app/api/notes/route.ts", code)).toBeUndefined();
  });
});

describe("frontend code is never flagged", () => {
  it("ignores a browser fetch to the OpenAI API", () => {
    const code = `export async function summarize(text: string) {\n  return fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: text });\n}\n`;
    expect(scanContent("src/lib/ai.ts", code)).toBeUndefined();
    expect(scanContent("src/components/Summarize.tsx", code)).toBeUndefined();
    expect(scanContent("src/pages/Index.tsx", code)).toBeUndefined();
  });

  it('ignores "use client" files even in an endpoint folder', () => {
    expect(scanContent("app/api/chat/route.ts", `"use client";\n${OPENAI_SDK}`)).toBeUndefined();
  });
});

describe("Step B: paid AI providers (HIGH)", () => {
  const providers: Record<string, { code: string; call: string }> = {
    OpenAI: { code: OPENAI_SDK, call: OPENAI_CALL },
    "OpenAI (fetch)": {
      code: `const r = await fetch("https://api.openai.com/v1/responses", { method: "POST" });\n`,
      call: "api.openai.com",
    },
    Anthropic: {
      code: `import Anthropic from "@anthropic-ai/sdk";\nconst client = new Anthropic();\nconst msg = await client.messages.create({ model: "claude", max_tokens: 100, messages: [] });\n`,
      call: "client.messages.create",
    },
    "Google Gemini": {
      code: `import { GoogleGenerativeAI } from "@google/generative-ai";\nconst model = new GoogleGenerativeAI(key).getGenerativeModel({ model: "gemini" });\nconst out = await model.generateContent(prompt);\n`,
      call: "model.generateContent",
    },
    "the Vercel AI SDK": {
      code: `import { streamText } from "ai";\nimport { someProvider } from "./provider";\nconst result = streamText({ model: someProvider("x"), prompt });\n`,
      call: "streamText({",
    },
    Replicate: {
      code: `import Replicate from "replicate";\nconst replicate = new Replicate();\nconst output = await replicate.run("owner/model", { input });\n`,
      call: "replicate.run",
    },
    ElevenLabs: {
      code: `import { ElevenLabsClient } from "@elevenlabs/elevenlabs-js";\nconst client = new ElevenLabsClient();\nconst audio = await client.textToSpeech.convert(voiceId, { text });\n`,
      call: "client.textToSpeech.convert",
    },
  };

  for (const [name, { code, call }] of Object.entries(providers)) {
    const provider = name.replace(" (fetch)", "");
    it(`flags ${name} at the line of the call`, () => {
      const finding = scanContent("supabase/functions/ai/index.ts", code);
      expect(finding).toMatchObject({ severity: "high", line: lineOf(code, call), fix: FIX });
      expect(finding?.message).toBe(
        `This endpoint calls ${provider} with no rate limit: anyone can call it in a loop and run up your AI bill. It also doesn't require login.`,
      );
    });
  }

  it("recognizes Deno-style imports (npm: and esm.sh)", () => {
    for (const spec of ["npm:openai@4", "https://esm.sh/openai@4.20.0"]) {
      const code = `import OpenAI from "${spec}";\nconst c = new OpenAI();\nawait c.chat.completions.create({});\n`;
      expect(scanContent("supabase/functions/ai/index.ts", code)?.message, spec).toContain("calls OpenAI");
    }
  });

  it("does not treat the 'ai' package without a generate/stream call as an AI call", () => {
    expect(scanContent("app/api/x/route.ts", `import type { Message } from "ai";\nexport const GET = () => Response.json([]);\n`)).toBeUndefined();
  });
});

describe("login check wording", () => {
  const withoutLogin = "It also doesn't require login.";

  const logins = {
    "supabase.auth.getUser": `const { data } = await supabase.auth.getUser(token);\n`,
    "reading the Authorization header": `const token = req.headers.get("Authorization");\n`,
    "Express-style header": `const token = req.headers.authorization;\n`,
    "a requireAuth helper": `await requireAuth(req);\n`,
    "next-auth": `const session = await getServerSession(authOptions);\n`,
    "Clerk": `const { userId } = await auth();\n`,
  };

  for (const [name, login] of Object.entries(logins)) {
    it(`leaves out the login sentence when the endpoint uses ${name}`, () => {
      const message = scanContent("app/api/chat/route.ts", login + OPENAI_SDK)?.message;
      expect(message).toContain("calls OpenAI with no rate limit");
      expect(message).not.toContain(withoutLogin);
    });
  }

  // Regression (act-solo-ai): login checked by a shared helper from _shared/auth.ts.
  it("recognizes shared login helpers such as getAuthedUser(req)", () => {
    for (const helper of ["getAuthedUser(req)", "getCurrentUser()", "verifyAuth(req)", "ensureUser(req)"]) {
      const message = scanContent("supabase/functions/ai/index.ts", `if (!(await ${helper})) return unauthorized();\n${OPENAI_SDK}`)?.message;
      expect(message, helper).not.toContain(withoutLogin);
    }
  });

  it("doesn't count setting an Authorization header on the outgoing AI call as a login check", () => {
    const code = `const r = await fetch("https://api.openai.com/v1/chat/completions", {\n  headers: { "Authorization": \`Bearer \${process.env.OPENAI_API_KEY}\` },\n});\n`;
    expect(scanContent("app/api/chat/route.ts", code)?.message).toContain(withoutLogin);
  });

  it("never adds the login sentence to email findings", () => {
    const code = `import { Resend } from "resend";\nawait new Resend(key).emails.send({});\n`;
    expect(scanContent("app/api/invite/route.ts", code)?.message).not.toContain(withoutLogin);
  });
});

describe("Step B: email, SMS and auth (MEDIUM)", () => {
  const senders: Record<string, { kind: "email" | "SMS"; code: string; call: string }> = {
    Resend: { kind: "email", code: `import { Resend } from "resend";\nconst resend = new Resend(key);\nawait resend.emails.send({ to });\n`, call: "resend.emails.send" },
    "Resend (fetch)": { kind: "email", code: `await fetch("https://api.resend.com/emails", { method: "POST" });\n`, call: "api.resend.com" },
    SendGrid: { kind: "email", code: `import sgMail from "@sendgrid/mail";\nsgMail.setApiKey(key);\nawait sgMail.send(msg);\n`, call: "sgMail.send(" },
    Nodemailer: { kind: "email", code: `import nodemailer from "nodemailer";\nconst t = nodemailer.createTransport(opts);\nawait t.sendMail({ to });\n`, call: "t.sendMail" },
    Postmark: { kind: "email", code: `import { ServerClient } from "postmark";\nconst client = new ServerClient(key);\nawait client.sendEmail({ To: to });\n`, call: "client.sendEmail" },
    Twilio: { kind: "SMS", code: `import twilio from "twilio";\nconst client = twilio(sid, token);\nawait client.messages.create({ to, body });\n`, call: "client.messages.create" },
    Vonage: { kind: "SMS", code: `import { Vonage } from "@vonage/server-sdk";\nconst vonage = new Vonage(creds);\nawait vonage.sms.send({ to, text });\n`, call: "vonage.sms.send" },
  };

  for (const [name, { kind, code, call }] of Object.entries(senders)) {
    const provider = name.replace(" (fetch)", "");
    it(`flags ${name} as MEDIUM at the line of the send`, () => {
      const finding = scanContent("netlify/functions/notify.ts", code);
      expect(finding).toMatchObject({ severity: "medium", line: lineOf(code, call) });
      expect(finding?.message).toContain(`sends ${kind} through ${provider} with no rate limit`);
    });
  }

  // Regression (bitebag): checking a Verify code sends nothing.
  it("does not flag a Twilio Verify code check, but flags sending a Verify code", () => {
    const check = `const url = \`https://verify.twilio.com/v2/Services/\${sid}/VerificationCheck\`;\nconst res = await fetch(url, { method: "POST", body });\n`;
    expect(scanContent("supabase/functions/verify-otp/index.ts", check)).toBeUndefined();
    expect(scanContent("supabase/functions/check/index.ts", `import twilio from "twilio";\nawait client.verify.v2.services(sid).verificationChecks.create({ to, code });\n`)).toBeUndefined();

    const send = check.replace("VerificationCheck", "Verifications");
    expect(scanContent("supabase/functions/send-otp/index.ts", send)).toMatchObject({ severity: "medium", line: 2 });
  });

  // Regression (bitebag): the URL is built on one line and fetched later.
  it("reports the fetch line when the API URL is assigned earlier", () => {
    const code = `const url = "https://api.openai.com/v1/chat/completions";\nconst body = JSON.stringify(payload);\n\nconst res = await fetch(url, { method: "POST", body });\n`;
    expect(scanContent("supabase/functions/ai/index.ts", code)?.line).toBe(4);
  });

  it("flags a custom login handler with its own password check", () => {
    const code = `import bcrypt from "bcryptjs";\nexport async function POST(req: Request) {\n  const { email, password } = await req.json();\n  const user = await db.findUser(email);\n  const ok = await bcrypt.compare(password, user.hash);\n  return Response.json({ ok });\n}\n`;
    const finding = scanContent("app/api/auth/login/route.ts", code);
    expect(finding).toMatchObject({ severity: "medium", line: lineOf(code, "bcrypt.compare") });
    expect(finding?.message).toContain("login/signup endpoint has no rate limit");
  });

  it("flags custom signup and password reset handlers", () => {
    const code = `import jwt from "jsonwebtoken";\nconst token = jwt.sign({ sub: user.id }, secret);\n`;
    expect(scanContent("pages/api/signup.ts", code)?.severity).toBe("medium");
    expect(scanContent("supabase/functions/reset-password/index.ts", code)?.severity).toBe("medium");
  });

  it("does not flag handlers that only use Supabase Auth", () => {
    const code = `export async function POST(req: Request) {\n  const { email, password } = await req.json();\n  const { error } = await supabase.auth.signInWithPassword({ email, password });\n  await supabase.auth.signInWithOtp({ phone: email });\n  return Response.json({ error });\n}\n`;
    expect(scanContent("app/api/auth/login/route.ts", code)).toBeUndefined();
  });

  it("does not flag password hashing outside an auth endpoint path", () => {
    expect(scanContent("app/api/notes/route.ts", `import bcrypt from "bcryptjs";\nawait bcrypt.hash(x, 10);\n`)).toBeUndefined();
  });
});

describe("one finding per endpoint file", () => {
  it("reports AI over email, at the AI call's line", () => {
    const code = `import OpenAI from "openai";\nimport { Resend } from "resend";\nawait new Resend(k).emails.send({});\nconst out = await new OpenAI().chat.completions.create({});\n`;
    const findings = [scanContent("app/api/x/route.ts", code)].filter(Boolean);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "high", line: lineOf(code, "chat.completions.create") });
  });

  it("uses the earliest AI call when a file calls several providers", () => {
    const code = `import Anthropic from "@anthropic-ai/sdk";\nimport OpenAI from "openai";\nconst a = await new Anthropic().messages.create({});\nconst b = await new OpenAI().chat.completions.create({});\n`;
    expect(scanContent("app/api/x/route.ts", code)?.message).toContain("calls Anthropic");
  });

  it("falls back to the provider's import line when the call isn't recognized", () => {
    const code = `import OpenAI from "openai";\nconst client = new OpenAI();\nexport const POST = () => helper(client);\n`;
    expect(scanContent("app/api/x/route.ts", code)?.line).toBe(2);
  });
});

describe("Step C: what counts as a rate limit", () => {
  const limited: Record<string, string> = {
    "@upstash/ratelimit": `import { Ratelimit } from "@upstash/ratelimit";\nconst rl = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "1 m") });\n`,
    "express-rate-limit": `import rateLimit from "express-rate-limit";\n`,
    "rate-limiter-flexible": `const { RateLimiterMemory } = require("rate-limiter-flexible");\n`,
    "hono-rate-limiter": `import { rateLimiter } from "hono-rate-limiter";\n`,
    "Deno import of @upstash/ratelimit": `import { Ratelimit } from "https://esm.sh/@upstash/ratelimit@2";\n`,
    "a local rateLimit() helper": `import { rateLimit } from "@/lib/limits";\nawait rateLimit(ip);\n`,
    "a local checkRatelimit() helper": `if (!(await checkRatelimit(req))) return new Response("Slow down", { status: 429 });\n`,
    "a helper used as middleware": `app.use(apiRateLimiter);\n`,
    "a snake_case helper": `await enforce_rate_limit(user.id);\n`,
    "a Postgres rate limit function": `const { data } = await supabase.rpc("check_rate_limit", { p_user: id });\n`,
    "a 429 response with request counting": `const count = (hits.get(ip) ?? 0) + 1;\nhits.set(ip, count);\nif (count > 10) return new Response("Too many", { status: 429 });\n`,
    "a 429 response with redis incr": `const n = await redis.incr(key);\nif (n > 5) return res.status(429).end();\n`,
  };

  for (const [name, limit] of Object.entries(limited)) {
    it(`accepts ${name}`, () => {
      expect(scanContent("app/api/chat/route.ts", limit + OPENAI_SDK)).toBeUndefined();
    });
  }

  const notLimited: Record<string, string> = {
    "a commented-out import": `// import { Ratelimit } from "@upstash/ratelimit";\n`,
    "a commented-out helper call": `/* await rateLimit(ip); */\n`,
    "a 'Rate limit exceeded' message passed on from the AI provider": `if (r.status === 429) return Response.json({ error: "Rate limit exceeded" }, { status: 429 });\n`,
    "a 429 without counting": `if (busy) return new Response("busy", { status: 429 });\n`,
    "a variable that only mentions rate limits": `const rateLimited = r.status === 429;\n`,
  };

  for (const [name, code] of Object.entries(notLimited)) {
    it(`does not accept ${name}`, () => {
      expect(scanContent("app/api/chat/route.ts", code + OPENAI_SDK)?.severity).toBe("high");
    });
  }

  it("hasRateLimit works on its own", () => {
    expect(hasRateLimit(`import rateLimit from "express-rate-limit";`)).toBe(true);
    expect(hasRateLimit(`return "rate limit";`)).toBe(false);
  });
});

describe("exclusions", () => {
  it("skips Stripe webhook handlers, verified or not", () => {
    const unverified = `export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === "checkout.session.completed") await new OpenAI().chat.completions.create({});\n}\nimport OpenAI from "openai";\n`;
    expect(scanContent("app/api/stripe/webhook/route.ts", unverified)).toBeUndefined();
  });

  it("skips webhooks verified with svix", () => {
    const code = `import { Webhook } from "svix";\nconst wh = new Webhook(secret);\nwh.verify(body, headers);\n${OPENAI_SDK}`;
    expect(scanContent("app/api/clerk-webhook/route.ts", code)).toBeUndefined();
  });

  it("skips webhooks verified with an HMAC", () => {
    const code = `import { createHmac, timingSafeEqual } from "node:crypto";\nconst sig = createHmac("sha256", secret).update(body).digest("hex");\n${OPENAI_SDK}`;
    expect(scanContent("app/api/inbound/route.ts", code)).toBeUndefined();
  });

  it("skips test files", () => {
    for (const file of ["app/api/chat/route.test.ts", "src/routes/api/chat.spec.ts", "app/api/__tests__/chat.ts", "tests/api/chat.ts"]) {
      expect(scanContent(file, OPENAI_SDK), file).toBeUndefined();
    }
  });
});

describe("rateLimitCheck on a project", () => {
  let dir: string;

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function project(files: Record<string, string>): Promise<string> {
    dir = await mkdtemp(join(tmpdir(), "leakproof-ratelimit-"));
    for (const [path, content] of Object.entries(files)) {
      await mkdir(dirname(join(dir, path)), { recursive: true });
      await writeFile(join(dir, path), content);
    }
    return dir;
  }

  const UPSTASH = `import { Ratelimit } from "@upstash/ratelimit";\nexport default async function middleware(req) { await ratelimit.limit(ip); }\n`;

  it("finds endpoints, sorted by file, and ignores frontend and test files", async () => {
    const findings = await rateLimitCheck.run(
      await project({
        "app/api/b/route.ts": OPENAI_SDK,
        "app/api/a/route.ts": OPENAI_SDK,
        "src/components/Chat.tsx": OPENAI_SDK,
        "app/api/a/route.test.ts": OPENAI_SDK,
      }),
    );
    expect(findings.map((f) => f.file)).toEqual(["app/api/a/route.ts", "app/api/b/route.ts"]);
  });

  for (const entry of ["middleware.ts", "src/middleware.ts", "src/server.ts", "server.js"]) {
    it(`treats every endpoint as rate limited when ${entry} applies a limit`, async () => {
      const findings = await rateLimitCheck.run(await project({ [entry]: UPSTASH, "app/api/chat/route.ts": OPENAI_SDK }));
      expect(findings).toEqual([]);
    });
  }

  it("does not count a limit in an ordinary helper file as project-wide", async () => {
    const findings = await rateLimitCheck.run(await project({ "src/lib/limits.ts": UPSTASH, "app/api/chat/route.ts": OPENAI_SDK }));
    expect(findings).toHaveLength(1);
  });

  it("does not count a commented-out limit in middleware", async () => {
    const findings = await rateLimitCheck.run(
      await project({ "middleware.ts": `// import { Ratelimit } from "@upstash/ratelimit";\n`, "app/api/chat/route.ts": OPENAI_SDK }),
    );
    expect(findings).toHaveLength(1);
  });

  it("has the agreed name and passed label", () => {
    expect(rateLimitRule.id).toBe("rate-limit");
    expect(rateLimitRule.passedLabel).toBe("Paid and sensitive endpoints are rate limited");
  });
});

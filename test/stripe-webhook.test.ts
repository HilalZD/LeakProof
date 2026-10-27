import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { stripComments, stripeWebhookCheck } from "../src/checks/stripe-webhook.js";

// Each fixture marks the line where the request body is first read with
// "// <-- body", so the expected line number lives next to the code.
const lineOf = (code: string) => code.split("\n").findIndex((l) => l.includes("// <-- body")) + 1;

const UNVERIFIED = {
  "app/api/stripe/route.ts": `import { NextResponse } from "next/server";
import Stripe from "stripe";

export async function POST(req: Request) {
  const event = await req.json(); // <-- body
  if (event.type === "checkout.session.completed") {
    await markPro(event.data.object.client_reference_id);
  }
  return NextResponse.json({ received: true });
}
`,
  "pages/api/webhook.ts": `import type { NextApiRequest, NextApiResponse } from "next";
import Stripe from "stripe";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const event = req.body; // <-- body
  switch (event.type) {
    case "customer.subscription.deleted":
      await cancel(event.data.object.customer);
      break;
  }
  res.status(200).json({ received: true });
}
`,
  "server/index.js": `const express = require("express");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/webhook", express.json(), (req, res) => {
  const event = req.body; // <-- body
  if (event.type === 'invoice.paid') grantAccess(event.data.object.customer);
  res.json({ received: true });
});

app.listen(3000);
`,
  "supabase/functions/stripe-webhook/index.ts": `import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

serve(async (req) => {
  const body = await req.text(); // <-- body
  const event = JSON.parse(body);
  if (event.type === "payment_intent.succeeded") {
    await unlock(event.data.object.metadata.user_id);
  }
  return new Response("ok");
});
`,
  "src/routes/api/public/stripe-webhook.ts": `import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/public/stripe-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const event = await request.json(); // <-- body
        if (event.type === "checkout.session.completed") {
          const s = event.data.object;
          await setPro(s.client_reference_id);
        }
        return Response.json({ received: true });
      },
    },
  },
});
`,
};

const VERIFIED = {
  "constructEvent.ts": `import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === "checkout.session.completed") await markPro(event);
  return new Response("ok");
}
`,
  "constructEventAsync.ts": `import Stripe from "npm:stripe";
const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);

Deno.serve(async (req) => {
  const body = await req.text();
  const event = await stripe.webhooks.constructEventAsync(body, req.headers.get("Stripe-Signature")!, secret);
  if (event.type === "invoice.payment_failed") await notify(event);
  return new Response("ok");
});
`,
  "subtleHmac.ts": `export async function POST(request: Request) {
  const payload = await request.text();
  const header = request.headers.get("stripe-signature") ?? "";
  const key = await crypto.subtle.importKey("raw", enc(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, enc(payload));
  if (!header.includes(hex(mac))) return new Response("bad", { status: 400 });
  const event = JSON.parse(payload);
  if (event.type === "checkout.session.completed") await markPro(event);
  return new Response("ok");
}
`,
  "nodeHmac.js": `const { createHmac, timingSafeEqual } = require("node:crypto");

app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const header = req.headers["stripe-signature"];
  const expected = createHmac("sha256", secret).update(req.body).digest("hex");
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(sig(header)))) return res.sendStatus(400);
  const event = JSON.parse(req.body);
  if (event.type === "charge.refunded") revoke(event);
  res.sendStatus(200);
});
`,
  "verifyHelper.ts": `import { verifyWebhook } from "@/lib/stripe-verify";

export async function POST(req: Request) {
  const body = await req.text();
  const event = await verifyWebhook(body, req.headers.get("stripe-signature"));
  if (event.type === "checkout.session.completed") await markPro(event);
  return new Response("ok");
}
`,
  "urlInString.ts": `import Stripe from "stripe";
const stripe = new Stripe(key, { host: "https://api.stripe.com" }); // see https://docs.stripe.com/webhooks

export async function POST(req: Request) {
  const body = await req.text();
  const event = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, secret);
  if (event.type === "checkout.session.completed") await markPro(event);
  return new Response("ok");
}
`,
};

// Regression: a real-world Paystack webhook (scan-lab round 1) that verifies
// x-paystack-signature with HMAC-SHA512 and uses Paystack's "charge.success".
const PAYSTACK = `import { createFileRoute } from "@tanstack/react-router";
import { createHmac, timingSafeEqual } from "crypto";

export const Route = createFileRoute("/api/public/paystack-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env.PAYSTACK_SECRET_KEY;
        if (!secret) return new Response("Server not configured", { status: 500 });

        const raw = await request.text();
        const signature = request.headers.get("x-paystack-signature") ?? "";
        const expected = createHmac("sha512", secret).update(raw).digest("hex");
        const sig = Buffer.from(signature, "hex");
        const exp = Buffer.from(expected, "hex");
        if (sig.length !== exp.length || !timingSafeEqual(sig, exp)) {
          return new Response("Invalid signature", { status: 401 });
        }

        const evt = JSON.parse(raw);
        if (evt.event === "charge.success" && evt.data.status === "success") await creditWallet(evt);
        return new Response("ok");
      },
    },
  },
});
`;

const NOT_HANDLERS = {
  "src/lib/stripe-events.ts": `export const HANDLED_EVENTS = [
  "checkout.session.completed",
  "customer.subscription.updated",
  "invoice.paid",
] as const;
export type HandledEvent = (typeof HANDLED_EVENTS)[number];
`,
  "src/lib/payments.ts": `export async function createCheckoutSession(userId: string) {
  // Frontend: the browser creates a checkout session and reads the response.
  const res = await fetch("/api/checkout", { method: "POST", body: JSON.stringify({ userId }) });
  const session = await res.json();
  if (session.status === "checkout.session.expired") return undefined;
  return session.url as string;
}
`,
};

let dir: string;

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function scan(files: Record<string, string>) {
  dir = await mkdtemp(join(tmpdir(), "leakproof-webhook-"));
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), content);
  }
  return stripeWebhookCheck.run(dir);
}

describe("flags unverified webhook handlers", () => {
  for (const [path, code] of Object.entries(UNVERIFIED)) {
    it(path, async () => {
      const findings = await scan({ [path]: code });

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ checkId: "stripe-webhook", severity: "critical", file: path, line: lineOf(code) });
      expect(findings[0].message).toBe(
        "Stripe webhook doesn't verify signatures: anyone can send a fake 'payment completed' event and unlock paid features for free",
      );
      expect(findings[0].fix).toMatch(/^Verify the stripe-signature header with stripe\.webhooks\.constructEvent/);
    });
  }

  it("reports one finding per handler file, at the first body read", async () => {
    const code = `export async function POST(req: Request) {
  const raw = await req.text(); // <-- body
  if (raw.length === 0) return new Response("empty");
  const again = await req.json();
  if (again.type === "checkout.session.completed") await markPro(again);
  return new Response("ok");
}
`;
    const findings = await scan({ "a/stripe/route.ts": code, "b/route.ts": UNVERIFIED["app/api/stripe/route.ts"] });
    expect(findings.map((f) => [f.file, f.line])).toEqual([
      ["a/stripe/route.ts", 2],
      ["b/route.ts", 5],
    ]);
  });
});

describe("does not flag verified handlers", () => {
  for (const [path, code] of Object.entries(VERIFIED)) {
    it(path, async () => {
      expect(await scan({ [path]: code })).toEqual([]);
    });
  }
});

describe("commented-out verification does not count", () => {
  const handler = (verification: string) => `import Stripe from "stripe";

export async function POST(req: Request) {
  const body = await req.text(); // <-- body
${verification}
  const event = JSON.parse(body);
  if (event.type === "checkout.session.completed") await markPro(event);
  return new Response("ok");
}
`;

  it("// line comment", async () => {
    const code = handler(`  // const event = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, secret);`);
    expect(await scan({ "route.ts": code })).toMatchObject([{ line: lineOf(code) }]);
  });

  it("/* */ block comment", async () => {
    const code = handler(`  /*
  const sig = req.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, sig, secret);
  */`);
    expect(await scan({ "route.ts": code })).toMatchObject([{ line: lineOf(code) }]);
  });
});

describe("stripComments", () => {
  it("keeps strings that contain // or /* and keeps line numbers", () => {
    const code = [
      'const url = "https://api.stripe.com/v1";',
      "// const gone = constructEvent();",
      'const glob = "src/**/*.ts";',
      "/* block",
      "   constructEvent() */ const kept = 1;",
      "const text = `a // b /* c */`;",
    ].join("\n");

    expect(stripComments(code).split("\n")).toEqual([
      'const url = "https://api.stripe.com/v1";',
      "",
      'const glob = "src/**/*.ts";',
      "",
      " const kept = 1;",
      "const text = `a // b /* c */`;",
    ]);
  });

  it("an apostrophe in JSX text doesn't hide later comments", () => {
    const code = "<p>Don't pay twice</p>\n/* constructEvent() */";
    expect(stripComments(code)).not.toContain("constructEvent");
  });
});

describe("files that are not handlers", () => {
  it("event-name constants and frontend checkout code are not flagged", async () => {
    expect(await scan(NOT_HANDLERS)).toEqual([]);
  });

  it("a verified Paystack webhook using charge.success is not flagged", async () => {
    expect(await scan({ "src/routes/api/public/paystack-webhook.ts": PAYSTACK })).toEqual([]);
  });

  it("needs a Stripe marker in the file or its path", async () => {
    // Same unverified handler, with every mention of Stripe removed.
    const code = UNVERIFIED["app/api/stripe/route.ts"].replace('import Stripe from "stripe";\n', "");
    expect(await scan({ "app/api/payments/route.ts": code })).toEqual([]);
    expect(await scan({ "app/api/stripe/route.ts": code })).toHaveLength(1); // marker in the path
  });

  it("skips test files and __tests__ folders", async () => {
    const code = UNVERIFIED["app/api/stripe/route.ts"];
    const findings = await scan({
      "src/webhook.test.ts": code,
      "src/webhook.spec.js": code,
      "src/__tests__/webhook.ts": code,
      "src/real.ts": code, // control
    });
    expect(findings.map((f) => f.file)).toEqual(["src/real.ts"]);
  });

  it("only reads script files", async () => {
    const code = UNVERIFIED["app/api/stripe/route.ts"];
    const findings = await scan({ "fixture.json": JSON.stringify({ code }), "notes.md": code, "route.mjs": code });
    expect(findings.map((f) => f.file)).toEqual(["route.mjs"]);
  });
});

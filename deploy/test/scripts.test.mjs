import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = (f) => fileURLToPath(new URL(`../${f}`, import.meta.url));
const run = (script, args, env) => new Promise((resolve) => {
  const p = spawn(process.execPath, [here(script), ...args], { env: { PATH: process.env.PATH, ...env } });
  let out = ""; p.stdout.on("data", (d) => (out += d)); p.stderr.on("data", (d) => (out += d));
  p.on("close", (code) => resolve({ code, out }));
});
const serve = (handler) => new Promise((resolve) => {
  const calls = [];
  const srv = createServer((req, res) => {
    let body = ""; req.on("data", (c) => (body += c));
    req.on("end", () => { const call = { method: req.method, url: req.url, auth: req.headers.authorization, body }; calls.push(call); const r = handler(call) ?? { status: 404, json: {} }; res.writeHead(r.status, { "content-type": "application/json" }); res.end(JSON.stringify(r.json)); });
  }).listen(0, () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, calls, close: () => srv.close() }));
});

// ---------- check-email.mjs ----------
const KEY = "re_test_SECRET_do_not_print";
const FROM = "NEXORA CSPM <no-reply@mail.cspm.example.test>";

test("check-email: no key, no network, clear message", async () => {
  const r = await run("check-email.mjs", [], { RESEND_API_BASE: "http://127.0.0.1:9" });
  assert.equal(r.code, 1); assert.match(r.out, /RESEND_API_KEY is not set/); assert.match(r.out, /MAIL_FROM is not set/);
});

test("check-email: verified domain, sends a test email, never prints the key", async () => {
  const s = await serve((c) => c.url === "/domains" ? { status: 200, json: { data: [{ id: "d1", name: "mail.cspm.example.test", status: "verified" }] } } : c.url === "/emails" ? { status: 200, json: { id: "em_1" } } : undefined);
  const r = await run("check-email.mjs", ["me@example.com"], { RESEND_API_BASE: s.url, RESEND_API_KEY: KEY, MAIL_FROM: FROM });
  s.close();
  assert.equal(r.code, 0, r.out); assert.match(r.out, /domain mail\.cspm\.example\.test is verified/); assert.match(r.out, /test email accepted/);
  assert.equal(r.out.includes(KEY), false);
  const sent = s.calls.find((c) => c.url === "/emails");
  assert.equal(sent.auth, `Bearer ${KEY}`);
  assert.deepEqual([JSON.parse(sent.body).from, JSON.parse(sent.body).to], [FROM, ["me@example.com"]]);
});

test("check-email: unverified domain lists the pending DNS records and fails", async () => {
  const s = await serve((c) => c.url === "/domains" ? { status: 200, json: { data: [{ id: "d1", name: "mail.cspm.example.test", status: "pending" }] } } : c.url === "/domains/d1" ? { status: 200, json: { records: [{ record: "SPF", type: "TXT", name: "send", status: "verified" }, { record: "DKIM", type: "TXT", name: "resend._domainkey", status: "pending" }] } } : undefined);
  const r = await run("check-email.mjs", [], { RESEND_API_BASE: s.url, RESEND_API_KEY: KEY, MAIL_FROM: FROM }); s.close();
  assert.equal(r.code, 1); assert.match(r.out, /is "pending"/); assert.match(r.out, /PENDING DKIM TXT resend\._domainkey/);
});

test("check-email: domain missing from the account, and a send-only key", async () => {
  let s = await serve((c) => c.url === "/domains" ? { status: 200, json: { data: [] } } : undefined);
  let r = await run("check-email.mjs", [], { RESEND_API_BASE: s.url, RESEND_API_KEY: KEY, MAIL_FROM: FROM }); s.close();
  assert.equal(r.code, 1); assert.match(r.out, /not in your Resend account/);
  s = await serve((c) => c.url === "/domains" ? { status: 403, json: { message: "restricted_api_key" } } : c.url === "/emails" ? { status: 200, json: { id: "em_2" } } : undefined);
  r = await run("check-email.mjs", ["me@example.com"], { RESEND_API_BASE: s.url, RESEND_API_KEY: KEY, MAIL_FROM: FROM }); s.close();
  assert.equal(r.code, 0, r.out); assert.match(r.out, /send-only/); assert.match(r.out, /test email accepted/);
});

test("check-email: a refused send fails with Resend's reason", async () => {
  const s = await serve((c) => c.url === "/domains" ? { status: 403, json: {} } : c.url === "/emails" ? { status: 403, json: { message: "The mail.cspm.example.test domain is not verified." } } : undefined);
  const r = await run("check-email.mjs", ["me@example.com"], { RESEND_API_BASE: s.url, RESEND_API_KEY: KEY, MAIL_FROM: FROM }); s.close();
  assert.equal(r.code, 1); assert.match(r.out, /test email refused \(HTTP 403: The mail\.cspm\.example\.test domain is not verified\./);
});

// ---------- stripe-test-setup.mjs ----------
const SK = "sk_test_SECRET_do_not_print";
const HOOK = "https://api.cspm.example.test/api/billing/webhook";
function mockStripe() {
  const st = { products: [], prices: [], hooks: [], portals: [], n: 0 };
  const form = (b) => new URLSearchParams(b);
  const s = serve((c) => {
    const [path] = c.url.split("?");
    const f = c.body ? form(c.body) : new URLSearchParams();
    if (path === "/v1/account") return { status: 200, json: { id: "acct_test_1" } };
    if (path === "/v1/products" && c.method === "GET") return { status: 200, json: { data: st.products } };
    if (path === "/v1/products") { const p = { id: `prod_${++st.n}`, name: f.get("name"), metadata: { app: f.get("metadata[app]") } }; st.products.push(p); return { status: 200, json: p }; }
    if (path === "/v1/prices" && c.method === "GET") return { status: 200, json: { data: st.prices } };
    if (path === "/v1/prices") { const p = { id: `price_${++st.n}`, unit_amount: Number(f.get("unit_amount")), currency: f.get("currency"), recurring: { interval: f.get("recurring[interval]") } }; st.prices.push(p); return { status: 200, json: p }; }
    if (path === "/v1/webhook_endpoints" && c.method === "GET") return { status: 200, json: { data: st.hooks } };
    if (path === "/v1/webhook_endpoints") { const h = { id: `we_${++st.n}`, url: f.get("url"), enabled_events: [0, 1, 2, 3].map((i) => f.get(`enabled_events[${i}]`)), secret: "whsec_MOCKSECRET" }; st.hooks.push({ ...h, secret: undefined }); return { status: 200, json: h }; }
    if (path === "/v1/billing_portal/configurations" && c.method === "GET") return { status: 200, json: { data: st.portals } };
    if (path === "/v1/billing_portal/configurations") { st.portals.push({ id: `bpc_${++st.n}`, is_default: true, features: { subscription_cancel: { enabled: f.get("features[subscription_cancel][enabled]") === "true" } } }); return { status: 200, json: st.portals[st.portals.length - 1] }; }
  });
  return s.then((srv) => ({ ...srv, st }));
}

test("stripe setup: refuses live keys and insecure webhook URLs without any request", async () => {
  const s = await mockStripe();
  let r = await run("stripe-test-setup.mjs", ["--webhook-url", HOOK], { STRIPE_API_BASE: s.url, STRIPE_SECRET_KEY: "sk_live_abc" });
  assert.equal(r.code, 2); assert.match(r.out, /LIVE key/);
  r = await run("stripe-test-setup.mjs", ["--webhook-url", "http://insecure.example.test/hook"], { STRIPE_API_BASE: s.url, STRIPE_SECRET_KEY: SK });
  assert.equal(r.code, 2); assert.match(r.out, /https required/);
  r = await run("stripe-test-setup.mjs", [], { STRIPE_API_BASE: s.url, STRIPE_SECRET_KEY: SK });
  assert.equal(r.code, 2);
  assert.equal(s.calls.length, 0); s.close();
});

test("stripe setup: creates product, $19/month price, webhook with the four events and a cancel-enabled portal; prints the env vars", async () => {
  const s = await mockStripe();
  const r = await run("stripe-test-setup.mjs", ["--webhook-url", HOOK], { STRIPE_API_BASE: s.url, STRIPE_SECRET_KEY: SK });
  assert.equal(r.code, 0, r.out);
  assert.equal(r.out.includes(SK), false); // the key is never echoed
  assert.match(r.out, /STRIPE_PRICE_STARTER=price_\d+/); assert.match(r.out, /STRIPE_WEBHOOK_SECRET=whsec_MOCKSECRET/);
  assert.equal(s.calls.every((c) => c.auth === `Bearer ${SK}`), true);
  assert.deepEqual([s.st.products.length, s.st.prices.length, s.st.hooks.length, s.st.portals.length], [1, 1, 1, 1]);
  assert.deepEqual([s.st.prices[0].unit_amount, s.st.prices[0].currency, s.st.prices[0].recurring.interval], [1900, "usd", "month"]);
  assert.deepEqual(s.st.hooks[0].enabled_events.sort(), ["checkout.session.completed", "customer.subscription.deleted", "customer.subscription.updated", "invoice.payment_failed"]);
  assert.equal(s.st.portals[0].features.subscription_cancel.enabled, true);
  s.close();
});

test("stripe setup: running it again creates nothing and says where to find the secret", async () => {
  const s = await mockStripe();
  const env = { STRIPE_API_BASE: s.url, STRIPE_SECRET_KEY: SK };
  await run("stripe-test-setup.mjs", ["--webhook-url", HOOK], env);
  const r = await run("stripe-test-setup.mjs", ["--webhook-url", HOOK], env);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual([s.st.products.length, s.st.prices.length, s.st.hooks.length, s.st.portals.length], [1, 1, 1, 1]);
  assert.match(r.out, /product exists/); assert.match(r.out, /webhook endpoint exists/); assert.match(r.out, /signing secret is only shown when it is created/);
  s.close();
});

test("stripe setup: an API error stops with Stripe's message, exit 1", async () => {
  const s = await serve((c) => c.url.startsWith("/v1/account") ? { status: 200, json: { id: "acct_1" } } : { status: 401, json: { error: { message: "Invalid API Key provided" } } });
  const r = await run("stripe-test-setup.mjs", ["--webhook-url", HOOK], { STRIPE_API_BASE: s.url, STRIPE_SECRET_KEY: SK }); s.close();
  assert.equal(r.code, 1); assert.match(r.out, /HTTP 401\): Invalid API Key provided/); assert.equal(r.out.includes(SK), false);
});

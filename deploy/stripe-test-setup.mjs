#!/usr/bin/env node
// Creates the Stripe TEST-mode objects NEXORA CSPM needs, using your own test key from your own machine.
//   STRIPE_SECRET_KEY=sk_test_... node deploy/stripe-test-setup.mjs --webhook-url https://api.cspm.onenexora.com/api/billing/webhook
// Safe to run twice: it reuses what it created before. It REFUSES live keys on purpose; do live mode in the Stripe
// dashboard after the test-mode run passes (see replica/stripe-setup.md). Prints the env vars to set. Never prints your key.
const base = (process.env.STRIPE_API_BASE ?? "https://api.stripe.com").replace(/\/$/, "");
const key = process.env.STRIPE_SECRET_KEY ?? "";
const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const webhookUrl = flag("--webhook-url");
const APP = "nexora-cspm";
const EVENTS = ["checkout.session.completed", "customer.subscription.updated", "customer.subscription.deleted", "invoice.payment_failed"];

if (!/^(sk|rk)_test_/.test(key)) { console.error(key.startsWith("sk_live_") || key.startsWith("rk_live_") ? "Refusing: this is a LIVE key. Use a test key (sk_test_...)." : "Set STRIPE_SECRET_KEY to a test-mode key (sk_test_...)."); process.exit(2); }
if (!webhookUrl || !/^https:\/\//.test(webhookUrl)) { console.error("Pass --webhook-url https://<your api>/api/billing/webhook (https required; for local testing use `stripe listen` instead, see replica/stripe-setup.md)."); process.exit(2); }

// Stripe takes form-encoded bodies with bracketed keys
const enc = (o, p = "") => Object.entries(o).flatMap(([k, v]) => {
  const name = p ? `${p}[${k}]` : k;
  return Array.isArray(v) ? v.map((x, i) => [`${name}[${i}]`, x]) : v && typeof v === "object" ? enc(v, name) : [[name, String(v)]];
});
const call = async (method, path, body) => {
  const res = await fetch(base + path, { method, headers: { authorization: `Bearer ${key}`, ...(body ? { "content-type": "application/x-www-form-urlencoded" } : {}) }, body: body && new URLSearchParams(enc(body)) });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Stripe ${method} ${path} failed (HTTP ${res.status}): ${json?.error?.message ?? "no message"}`);
  return json;
};

try {
  const acct = await call("GET", "/v1/account").catch(() => null);
  console.log(`Stripe test mode${acct?.id ? `, account ${acct.id}` : ""}`);

  let product = (await call("GET", "/v1/products?active=true&limit=100")).data.find((p) => p.metadata?.app === APP);
  console.log(product ? `  product exists: ${product.id}` : "  creating product");
  product ??= await call("POST", "/v1/products", { name: "NEXORA CSPM Starter", metadata: { app: APP } });

  let price = (await call("GET", `/v1/prices?product=${product.id}&active=true&limit=100`)).data.find((p) => p.unit_amount === 1900 && p.currency === "usd" && p.recurring?.interval === "month");
  console.log(price ? `  price exists: ${price.id}` : "  creating price $19/month");
  price ??= await call("POST", "/v1/prices", { product: product.id, unit_amount: 1900, currency: "usd", recurring: { interval: "month" }, metadata: { app: APP } });

  const hooks = (await call("GET", "/v1/webhook_endpoints?limit=100")).data;
  const existing = hooks.find((h) => h.url === webhookUrl);
  let secret = null;
  let portalEnv = "";
  if (existing) {
    console.log(`  webhook endpoint exists: ${existing.id} (its signing secret is only shown when it is created; copy it from the dashboard, or delete this endpoint and run again)`);
    if (existing.status === "disabled") { console.log("  that endpoint is DISABLED, so Stripe would send nothing: enabling it"); await call("POST", `/v1/webhook_endpoints/${existing.id}`, { disabled: false }); }
  } else {
    console.log("  creating webhook endpoint");
    const h = await call("POST", "/v1/webhook_endpoints", { url: webhookUrl, enabled_events: EVENTS, description: "NEXORA CSPM" });
    secret = h.secret;
  }
  if (existing) { const missing = EVENTS.filter((e) => !existing.enabled_events.includes(e) && !existing.enabled_events.includes("*")); if (missing.length) console.log(`  WARNING: that endpoint is missing events: ${missing.join(", ")}. Add them in the dashboard.`); }

  // The API opens portal sessions with STRIPE_PORTAL_CONFIG when it is set, otherwise with Stripe's default configuration.
  const cfgs = (await call("GET", "/v1/billing_portal/configurations?active=true&limit=100")).data;
  let portal = cfgs.find((c) => c.is_default && c.features?.subscription_cancel?.enabled);
  if (portal) console.log("  customer portal: the default configuration already allows cancelling; no STRIPE_PORTAL_CONFIG needed");
  else {
    portal = cfgs.find((c) => c.metadata?.app === APP && c.features?.subscription_cancel?.enabled);
    console.log(portal ? `  customer portal configuration exists: ${portal.id}` : "  creating customer portal configuration (cancel at period end, payment method, invoices)");
    portal ??= await call("POST", "/v1/billing_portal/configurations", { metadata: { app: APP }, business_profile: { headline: "Manage your NEXORA CSPM subscription" }, features: { subscription_cancel: { enabled: true, mode: "at_period_end" }, payment_method_update: { enabled: true }, invoice_history: { enabled: true } } });
    portalEnv = `\nSTRIPE_PORTAL_CONFIG=${portal.id}`;
  }

  console.log("\nSet these on the API (test mode):\n");
  console.log(`STRIPE_SECRET_KEY=<your sk_test_ key>\nSTRIPE_PRICE_STARTER=${price.id}\nSTRIPE_WEBHOOK_SECRET=${secret ?? "<copy from the dashboard: Developers > Webhooks > your endpoint > Signing secret>"}${portalEnv}`);
  console.log("\nThen follow the test-card steps in replica/stripe-setup.md.");
} catch (e) { console.error(`\n${e.message}`); process.exit(1); }

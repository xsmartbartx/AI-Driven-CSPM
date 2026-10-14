import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import type { Server } from "node:http";

process.env["SSO_SECRET"] = "test-sso-secret";
process.env["STRIPE_WEBHOOK_SECRET"] = "whsec_test";
process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { signJwt } = await import("../src/lib/crypto.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");
const { verifyStripeSignature } = await import("../src/routes/team.ts");
const { SAMPLE_CONFIG } = await import("@workspace/cspm-engine");

let server: Server;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;
before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  server = createApp(db).listen(0);
  base = `http://127.0.0.1:${(server.address() as any).port}/api`;
});
after(async () => {
  server.close();
  await db.close();
});

class Client {
  cookie = "";
  constructor(public key = "") {}
  async call(method: string, path: string, body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1", ...extra };
    if (this.cookie) headers["cookie"] = this.cookie;
    if (this.key) headers["authorization"] = `Bearer ${this.key}`;
    const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
    const sc = res.headers.get("set-cookie");
    if (sc) this.cookie = sc.split(";")[0]!;
    const text = await res.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json, text, headers: res.headers };
  }
  get = (p: string) => this.call("GET", p);
  post = (p: string, b?: unknown) => this.call("POST", p, b ?? {});
  patch = (p: string, b?: unknown) => this.call("PATCH", p, b ?? {});
  del = (p: string) => this.call("DELETE", p);
}
let n = 0;
async function signup(name = "Org") {
  resetRateLimits();
  const c = new Client();
  const email = `u${++n}-${Date.now()}@example.com`;
  const r = await c.post("/auth/signup", { email, password: "correct horse battery", orgName: `${name} ${n}` });
  assert.equal(r.status, 201, r.text);
  return { c, email, me: r.json };
}
const clone = (o: unknown) => JSON.parse(JSON.stringify(o));

test("health + security headers", async () => {
  const r = await new Client().get("/healthz");
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  assert.equal(r.headers.get("x-powered-by"), null);
});

test("CORS: only listed origins are echoed", async () => {
  const ok = await fetch(base + "/healthz", { headers: { origin: "http://localhost:5174" } });
  assert.equal(ok.headers.get("access-control-allow-origin"), "http://localhost:5174");
  assert.equal(ok.headers.get("access-control-allow-credentials"), "true");
  const evil = await fetch(base + "/healthz", { headers: { origin: "https://evil.example" } });
  assert.equal(evil.headers.get("access-control-allow-origin"), null);
});

test("signup, me, duplicate, weak password, login, logout", async () => {
  const { c, email, me } = await signup();
  assert.equal(me.role, "owner");
  assert.equal(me.org.plan, "free");
  assert.equal((await c.get("/auth/me")).json.user.email, email);
  assert.equal((await new Client().post("/auth/signup", { email, password: "another long password" })).status, 409);
  assert.equal((await new Client().post("/auth/signup", { email: "x@example.com", password: "short" })).status, 400);
  const l = new Client();
  assert.equal((await l.post("/auth/login", { email, password: "wrong password!!" })).status, 401);
  assert.equal((await l.post("/auth/login", { email, password: "correct horse battery" })).status, 200);
  assert.equal((await l.get("/auth/me")).status, 200);
  await l.post("/auth/logout");
});

test("unauthenticated requests are rejected", async () => {
  for (const p of ["/overview", "/findings", "/assets", "/scans", "/team", "/usage"]) assert.equal((await new Client().get(p)).status, 401, p);
});

test("CSRF: cookie session without x-csrf header or with foreign origin is blocked", async () => {
  const { c } = await signup();
  assert.equal((await c.call("POST", "/scans", { config: SAMPLE_CONFIG }, { "x-csrf": "" })).status, 403);
  assert.equal((await c.call("POST", "/scans", { config: SAMPLE_CONFIG }, { origin: "https://evil.example" })).status, 403);
  assert.equal((await c.post("/scans", { config: SAMPLE_CONFIG })).status, 201);
});

test("demo scan: works, validates, rate limits", async () => {
  resetRateLimits();
  const c = new Client();
  const ok = await c.post("/demo/scan", { config: SAMPLE_CONFIG });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.findings.length, 7);
  assert.ok(ok.json.score < 100);
  assert.equal((await c.post("/demo/scan", { config: "nope" })).status, 400);
  assert.equal((await c.post("/demo/scan", { config: [] })).json.error.code, "invalid_config");
  assert.equal((await c.post("/demo/scan", { config: SAMPLE_CONFIG })).status, 200);
  assert.equal((await c.post("/demo/scan", { config: SAMPLE_CONFIG })).status, 200);
  assert.equal((await c.post("/demo/scan", { config: SAMPLE_CONFIG })).status, 429);
  resetRateLimits();
});

test("scan lifecycle: create, persist, rescan fixes, snapshot, overview", async () => {
  const { c } = await signup();
  const empty = (await c.get("/overview")).json;
  assert.equal(empty.hasData, false);
  assert.equal(empty.score, 100);

  const s1 = await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.equal(s1.status, 201);
  assert.equal(s1.json.findingCount, 7);
  assert.equal(s1.json.counts.new, 7);
  assert.equal(s1.json.counts.fixed, 0);

  const ov = (await c.get("/overview")).json;
  assert.equal(ov.hasData, true);
  assert.equal(ov.openTotal, 7);
  assert.equal(ov.assets.total, 7);
  assert.equal(ov.trend.length, 1);
  assert.equal(ov.score, s1.json.score);
  assert.ok(ov.topActions[0].riskScore >= ov.topActions[4].riskScore);
  assert.equal(ov.usage.scans.used, 1);

  const s2 = await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.equal(s2.json.counts.new, 0);
  assert.equal(s2.json.counts.persisting, 7);
  assert.equal((await c.get("/findings?status=all")).json.total, 7);

  const fixed = clone(SAMPLE_CONFIG);
  fixed.resources[0] = { ...fixed.resources[0], public_read: false, encrypted: true };
  const s3 = await c.post("/scans", { config: fixed });
  assert.equal(s3.json.counts.fixed, 2);
  assert.ok(s3.json.score > s1.json.score);
  assert.equal((await c.get("/findings")).json.total, 5);
  assert.equal((await c.get("/findings?status=fixed")).json.total, 2);

  const s4 = await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.equal(s4.json.counts.new, 2);
  assert.equal((await c.get("/overview")).json.trend.length, 1);
  assert.equal((await c.get("/scans")).json.items.length, 4);
  assert.equal((await c.get(`/scans/${s4.json.id}`)).json.findings.length, 7);
});

test("findings: filter, search (wildcards escaped), pagination, sort, detail", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.equal((await c.get("/findings?severity=critical")).json.items.every((f: any) => f.severity === "critical"), true);
  assert.equal((await c.get("/findings?q=orders-db")).json.total, 2);
  assert.equal((await c.get("/findings?q=%25")).json.total, 0);
  const p = (await c.get("/findings?pageSize=3&page=2")).json;
  assert.equal(p.items.length, 3);
  assert.equal(p.total, 7);
  const items = (await c.get("/findings?sort=risk")).json.items;
  for (let i = 1; i < items.length; i++) assert.ok(items[i - 1].riskScore >= items[i].riskScore);
  assert.equal((await c.get("/findings?severity=bogus")).status, 400);
  const d = (await c.get(`/findings/${items[0].id}`)).json;
  assert.ok(d.remediation && d.evidence && d.frameworks.length && d.ruleExplanation.includes("How to fix"));
  assert.equal((await c.get("/findings/not-a-uuid")).status, 400);
});

test("tenant isolation: org B never sees or touches org A data", async () => {
  const a = await signup("A");
  const b = await signup("B");
  const sa = await a.c.post("/scans", { config: SAMPLE_CONFIG });
  const fa = (await a.c.get("/findings")).json.items[0];
  assert.equal((await b.c.get("/findings")).json.total, 0);
  assert.equal((await b.c.get("/assets")).json.items.length, 0);
  assert.equal((await b.c.get("/scans")).json.items.length, 0);
  assert.equal((await b.c.get(`/findings/${fa.id}`)).status, 404);
  assert.equal((await b.c.patch(`/findings/${fa.id}`, { status: "false_positive", reason: "not mine to touch" })).status, 404);
  assert.equal((await b.c.post(`/findings/${fa.id}/explain`)).status, 404);
  assert.equal((await b.c.get(`/scans/${sa.json.id}`)).status, 404);
  assert.equal((await b.c.get("/overview")).json.hasData, false);
  assert.equal((await b.c.get("/compliance")).json.frameworks.every((f: any) => f.failed === 0), true);
  assert.equal((await b.c.get("/reports/summary.csv")).text.split("\r\n").length, 1);
  // same resource names in both orgs do not collide
  assert.equal((await b.c.post("/scans", { config: SAMPLE_CONFIG })).status, 201);
  assert.equal((await a.c.get("/findings?status=all")).json.total, 7);
  // an org id supplied by the client is ignored
  assert.equal((await b.c.post("/scans", { config: SAMPLE_CONFIG, orgId: a.me.org.id })).status, 201);
  assert.equal((await a.c.get("/scans")).json.items.length, 1);
});

test("quota: free plan stops at 10 scans with 402, upgrade lifts it", async () => {
  const { c, me } = await signup();
  for (let i = 0; i < 10; i++) assert.equal((await c.post("/scans", { config: SAMPLE_CONFIG })).status, 201);
  const r = await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.equal(r.status, 402);
  assert.equal(r.json.error.code, "quota_exceeded");
  assert.equal((await c.get("/usage")).json.scans.used, 10);
  await db.query("update organizations set plan = 'starter' where id = $1", [me.org.id]);
  assert.equal((await c.post("/scans", { config: SAMPLE_CONFIG })).status, 201);
});

test("concurrent scans cannot exceed the quota", async () => {
  const { c } = await signup();
  const rs = await Promise.all(Array.from({ length: 14 }, () => c.post("/scans", { config: SAMPLE_CONFIG })));
  assert.equal(rs.filter((r) => r.status === 201).length, 10);
  assert.equal(rs.filter((r) => r.status === 402).length, 4);
});

test("scan input limits", async () => {
  const { c } = await signup();
  assert.equal((await c.post("/scans", { config: { resources: [{ type: "s3_bucket" }] } })).status, 400);
  const big = Array.from({ length: 501 }, (_, i) => ({ type: "s3_bucket", name: `b${i}` }));
  assert.equal((await c.post("/scans", { config: big })).status, 400);
  assert.equal((await c.post("/scans", { config: "x".repeat(1_200_000) })).status, 413);
  const bad = await fetch(base + "/scans", { method: "POST", headers: { "content-type": "application/json" }, body: "{not json" });
  assert.equal(bad.status, 400);
});

test("finding status rules", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: SAMPLE_CONFIG });
  const f = (await c.get("/findings")).json.items[0];
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "accepted" })).status, 400);
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "accepted", reason: "vendor fix due" })).json.error.code, "expiry_required");
  const past = new Date(Date.now() - 86400_000).toISOString();
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "accepted", reason: "vendor fix due", acceptedUntil: past })).status, 400);
  const far = new Date(Date.now() + 800 * 86400_000).toISOString();
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "accepted", reason: "vendor fix due", acceptedUntil: far })).json.error.code, "expiry_too_long");
  const soon = new Date(Date.now() + 30 * 86400_000).toISOString();
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "accepted", reason: "vendor fix due", acceptedUntil: soon })).status, 200);
  assert.equal((await c.get("/overview")).json.openTotal, 6);
  assert.equal((await c.get(`/findings/${f.id}`)).json.statusReason, "vendor fix due");
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "open" })).status, 200);
  assert.equal((await c.get("/overview")).json.openTotal, 7);
});

test("AI explain: evidence-only fallback, cached, counted", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: SAMPLE_CONFIG });
  const f = (await c.get("/findings")).json.items[0];
  const a = await c.post(`/findings/${f.id}/explain`);
  assert.equal(a.status, 200);
  assert.equal(a.json.model, "rules");
  assert.ok(a.json.content.includes("Evidence in your config"));
  const b = await c.post(`/findings/${f.id}/explain`);
  assert.equal(b.json.content, a.json.content);
  assert.equal((await c.get("/usage")).json.ai.used, 1);
  assert.ok((await c.get(`/findings/${f.id}`)).json.brief);
});

test("RBAC: viewer is read-only, invites, role changes, last owner protected", async () => {
  const { c: owner, me } = await signup();
  await owner.post("/scans", { config: SAMPLE_CONFIG });
  const inv = await owner.post("/team/invite", { email: "viewer@example.com", role: "viewer" });
  assert.equal(inv.status, 201);
  const token = inv.json.link.split("/invite/")[1];
  const v = new Client();
  assert.equal((await v.post("/invites/accept", { token: "x".repeat(20), password: "viewer password 1" })).status, 400);
  const acc = await v.post("/invites/accept", { token, password: "viewer password 1", name: "Vi" });
  assert.equal(acc.status, 201);
  assert.equal(acc.json.role, "viewer");
  assert.equal(acc.json.org.id, me.org.id);
  assert.equal((await new Client().post("/invites/accept", { token, password: "viewer password 1" })).status, 400);
  assert.equal((await v.get("/findings")).status, 200);
  assert.equal((await v.post("/scans", { config: SAMPLE_CONFIG })).status, 403);
  assert.equal((await v.get("/team")).status, 403);
  assert.equal((await v.get("/audit")).status, 403);
  assert.equal((await v.post("/api-keys", { name: "k" })).status, 403);
  const f = (await v.get("/findings")).json.items[0];
  assert.equal((await v.patch(`/findings/${f.id}`, { status: "false_positive", reason: "nope nope" })).status, 403);

  const team = (await owner.get("/team")).json;
  const vm = team.members.find((m: any) => m.email === "viewer@example.com");
  const om = team.members.find((m: any) => m.role === "owner");
  assert.equal((await owner.patch(`/team/${vm.id}`, { role: "analyst" })).status, 200);
  assert.equal((await v.post("/scans", { config: SAMPLE_CONFIG })).status, 201);
  assert.equal((await owner.patch(`/team/${om.id}`, { role: "viewer" })).json.error.code, "last_owner");
  assert.equal((await owner.del(`/team/${om.id}`)).json.error.code, "last_owner");
  assert.equal((await owner.del(`/team/${vm.id}`)).status, 200);
  assert.equal((await v.get("/findings")).status, 401);
  const actions = (await owner.get("/audit")).json.items.map((e: any) => e.action);
  for (const a of ["auth.signup", "scan.run", "team.invite", "team.role_changed", "team.removed"]) assert.ok(actions.includes(a), a);
});

test("admin cannot grant or touch owner role", async () => {
  const { c: owner } = await signup();
  const inv = await owner.post("/team/invite", { email: "adm@example.com", role: "admin" });
  const adm = new Client();
  await adm.post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "admin password 12" });
  const team = (await owner.get("/team")).json;
  const am = team.members.find((m: any) => m.email === "adm@example.com");
  const om = team.members.find((m: any) => m.role === "owner");
  assert.equal((await adm.patch(`/team/${am.id}`, { role: "owner" })).status, 403);
  assert.equal((await adm.patch(`/team/${om.id}`, { role: "viewer" })).status, 403);
  assert.equal((await adm.del(`/team/${om.id}`)).status, 403);
  assert.equal((await new Client().post("/team/invite", { email: "z@example.com", role: "owner" })).status, 401);
  assert.equal((await owner.post("/team/invite", { email: "z@example.com", role: "owner" })).status, 400);
});

test("API keys: shown once, authenticate as analyst, revocable", async () => {
  const { c } = await signup();
  const k = await c.post("/api-keys", { name: "ci" });
  assert.equal(k.status, 201);
  assert.ok(k.json.key.startsWith("cspm_"));
  const listed = (await c.get("/api-keys")).json.items;
  assert.equal(listed.length, 1);
  assert.equal(JSON.stringify(listed).includes(k.json.key), false);
  const api = new Client(k.json.key);
  assert.equal((await api.post("/scans", { config: SAMPLE_CONFIG })).status, 201);
  assert.equal((await api.get("/findings")).json.total, 7);
  assert.equal((await api.get("/team")).status, 403);
  assert.equal((await new Client("cspm_wrong").get("/findings")).status, 401);
  await c.del(`/api-keys/${k.json.id}`);
  assert.equal((await api.get("/findings")).status, 401);
});

test("SSO handoff from Nexora", async () => {
  const base_ = { sub: "nx-user-1", email: "Person@Example.com", name: "Pat", org: "nx-org-1", orgName: "Acme" };
  const sso = (o: object = {}, secret = "test-sso-secret", ttl = 120) => signJwt({ ...base_, jti: `jti-${Math.random()}-${Date.now()}`, ...o }, secret, ttl);
  const tok = sso();
  const c = new Client();
  const r = await c.get(`/auth/sso?token=${tok}`);
  assert.equal(r.status, 302, r.text);
  const me = (await c.get("/auth/me")).json;
  assert.equal(me.user.email, "person@example.com");
  assert.equal(me.org.name, "Acme");
  assert.equal(me.role, "owner");
  assert.equal((await new Client().get(`/auth/sso?token=${tok}`)).status, 401); // a link works once
  const c2 = new Client();
  await c2.get(`/auth/sso?token=${sso({ sub: "nx-user-2", email: "two@example.com" })}`);
  const me2 = (await c2.get("/auth/me")).json;
  assert.equal(me2.role, "viewer");
  assert.equal(me2.org.id, me.org.id);
  const c3 = new Client();
  await c3.get(`/auth/sso?token=${sso({ sub: "nx-user-3", email: "three@example.com", role: "owner" })}`);
  assert.equal((await c3.get("/auth/me")).json.role, "viewer");
  for (const bad of [sso({}, "other-secret"), sso({}, "test-sso-secret", -10), sso({}, "test-sso-secret", 86400), signJwt(base_, "test-sso-secret", 120), "garbage"]) {
    assert.equal((await new Client().get(`/auth/sso?token=${bad}`)).status, 401);
  }
  const [h, , s] = tok.split(".");
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...base_, jti: "forged-jti-1", org: "other", exp: 9999999999 })).toString("base64url")}.${s}`;
  assert.equal((await new Client().get(`/auth/sso?token=${forged}`)).status, 401);
});

test("sign out everywhere ends every session", async () => {
  const { c, email } = await signup();
  const other = new Client();
  assert.equal((await other.post("/auth/login", { email, password: "correct horse battery" })).status, 200);
  assert.equal((await other.get("/auth/me")).status, 200);
  assert.equal((await c.post("/auth/logout-all")).status, 200);
  assert.equal((await other.get("/auth/me")).status, 401);
  assert.equal((await c.get("/auth/me")).status, 401);
  assert.equal((await new Client().post("/auth/login", { email, password: "correct horse battery" })).status, 200);
});

test("account deletion: needs password, deletes data, protects sole owner of a shared org", async () => {
  const { c, email } = await signup();
  await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.equal((await c.call("DELETE", "/auth/me", { password: "wrong password!!" })).status, 401);
  assert.equal((await c.call("DELETE", "/auth/me", { password: "correct horse battery" })).status, 200);
  assert.equal((await db.query("select 1 from users where email = $1", [email])).rows.length, 0);
  assert.equal((await new Client().post("/auth/login", { email, password: "correct horse battery" })).status, 401);

  const { c: owner, me } = await signup();
  const inv = await owner.post("/team/invite", { email: "member@example.com", role: "viewer" });
  await new Client().post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "member password 1" });
  const r = await owner.call("DELETE", "/auth/me", { password: "correct horse battery" });
  assert.equal(r.status, 409);
  assert.equal(r.json.error.code, "sole_owner");
  assert.equal((await db.query("select 1 from organizations where id = $1", [me.org.id])).rows.length, 1);
});

test("Stripe webhook: signature, idempotency, plan change", async () => {
  const { me } = await signup();
  const body = JSON.stringify({ id: `evt_${Date.now()}`, type: "checkout.session.completed", data: { object: { client_reference_id: me.org.id, customer: "cus_123" } } });
  const sign = (b: string, t = Math.floor(Date.now() / 1000), secret = "whsec_test") => `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${b}`).digest("hex")}`;
  const post = (b: string, sig: string) => fetch(base + "/billing/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": sig }, body: b });
  assert.equal((await post(body, sign(body, undefined, "wrong"))).status, 400);
  assert.equal((await post(body, sign(body, 1000))).status, 400);
  assert.equal((await post(body, "garbage")).status, 400);
  assert.equal((await post(body, sign(body))).status, 200);
  assert.equal((await db.query("select plan from organizations where id = $1", [me.org.id])).rows[0]!.plan, "starter");
  await db.query("update organizations set plan = 'free' where id = $1", [me.org.id]);
  const dup = await post(body, sign(body));
  assert.equal(((await dup.json()) as any).duplicate, true);
  assert.equal((await db.query("select plan from organizations where id = $1", [me.org.id])).rows[0]!.plan, "free");
  assert.equal(verifyStripeSignature(Buffer.from(body), sign(body), "whsec_test"), true);
});

test("Stripe: subscription lifecycle events; a failed handler is not marked seen", async () => {
  const { me } = await signup();
  const sign = (b: string) => { const t = Math.floor(Date.now() / 1000); return `t=${t},v1=${createHmac("sha256", "whsec_test").update(`${t}.${b}`).digest("hex")}`; };
  const send = (ev: object) => { const b = JSON.stringify(ev); return fetch(base + "/billing/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": sign(b) }, body: b }); };
  const plan = async () => (await db.query("select plan from organizations where id = $1", [me.org.id])).rows[0]!.plan;
  const id = () => `evt_${Math.random()}`;
  await send({ id: id(), type: "checkout.session.completed", data: { object: { client_reference_id: me.org.id, customer: "cus_life" } } });
  assert.equal(await plan(), "starter");
  await send({ id: id(), type: "customer.subscription.updated", data: { object: { customer: "cus_life", status: "past_due" } } });
  assert.equal(await plan(), "starter");
  await send({ id: id(), type: "invoice.payment_failed", data: { object: { customer: "cus_life", id: "in_1" } } });
  assert.ok((await db.query("select 1 from audit_events where org_id = $1 and action = 'billing.payment_failed'", [me.org.id])).rows.length);
  await send({ id: id(), type: "customer.subscription.updated", data: { object: { customer: "cus_life", status: "canceled" } } });
  assert.equal(await plan(), "free");
  const evId = id();
  const bad = await send({ id: evId, type: "checkout.session.completed", data: { object: { client_reference_id: "not-a-uuid", customer: "cus_x" } } });
  assert.equal(bad.status, 500);
  assert.equal((await db.query("select 1 from stripe_events where id = $1", [evId])).rows.length, 0);
});

test("billing portal needs a subscription and Stripe keys", async () => {
  const { c } = await signup();
  assert.equal((await c.post("/billing/portal")).status, 503);
});

test("billing checkout is a clear 503 until Stripe keys are set", async () => {
  const { c } = await signup();
  assert.equal((await c.post("/billing/checkout")).json.error.code, "billing_not_configured");
});

test("CSV export neutralises spreadsheet formulas", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: [{ type: "s3_bucket", name: '=HYPERLINK("http://evil")', public_read: true }] });
  const csv = (await c.get("/reports/summary.csv")).text;
  assert.ok(csv.includes(`"'=HYPERLINK`));
  assert.equal(csv.includes(`,"=HYPERLINK`), false);
});

test("compliance and assets endpoints reflect open findings", async () => {
  const { c } = await signup();
  assert.ok((await c.get("/compliance")).json.frameworks.every((f: any) => f.coverage === 100));
  await c.post("/scans", { config: SAMPLE_CONFIG });
  assert.ok((await c.get("/compliance")).json.frameworks.some((f: any) => f.coverage < 100));
  const assets = (await c.get("/assets")).json;
  assert.equal(assets.items.length, 7);
  assert.ok(assets.items[0].maxRisk >= assets.items[6].maxRisk);
  assert.equal((await c.get("/assets?type=database")).json.items.length, 1);
});

test("unknown API route returns JSON 404", async () => {
  const r = await new Client().get("/nope");
  assert.equal(r.status, 404);
  assert.equal(r.json.error.code, "not_found");
});

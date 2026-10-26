import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");
const { SAMPLE_PATHS_CONFIG } = await import("@workspace/cspm-engine");

let server: Server;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;
const sent: any[] = [];
const slack: { url: string; body: any }[] = [];
const slackStatus = { code: 200 };
const fakeFetch = (async (url: string, init: any) => { slack.push({ url, body: JSON.parse(init.body) }); return new Response("ok", { status: slackStatus.code }); }) as unknown as typeof fetch;
before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  server = createApp(db, { mailer: { enabled: true, send: async (m: any) => { sent.push(m); return true; } }, fetch: fakeFetch }).listen(0);
  base = `http://127.0.0.1:${(server.address() as any).port}/api`;
});
after(async () => { server.close(); await db.close(); });

class Client {
  cookie = "";
  async call(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1" };
    if (this.cookie) headers["cookie"] = this.cookie;
    const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = res.headers.get("set-cookie"); if (sc) this.cookie = sc.split(";")[0]!;
    const text = await res.text(); let json: any = null; try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json, text };
  }
  get = (p: string) => this.call("GET", p);
  post = (p: string, b?: unknown) => this.call("POST", p, b ?? {});
  put = (p: string, b?: unknown) => this.call("PUT", p, b ?? {});
}
let n = 0;
async function signup() {
  resetRateLimits();
  const c = new Client();
  const email = `notify${++n}-${Date.now()}@example.com`;
  const r = await c.post("/auth/signup", { email, password: "correct horse battery", orgName: `Notify ${n}` });
  assert.equal(r.status, 201, r.text);
  await new Promise((r) => setTimeout(r, 50)); // the confirmation email is sent in the background; drop it from the capture
  reset();
  return { c, me: r.json, email };
}
const HOOK = "https://hooks.slack.com/services/T000/B000/abcDEF123";
const waitFor = async (cond: () => boolean) => { for (let i = 0; i < 100 && !cond(); i++) await new Promise((r) => setTimeout(r, 20)); };
const reset = () => { sent.length = 0; slack.length = 0; slackStatus.code = 200; };

test("off by default: scans send nothing", async () => {
  reset();
  const { c } = await signup();
  assert.deepEqual((await c.get("/notifications")).json, { emailEnabled: false, minSeverity: "high", slackConfigured: false, lastSentAt: null, lastError: null });
  assert.equal((await c.post("/scans", { config: SAMPLE_PATHS_CONFIG() })).status, 201);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(sent.length, 0); assert.equal(slack.length, 0);
});

test("email and Slack on: the first scan alerts, the same scan again does not, and the response never carries the alert list", async () => {
  reset();
  const { c, email } = await signup();
  assert.equal((await c.put("/notifications", { emailEnabled: true, slackWebhook: HOOK })).status, 200);
  const g = (await c.get("/notifications")).json;
  assert.equal(g.emailEnabled, true); assert.equal(g.slackConfigured, true);
  assert.equal(JSON.stringify(g).includes("hooks.slack.com"), false); // the secret never comes back
  const first = await c.post("/scans", { config: SAMPLE_PATHS_CONFIG() });
  assert.equal(first.status, 201); assert.equal("alerts" in first.json, false);
  await waitFor(() => sent.length > 0 && slack.length > 0);
  assert.equal(sent.length, 1); assert.equal(sent[0].to, email);
  assert.match(sent[0].subject, /new findings? for Notify/);
  assert.match(sent[0].text, /CRITICAL: /); assert.doesNotMatch(sent[0].text, /MEDIUM|LOW/);
  assert.equal(slack.length, 1); assert.equal(slack[0]!.url, HOOK);
  assert.match(slack[0]!.body.text, /\*CRITICAL\*/); assert.match(slack[0]!.body.text, /Open findings/);
  assert.ok((await c.get("/notifications")).json.lastSentAt);
  reset();
  await c.post("/scans", { config: SAMPLE_PATHS_CONFIG() }); // nothing new
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(sent.length, 0); assert.equal(slack.length, 0);
});

test("critical-only threshold, and a Slack failure is recorded without failing the scan", async () => {
  reset();
  const { c } = await signup();
  await c.put("/notifications", { slackWebhook: HOOK, minSeverity: "critical" });
  slackStatus.code = 500;
  assert.equal((await c.post("/scans", { config: SAMPLE_PATHS_CONFIG() })).status, 201);
  await waitFor(() => slack.length > 0);
  assert.doesNotMatch(slack[0]!.body.text, /\*HIGH\*/);
  let last: any; for (let i = 0; i < 50; i++) { last = (await c.get("/notifications")).json; if (last.lastError) break; await new Promise((r) => setTimeout(r, 20)); }
  assert.match(last.lastError, /Slack answered 500/);
});

test("the webhook must be a Slack incoming webhook; removing it works; only admins can configure", async () => {
  reset();
  const { c } = await signup();
  for (const bad of ["http://hooks.slack.com/services/T/B/x", "https://evil.example.com/services/T/B/x", "https://hooks.slack.com/services/T/B", "https://hooks.slack.com.evil.io/services/T/B/x", "not a url"])
    assert.equal((await c.put("/notifications", { slackWebhook: bad })).status, 400, bad);
  assert.equal((await c.put("/notifications", { minSeverity: "low" })).status, 400);
  await c.put("/notifications", { slackWebhook: HOOK });
  assert.equal((await c.put("/notifications", { emailEnabled: true })).status, 200);
  assert.equal((await c.get("/notifications")).json.slackConfigured, true); // omitted field keeps its value
  await c.put("/notifications", { slackWebhook: null });
  assert.equal((await c.get("/notifications")).json.slackConfigured, false);
  const inv = await c.post("/team/invite", { email: `an-${Date.now()}@example.com`, role: "analyst" });
  const a = new Client();
  await a.post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "analyst password 12" });
  assert.equal((await a.get("/notifications")).status, 403); assert.equal((await a.put("/notifications", { emailEnabled: true })).status, 403);
  assert.equal((await new Client().get("/notifications")).status, 401);
});

test("settings are per organization, and the test button reports each channel", async () => {
  reset();
  const a = await signup(), b = await signup();
  await a.c.put("/notifications", { emailEnabled: true, slackWebhook: HOOK });
  assert.equal((await b.c.get("/notifications")).json.emailEnabled, false);
  await b.c.post("/scans", { config: SAMPLE_PATHS_CONFIG() });
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(sent.length, 0); assert.equal(slack.length, 0); // b never turned anything on
  const t = await a.c.post("/notifications/test");
  assert.equal(t.status, 200); assert.equal(t.json.email, `sent to ${a.email}`); assert.equal(t.json.slack, "sent");
  assert.equal((await b.c.post("/notifications/test")).json.email, "off");
});

test("a flood of low-severity findings does not push a critical one out of the alert", async () => {
  reset();
  const { c } = await signup();
  await c.put("/notifications", { slackWebhook: HOOK, minSeverity: "high" });
  const plain = Array.from({ length: 250 }, (_, i) => ({ type: "s3_bucket", name: `plain-${String(i).padStart(3, "0")}`, encryption: true, public_read: false, versioning: true }));
  const config = [...plain.map((b) => ({ ...b, encryption: false })), { type: "s3_bucket", name: "zz-public-last", encryption: true, public_read: true }];
  assert.equal((await c.post("/scans", { config })).status, 201);
  await waitFor(() => slack.length > 0);
  assert.match(slack[0]!.body.text, /zz-public-last/);
});

test("CORS: the dashboard's origin may use PUT (cross-origin preflight)", async () => {
  const res = await fetch(base + "/notifications", { method: "OPTIONS", headers: { origin: "http://localhost:5174", "access-control-request-method": "PUT", "access-control-request-headers": "content-type,x-csrf" } });
  assert.match(res.headers.get("access-control-allow-methods") ?? "", /\bPUT\b/);
});

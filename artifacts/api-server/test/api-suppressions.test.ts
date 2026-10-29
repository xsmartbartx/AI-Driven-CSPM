import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");

let server: Server;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;
before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  server = createApp(db, { mailer: { enabled: true, send: async () => true } }).listen(0);
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
  patch = (p: string, b?: unknown) => this.call("PATCH", p, b ?? {});
  del = (p: string) => this.call("DELETE", p);
}
let n = 0;
async function signup() {
  resetRateLimits();
  const c = new Client();
  const r = await c.post("/auth/signup", { email: `sup${++n}-${Date.now()}@example.com`, password: "correct horse battery", orgName: `Sup ${n}` });
  assert.equal(r.status, 201, r.text);
  return { c, me: r.json };
}
const bucket = (name: string, environment = "production") => ({ type: "s3_bucket", name, encrypted: false, public_read: false, versioning: true, environment });
const RULE = "s3-no-encryption";
const open = async (c: Client, q = "") => (await c.get(`/findings?status=open&q=${encodeURIComponent(q)}&pageSize=100`)).json;
const assetId = async (c: Client, name: string) => (await c.get(`/assets`)).json.items.find((a: any) => a.name === name).id;

test("suppressing a rule everywhere hides its findings, survives rescans (even for new assets), and removing it brings them back", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: [bucket("a"), bucket("b"), bucket("c", "staging")] });
  const ruleOpen = async () => (await open(c)).items.filter((f: any) => f.ruleId === RULE || /encryption at rest/.test(f.title) && f.assetType === "s3_bucket").length;
  assert.equal(await ruleOpen(), 3);
  const before = (await c.get("/overview")).json.openTotal;

  const s = await c.post("/suppressions", { ruleId: RULE, reason: "Encryption is handled by the account default" });
  assert.equal(s.status, 201); assert.equal(s.json.suppressed, 3);
  assert.equal(await ruleOpen(), 0);
  assert.equal((await c.get("/overview")).json.openTotal, before - 3); // out of the score and the counts
  const fp = (await c.get("/findings?status=false_positive&pageSize=100")).json.items;
  assert.equal(fp.length, 3);
  const detail = (await c.get(`/findings/${fp[0].id}`)).json;
  assert.match(detail.statusReason, /^Suppressed: Encryption is handled/); assert.equal(detail.suppressionId, s.json.id);

  // a rescan with a brand new bucket: it is born suppressed
  const r2 = await c.post("/scans", { config: [bucket("a"), bucket("b"), bucket("c", "staging"), bucket("d")] });
  assert.equal(r2.status, 201); assert.equal(r2.json.counts.suppressed, 1); assert.equal(r2.json.counts.new, 0);
  assert.equal(await ruleOpen(), 0);
  assert.equal((await c.get("/findings?status=false_positive&pageSize=100")).json.total, 4);

  const del = await c.del(`/suppressions/${s.json.id}`);
  assert.equal(del.status, 200); assert.equal(del.json.reopened, 4);
  assert.equal(await ruleOpen(), 4);
  assert.equal((await c.get("/suppressions")).json.items.length, 0);
});

test("scope: one asset only, or one environment only", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: [bucket("prod-1"), bucket("prod-2"), bucket("stg-1", "staging")] });
  const one = await c.post("/suppressions", { ruleId: RULE, assetId: await assetId(c, "prod-1"), reason: "Known, tracked elsewhere" });
  assert.equal(one.json.suppressed, 1);
  assert.deepEqual((await c.get("/findings?status=false_positive")).json.items.map((f: any) => f.assetName), ["prod-1"]);
  const env = await c.post("/suppressions", { ruleId: RULE, environment: "staging", reason: "Staging is disposable" });
  assert.equal(env.json.suppressed, 1);
  assert.deepEqual((await open(c)).items.filter((f: any) => f.assetType === "s3_bucket" && /encryption at rest/.test(f.title)).map((f: any) => f.assetName), ["prod-2"]);
  const list = (await c.get("/suppressions")).json.items;
  assert.equal(list.length, 2); assert.equal(list.find((x: any) => x.assetName === "prod-1").suppressed, 1);
  assert.equal(list[0].ruleTitle, "Storage bucket has no encryption at rest");
});

test("validation and permissions", async () => {
  const { c, me } = await signup(), other = await signup();
  await c.post("/scans", { config: [bucket("a")] });
  await other.c.post("/scans", { config: [bucket("theirs")] });
  const id = await assetId(c, "a");
  const post = (b: object) => c.post("/suppressions", { reason: "good enough reason", ...b });
  assert.equal((await post({ ruleId: "no-such-rule" })).status, 400);
  assert.equal((await post({ ruleId: RULE, assetId: id, environment: "staging" })).status, 400);       // two scopes
  assert.equal((await post({ ruleId: "sg-open-world", assetId: id })).status, 400);                     // rule does not apply to a bucket
  assert.equal((await post({ ruleId: RULE, reason: "no" })).status, 400);
  assert.equal((await post({ ruleId: RULE, expiresInDays: 0 })).status, 400);
  assert.equal((await post({ ruleId: RULE, assetId: await assetId(other.c, "theirs") })).status, 404); // another organization's asset
  assert.equal((await post({ ruleId: RULE, assetId: "not-a-uuid" })).status, 400);
  const ok = await post({ ruleId: RULE });
  assert.equal(ok.status, 201);
  // analysts can look but not change; viewers cannot look; nobody sees another organization's rules
  const mk = async (role: string) => { const inv = await c.post("/team/invite", { email: `${role}-${Date.now()}@example.com`, role }); const x = new Client(); await x.post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "member password 12" }); return x; };
  const analyst = await mk("analyst"), viewer = await mk("viewer");
  assert.equal((await analyst.get("/suppressions")).status, 200);
  assert.equal((await analyst.post("/suppressions", { ruleId: RULE, reason: "good enough reason" })).status, 403);
  assert.equal((await analyst.del(`/suppressions/${ok.json.id}`)).status, 403);
  assert.equal((await viewer.get("/suppressions")).status, 403);
  assert.equal((await other.c.get("/suppressions")).json.items.length, 0);
  assert.equal((await other.c.del(`/suppressions/${ok.json.id}`)).status, 404);
  assert.equal((await new Client().get("/suppressions")).status, 401);
  void me;
});

test("an expired suppression reopens its findings by itself", async () => {
  const { c, me } = await signup();
  await c.post("/scans", { config: [bucket("a")] });
  const s = await c.post("/suppressions", { ruleId: RULE, reason: "Until the migration finishes", expiresInDays: 30 });
  assert.equal(s.json.suppressed, 1);
  assert.equal((await c.get("/suppressions")).json.items[0].suppressed, 1);
  await db.query("update suppressions set expires_at = now() - interval '1 minute' where id = $1", [s.json.id]);
  assert.equal((await c.get("/suppressions")).json.items.length, 0);                // gone from the list
  assert.equal((await c.get("/findings?status=false_positive")).json.total, 0);      // and reopened
  assert.equal((await open(c, "encryption")).total, 1);
  void me;
});

test("reopening a suppressed finding by hand takes it out of the suppression and a rescan leaves it open", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: [bucket("a")] });
  const s = await c.post("/suppressions", { ruleId: RULE, reason: "Temporary exception" });
  const f = (await c.get("/findings?status=false_positive")).json.items[0];
  assert.equal((await c.patch(`/findings/${f.id}`, { status: "open" })).status, 200);
  assert.equal((await c.get(`/findings/${f.id}`)).json.suppressionId, null);
  await c.post("/scans", { config: [bucket("a")] });
  assert.equal((await c.get(`/findings/${f.id}`)).json.status, "open");
  assert.equal((await c.get("/suppressions")).json.items[0].suppressed, 0);
  void s;
});

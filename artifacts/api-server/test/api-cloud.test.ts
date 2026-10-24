import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");
const { AwsError } = await import("../src/services/aws/types.ts");
import type { AwsConnector, AwsTarget, CollectResult } from "../src/services/aws/types.ts";

let server: Server;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;

// A fake AWS: tests choose what it finds and what fails. The real one is covered by aws-collect / aws-sts tests.
const aws = {
  verifyError: null as InstanceType<typeof AwsError> | null,
  collectError: null as InstanceType<typeof AwsError> | null,
  result: { resources: [], notes: [], complete: true } as CollectResult,
  delayMs: 0,
  verified: [] as AwsTarget[],
  collected: [] as AwsTarget[],
  reset() { this.verifyError = null; this.collectError = null; this.result = { resources: [], notes: [], complete: true }; this.delayMs = 0; this.verified = []; this.collected = []; },
};
const fakeAws: AwsConnector = {
  enabled: true,
  principalAccountId: "123456789012",
  async verify(t) { aws.verified.push(t); if (aws.verifyError) throw aws.verifyError; },
  async collect(t) { aws.collected.push(t); if (aws.delayMs) await new Promise((r) => setTimeout(r, aws.delayMs)); if (aws.collectError) throw aws.collectError; return aws.result; },
};
const mailer = { enabled: true, send: async () => true };

before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  server = createApp(db, { mailer, aws: fakeAws }).listen(0);
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
  del = (p: string) => this.call("DELETE", p);
}
let n = 0;
async function signup(name = "Cloud") {
  resetRateLimits(); aws.reset();
  const c = new Client();
  const r = await c.post("/auth/signup", { email: `cloud${++n}-${Date.now()}@example.com`, password: "correct horse battery", orgName: `${name} ${n}` });
  assert.equal(r.status, 201, r.text);
  return { c, me: r.json };
}
async function member(owner: Client, role: "viewer" | "analyst" | "admin") {
  const email = `m${++n}-${Date.now()}@example.com`;
  const inv = await owner.post("/team/invite", { email, role });
  const c = new Client();
  assert.equal((await c.post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "member password 12" })).status, 201);
  return c;
}
const ACCT = "111122223333";
const connect = async (c: Client, over: object = {}) => c.post("/cloud-accounts", { accountId: ACCT, region: "eu-west-1", ...over });
const connected = async (c: Client, over: object = {}) => { const r = await connect(c, over); assert.equal(r.status, 201, r.text); assert.equal((await c.post(`/cloud-accounts/${r.json.id}/verify`)).status, 200); return r.json.id as string; };
const bucket = (name: string, pub = false) => ({ type: "s3_bucket", name, public_read: pub, encrypted: true });

test("connecting: returns the External ID, our account id and a read-only template; validates input", async () => {
  const { c } = await signup();
  const r = await connect(c);
  assert.equal(r.status, 201, r.text);
  assert.match(r.json.externalId, /^nx-[\w-]{20,}$/);
  assert.equal(r.json.principalAccountId, "123456789012");
  assert.equal(r.json.roleArn, `arn:aws:iam::${ACCT}:role/NexoraCSPMReadOnly`);
  assert.equal(r.json.status, "pending");
  assert.ok(r.json.template.includes(`sts:ExternalId: ${r.json.externalId}`) && r.json.template.includes("arn:aws:iam::123456789012:root"));
  assert.equal(/\*\s*$/m.test(r.json.template.split("Action:")[2] ?? ""), false);
  for (const bad of [{ accountId: "123" }, { accountId: "12345678901x" }, { region: "mars-north-1" }, { roleName: "bad name; drop" }, { roleName: "x".repeat(70) }])
    assert.equal((await connect(c, bad)).status, 400, JSON.stringify(bad));
  assert.equal((await connect(c)).json.error.code, "already_connected");
  assert.equal((await connect(c, { region: "us-east-1" })).status, 201); // same account, another region is allowed
  assert.equal((await connect(c, { accountId: "444455556666", roleName: "Custom-Role" })).json.roleArn, "arn:aws:iam::444455556666:role/Custom-Role");
  const list = (await c.get("/cloud-accounts")).json;
  assert.equal(list.items.length, 3); assert.equal(list.connector.enabled, true); assert.ok(list.items.every((x: any) => x.externalId));
});

test("each connection gets its own External ID; at most 10 connections per organization", async () => {
  const { c } = await signup();
  const a = (await connect(c)).json.externalId, b = (await connect(c, { region: "us-east-1" })).json.externalId;
  assert.notEqual(a, b);
  for (let i = 0; i < 8; i++) assert.equal((await connect(c, { accountId: String(200000000000 + i) })).status, 201);
  assert.equal((await connect(c, { accountId: "300000000000" })).json.error.code, "too_many_connections");
});

test("verify: success connects; the role is not trusted/wrong account -> clear error and status error; our own AWS problem does not blame the customer", async () => {
  const { c } = await signup();
  const id = (await connect(c)).json.id;
  assert.equal((await c.post(`/cloud-accounts/${id}/scan`)).json.error.code, "not_verified"); // cannot scan before verifying
  aws.verifyError = new AwsError("assume_denied", "NEXORA could not assume the role. Check the trust policy.");
  const bad = await c.post(`/cloud-accounts/${id}/verify`);
  assert.equal(bad.status, 422); assert.equal(bad.json.error.code, "assume_denied");
  let row = (await c.get("/cloud-accounts")).json.items[0];
  assert.equal(row.status, "error"); assert.match(row.lastError, /trust policy/);
  aws.verifyError = new AwsError("platform_credentials", "NEXORA's own AWS credentials are not working.");
  assert.equal((await c.post(`/cloud-accounts/${id}/verify`)).status, 503);
  row = (await c.get("/cloud-accounts")).json.items[0];
  assert.equal(row.status, "error"); // unchanged: a problem on our side says nothing about their role
  aws.verifyError = null;
  assert.equal((await c.post(`/cloud-accounts/${id}/verify`)).status, 200);
  row = (await c.get("/cloud-accounts")).json.items[0];
  assert.equal(row.status, "connected"); assert.equal(row.lastError, null); assert.ok(row.verifiedAt);
  assert.deepEqual([aws.verified.at(-1)!.accountId, aws.verified.at(-1)!.region, aws.verified.at(-1)!.roleArn], [ACCT, "eu-west-1", `arn:aws:iam::${ACCT}:role/NexoraCSPMReadOnly`]);
  assert.match(aws.verified.at(-1)!.externalId, /^nx-/);
});

test("scan: findings and assets belong to the account, the scan is marked as an account scan, notes are returned, quota is counted", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.result = { resources: [bucket("pub-bucket", true), bucket("ok-bucket"), { type: "database", name: `${ACCT}/eu-west-1/orders`, publicly_accessible: true, encrypted: false }], notes: ["IAM: only customer-managed policies are checked."], complete: true };
  const r = await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal(r.status, 201, r.text);
  assert.equal(r.json.findingCount, 3); assert.equal(r.json.complete, true); assert.deepEqual(r.json.notes, ["IAM: only customer-managed policies are checked."]);
  const scan = (await c.get(`/scans/${r.json.id}`)).json;
  assert.equal(scan.source, "account");
  const rows = (await db.query("select a.name, a.account_id, a.provider from assets a where a.org_id = (select id from organizations where name like 'Cloud%' order by created_at desc limit 1) and a.account_id is not null")).rows;
  assert.ok(rows.length >= 3); assert.ok(rows.every((x) => x.account_id === id && x.provider === "aws"));
  const row = (await c.get("/cloud-accounts")).json.items[0];
  assert.ok(row.lastSyncAt); assert.equal(row.lastScanId, r.json.id); assert.equal(row.lastError, null);
  assert.equal((await c.get("/usage")).json.scans.used, 1);
  assert.equal((await c.get("/findings")).json.total, 3);
});

test("a COMPLETE account scan fixes findings on resources that are gone; an INCOMPLETE one never does", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.result = { resources: [bucket("keep", true), bucket("vanishing", true)], notes: [], complete: true };
  await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal((await c.get("/findings")).json.total, 2);
  // "vanishing" is not returned, but the scan could not read everything: nothing may be concluded
  aws.result = { resources: [bucket("keep", true)], notes: ["S3: access denied on 1 bucket."], complete: false };
  const partial = await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal(partial.json.counts.fixed, 0); assert.equal((await c.get("/findings")).json.total, 2);
  // a complete scan that no longer sees it: its finding is fixed, the other stays
  aws.result = { resources: [bucket("keep", true)], notes: [], complete: true };
  const full = await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal(full.json.counts.fixed, 1);
  const open = (await c.get("/findings")).json.items;
  assert.deepEqual(open.map((f: any) => f.assetName), ["keep"]);
  assert.equal((await c.get("/findings?status=fixed")).json.items[0].assetName, "vanishing");
});

test("a complete scan of one account never touches another account's or a pasted scan's findings", async () => {
  const { c } = await signup();
  const a = await connected(c), b = await connected(c, { accountId: "444455556666" });
  aws.result = { resources: [bucket("in-a", true)], notes: [], complete: true }; await c.post(`/cloud-accounts/${a}/scan`);
  aws.result = { resources: [bucket("in-b", true)], notes: [], complete: true }; await c.post(`/cloud-accounts/${b}/scan`);
  await c.post("/scans", { config: [bucket("pasted", true)] });
  assert.equal((await c.get("/findings")).json.total, 3);
  aws.result = { resources: [bucket("other", false)], notes: [], complete: true };
  await c.post(`/cloud-accounts/${a}/scan`); // account A now shows something else entirely
  const names = (await c.get("/findings")).json.items.map((f: any) => f.assetName).sort();
  assert.deepEqual(names, ["in-b", "pasted"]); // only A's vanished resource was fixed
});

test("scan failures: AWS errors are mapped, nothing is stored, nothing is counted; an empty account is explained", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.collectError = new AwsError("throttled", "AWS is rate limiting the requests. Try again in a minute.");
  const r = await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal(r.status, 429); assert.equal(r.json.error.code, "throttled");
  assert.match((await c.get("/cloud-accounts")).json.items[0].lastError, /rate limiting/);
  assert.equal((await c.get("/scans")).json.items.length, 0); assert.equal((await c.get("/usage")).json.scans.used, 0);
  aws.collectError = null; aws.result = { resources: [], notes: ["S3: access denied on 2 buckets."], complete: false };
  const empty = await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal(empty.status, 422); assert.equal(empty.json.error.code, "no_resources"); assert.match(empty.json.error.message, /access denied on 2 buckets/);
  assert.equal((await c.get("/usage")).json.scans.used, 0);
});

test("a free plan with no scans left is refused BEFORE AWS is read", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.result = { resources: [bucket("b")], notes: [], complete: true };
  for (let i = 0; i < 10; i++) assert.equal((await c.post("/scans", { config: [bucket(`p${i}`)] })).status, 201);
  const before = aws.collected.length;
  const r = await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal(r.status, 402); assert.equal(r.json.error.code, "quota_exceeded");
  assert.equal(aws.collected.length, before); // no AWS calls were wasted
});

test("two simultaneous scans of the same account: the second is refused, the first completes", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.delayMs = 250; aws.result = { resources: [bucket("slow")], notes: [], complete: true };
  const [a, b] = await Promise.all([c.post(`/cloud-accounts/${id}/scan`), c.post(`/cloud-accounts/${id}/scan`)]); // truly simultaneous: exactly one may run
  assert.deepEqual([a.status, b.status], [201, 409]); assert.equal(b.json.error.code, "scan_running");
  assert.equal((await c.post(`/cloud-accounts/${id}/scan`)).status, 201); // and it can run again afterwards
});

test("permissions: viewers cannot connect/verify/scan/delete or see the External ID; analysts can scan but not manage; admins manage", async () => {
  const { c: owner } = await signup();
  const id = await connected(owner);
  aws.result = { resources: [bucket("b")], notes: [], complete: true };
  const viewer = await member(owner, "viewer"), analyst = await member(owner, "analyst"), admin = await member(owner, "admin");
  const vList = (await viewer.get("/cloud-accounts")).json;
  assert.equal(vList.items.length, 1); assert.equal(vList.items[0].externalId, undefined); assert.equal(vList.connector.principalAccountId, null);
  for (const [who, name] of [[viewer, "viewer"], [analyst, "analyst"]] as const) {
    assert.equal((await connect(who, { accountId: "555566667777" })).status, 403, `${name} connect`);
    assert.equal((await who.post(`/cloud-accounts/${id}/verify`)).status, 403, `${name} verify`);
    assert.equal((await who.del(`/cloud-accounts/${id}`)).status, 403, `${name} delete`);
    assert.equal((await who.get(`/cloud-accounts/${id}/setup`)).status, 403, `${name} setup`);
  }
  assert.equal((await viewer.post(`/cloud-accounts/${id}/scan`)).status, 403);
  assert.equal((await analyst.post(`/cloud-accounts/${id}/scan`)).status, 201);
  assert.equal((await analyst.get("/cloud-accounts")).json.items[0].externalId, undefined);
  assert.equal((await admin.get("/cloud-accounts")).json.items[0].externalId.startsWith("nx-"), true);
  assert.equal((await admin.get(`/cloud-accounts/${id}/setup`)).status, 200);
  assert.equal((await new Client().get("/cloud-accounts")).status, 401);
});

test("tenant isolation: another organization cannot see, verify, scan, read the setup of, or delete a connection", async () => {
  const a = await signup("Iso A"); const id = await connected(a.c);
  const b = await signup("Iso B");
  assert.equal((await b.c.get("/cloud-accounts")).json.items.length, 0);
  for (const [m, p] of [["post", `/cloud-accounts/${id}/verify`], ["post", `/cloud-accounts/${id}/scan`], ["get", `/cloud-accounts/${id}/setup`], ["del", `/cloud-accounts/${id}`]] as const)
    assert.equal((await (b.c as any)[m](p)).status, 404, p);
  assert.equal((await a.c.get("/cloud-accounts")).json.items.length, 1);
  assert.equal((await connect(b.c)).status, 201); // the same AWS account may be connected by another organization
});

test("deleting a connection keeps its assets and findings (history), unlinked from the account", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.result = { resources: [bucket("stay", true)], notes: [], complete: true };
  await c.post(`/cloud-accounts/${id}/scan`);
  assert.equal((await c.del(`/cloud-accounts/${id}`)).status, 200);
  assert.equal((await c.get("/cloud-accounts")).json.items.length, 0);
  assert.equal((await c.get("/findings")).json.total, 1);
  assert.equal((await c.get("/assets")).json.items.length, 1);
  assert.equal((await c.del(`/cloud-accounts/${id}`)).status, 404);
});

test("automatic scans: only admins set them, only for a verified connection, with a start time that respects the last scan", async () => {
  const { c: owner } = await signup();
  const pending = (await connect(owner)).json.id;
  assert.equal((await owner.call("PATCH", `/cloud-accounts/${pending}`, { schedule: "daily" })).json.error.code, "not_verified");
  const id = await connected(owner, { region: "us-east-1" });
  for (const bad of [{ schedule: "hourly" }, { schedule: "" }, {}, { schedule: 5 }]) assert.equal((await owner.call("PATCH", `/cloud-accounts/${id}`, bad)).status, 400, JSON.stringify(bad));
  const list = async () => (await owner.get("/cloud-accounts")).json.items.find((x: any) => x.id === id);
  assert.deepEqual([(await list()).schedule, (await list()).nextRunAt], ["off", null]);

  // never scanned: the first automatic scan starts within minutes
  assert.equal((await owner.call("PATCH", `/cloud-accounts/${id}`, { schedule: "daily" })).status, 200);
  let x = await list(); const soon = (Date.parse(x.nextRunAt) - Date.now()) / 60000;
  assert.equal(x.schedule, "daily"); assert.ok(soon > 0.5 && soon < 11, `first run in ${soon} min`);

  // after a scan, one full interval has to pass first
  aws.result = { resources: [bucket("b")], notes: [], complete: true };
  assert.equal((await owner.post(`/cloud-accounts/${id}/scan`)).status, 201);
  await owner.call("PATCH", `/cloud-accounts/${id}`, { schedule: "weekly" });
  x = await list(); const days = (Date.parse(x.nextRunAt) - Date.now()) / 86400000;
  assert.equal(x.schedule, "weekly"); assert.ok(days > 6.99 && days < 7.01, `next run in ${days} days`);
  await owner.call("PATCH", `/cloud-accounts/${id}`, { schedule: "daily" });
  const hours = (Date.parse((await list()).nextRunAt) - Date.now()) / 3600000;
  assert.ok(hours > 23.9 && hours < 24.1, `next run in ${hours} h`);

  // turning off clears it and any failure history
  await db.query("update cloud_accounts set failure_count = 3 where id = $1", [id]);
  await owner.call("PATCH", `/cloud-accounts/${id}`, { schedule: "off" });
  x = await list(); assert.deepEqual([x.schedule, x.nextRunAt, x.failureCount], ["off", null, 0]);
  assert.ok((await owner.get("/audit")).json.items.some((e: any) => e.action === "cloud.schedule" && /:off$/.test(e.target)));
});

test("automatic scans: viewers and analysts cannot change them, other organizations cannot see the connection", async () => {
  const { c: owner } = await signup();
  const id = await connected(owner);
  const viewer = await member(owner, "viewer"), analyst = await member(owner, "analyst");
  for (const who of [viewer, analyst]) assert.equal((await who.call("PATCH", `/cloud-accounts/${id}`, { schedule: "daily" })).status, 403);
  assert.equal((await new Client().call("PATCH", `/cloud-accounts/${id}`, { schedule: "daily" })).status, 401);
  const other = await signup("Sched Iso");
  assert.equal((await other.c.call("PATCH", `/cloud-accounts/${id}`, { schedule: "daily" })).status, 404);
  assert.equal((await viewer.get("/cloud-accounts")).json.items[0].schedule, "off"); // viewers can see it
});

test("a manual scan while a scheduled one holds the lease is refused, and the lease is released afterwards", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.result = { resources: [bucket("b")], notes: [], complete: true };
  await db.query("update cloud_accounts set scan_started_at = now() where id = $1", [id]);
  assert.equal((await c.post(`/cloud-accounts/${id}/scan`)).json.error.code, "scan_running");
  await db.query("update cloud_accounts set scan_started_at = now() - interval '30 minutes' where id = $1", [id]); // abandoned
  assert.equal((await c.post(`/cloud-accounts/${id}/scan`)).status, 201);
  assert.equal((await db.query("select scan_started_at from cloud_accounts where id = $1", [id])).rows[0]!.scan_started_at, null);
});

test("audit trail records connecting, verifying, scanning and disconnecting; no External ID or ARN in it", async () => {
  const { c } = await signup();
  const id = await connected(c);
  aws.result = { resources: [bucket("b")], notes: [], complete: true };
  await c.post(`/cloud-accounts/${id}/scan`); await c.del(`/cloud-accounts/${id}`);
  const log = (await c.get("/audit")).json.items;
  const actions = log.map((e: any) => e.action);
  for (const a of ["cloud.connect", "cloud.verify", "cloud.scan", "cloud.disconnect"]) assert.ok(actions.includes(a), a);
  assert.equal(JSON.stringify(log).includes("nx-"), false);
  assert.equal(JSON.stringify(log).includes("arn:aws"), false);
});

test("when AWS connections are not enabled on the server, the list says so and creating is a clear 503", async () => {
  const { disabledAwsConnector } = await import("../src/services/aws/connector.ts");
  const off = createApp(db, { mailer, aws: disabledAwsConnector }).listen(0);
  const url = `http://127.0.0.1:${(off.address() as any).port}/api`;
  const c = new Client();
  const email = `off-${Date.now()}@example.com`;
  const hdr = { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1" };
  resetRateLimits();
  const su = await fetch(`${url}/auth/signup`, { method: "POST", headers: hdr, body: JSON.stringify({ email, password: "correct horse battery" }) });
  const cookie = su.headers.get("set-cookie")!.split(";")[0]!;
  const list = await (await fetch(`${url}/cloud-accounts`, { headers: { ...hdr, cookie } })).json() as any;
  assert.equal(list.connector.enabled, false);
  const create = await fetch(`${url}/cloud-accounts`, { method: "POST", headers: { ...hdr, cookie }, body: JSON.stringify({ accountId: ACCT, region: "eu-west-1" }) });
  assert.equal(create.status, 503); assert.equal(((await create.json()) as any).error.code, "aws_not_configured");
  off.close(); void c;
});

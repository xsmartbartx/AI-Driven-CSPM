import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");
const { SAMPLE_PATHS_CONFIG } = await import("@workspace/cspm-engine");
import type { AwsConnector, CollectResult } from "../src/services/aws/types.ts";

let server: Server;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;
const aws = { result: { resources: [], notes: [], complete: true } as CollectResult };
const fakeAws: AwsConnector = { enabled: true, principalAccountId: "123456789012", async verify() {}, async collect() { return aws.result; } };
before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  server = createApp(db, { mailer: { enabled: true, send: async () => true }, aws: fakeAws }).listen(0);
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
}
let n = 0;
async function signup() {
  resetRateLimits();
  const c = new Client();
  const r = await c.post("/auth/signup", { email: `paths${++n}-${Date.now()}@example.com`, password: "correct horse battery", orgName: `Paths ${n}` });
  assert.equal(r.status, 201, r.text);
  return { c, me: r.json };
}

test("a pasted configuration with an exposed instance, an admin role and a trusting database yields the two headline paths, linked to findings", async () => {
  const { c } = await signup();
  assert.equal((await c.post("/scans", { config: SAMPLE_PATHS_CONFIG() })).status, 201);
  const r = await c.get("/attack-paths");
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.paths.map((p: any) => [p.target, p.score, p.severity]), [["AWS account (full control)", 100, "critical"], ["orders-db", 77, "critical"]]);
  const account = r.json.paths[0];
  assert.deepEqual(account.nodes.map((x: any) => x.kind), ["internet", "instance", "role", "account"]);
  assert.ok(account.edges.every((e: any) => e.label && e.fix.action));
  // existing findings on the assets involved are attached, so the page can link to them
  const titles = account.findings.map((f: any) => f.title);
  assert.ok(titles.includes("Admin or database port open to the internet")); assert.ok(titles.includes("Policy grants full administrator access"));
  assert.ok(account.findings.every((f: any) => /^[0-9a-f-]{36}$/.test(f.id)));
  assert.equal(r.json.chokePoints[0].asset, "web-sg"); assert.equal(r.json.chokePoints[0].paths, 2);
  assert.equal(r.json.coverage.hasRelationshipData, true); assert.ok(r.json.notes.some((x: string) => /Not modelled/.test(x)));
});

test("an organization without instances gets no paths and is told what is needed", async () => {
  const { c } = await signup();
  await c.post("/scans", { config: [{ type: "s3_bucket", name: "plain", public_read: true }] });
  const r = await c.get("/attack-paths");
  assert.deepEqual(r.json.paths, []); assert.equal(r.json.coverage.hasRelationshipData, false); assert.match(r.json.notes[0], /No instances were found/);
});

test("permissions and isolation: viewers can read, nobody else's data is visible, anonymous is refused", async () => {
  const a = await signup(), b = await signup();
  await a.c.post("/scans", { config: SAMPLE_PATHS_CONFIG() });
  assert.equal((await new Client().get("/attack-paths")).status, 401);
  assert.equal((await b.c.get("/attack-paths")).json.paths.length, 0);
  const inv = await a.c.post("/team/invite", { email: `v-${Date.now()}@example.com`, role: "viewer" });
  const v = new Client();
  await v.post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "viewer password 12" });
  assert.equal((await v.get("/attack-paths")).json.paths.length, 2);
});

test("pasted assets older than 30 days no longer count", async () => {
  const { c, me } = await signup();
  await c.post("/scans", { config: SAMPLE_PATHS_CONFIG() });
  assert.equal((await c.get("/attack-paths")).json.paths.length, 2);
  await db.query("update assets set last_seen_at = now() - interval '40 days' where org_id = $1 and name = 'web-1'", [me.org.id]);
  const r = await c.get("/attack-paths");
  assert.equal(r.json.paths.length, 0); assert.match(r.json.notes[0], /No instances were found/);
});

test("for a connected AWS account only what the LATEST scan saw counts: a vanished or unreadable instance drops out of the paths at once", async () => {
  const { c } = await signup();
  const web = { type: "security_group", name: "web (sg-1)", id: "sg-1", ingress: [{ cidr: "0.0.0.0/0", port: 22 }] };
  const instance = { type: "ec2_instance", name: "web-1 (i-1)", public_ip: true, security_groups: ["sg-1"], role: "app-role", environment: "production" };
  const role = { type: "iam_role", name: "app-role", managed_policies: ["arn:aws:iam::aws:policy/AdministratorAccess"] };
  const conn = (await c.post("/cloud-accounts", { accountId: "111122223333", region: "eu-west-1" })).json.id;
  assert.equal((await c.post(`/cloud-accounts/${conn}/verify`)).status, 200);

  aws.result = { resources: [web, instance, role] as any, notes: [], complete: true };
  assert.equal((await c.post(`/cloud-accounts/${conn}/scan`)).status, 201);
  let r = await c.get("/attack-paths");
  assert.deepEqual(r.json.paths.map((p: any) => p.target), ["AWS account (full control)"]);

  // the next scan could not read instances (older role template): the optional data is simply absent
  aws.result = { resources: [web] as any, notes: ["EC2 instances: access denied, so attack paths cannot be built."], complete: true };
  assert.equal((await c.post(`/cloud-accounts/${conn}/scan`)).status, 201);
  r = await c.get("/attack-paths");
  assert.deepEqual(r.json.paths, []); // no stale path from the previous scan

  aws.result = { resources: [web, instance, role] as any, notes: [], complete: true };
  await c.post(`/cloud-accounts/${conn}/scan`);
  assert.equal((await c.get("/attack-paths")).json.paths.length, 1); // and it comes back when the data does

  // disconnecting the account: its history stays, and it is treated like pasted data (seen recently)
  assert.equal((await c.call("DELETE", `/cloud-accounts/${conn}`)).status, 200);
  assert.equal((await c.get("/attack-paths")).status, 200);
});

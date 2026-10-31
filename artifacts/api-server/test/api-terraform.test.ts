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
  constructor(private key = "") {}
  async call(method: string, path: string, body?: unknown, raw?: string) {
    const headers: Record<string, string> = { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1" };
    if (this.cookie) headers["cookie"] = this.cookie;
    if (this.key) headers["authorization"] = `Bearer ${this.key}`;
    const res = await fetch(base + path, { method, headers, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)) });
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
  const r = await c.post("/auth/signup", { email: `tf${++n}-${Date.now()}@example.com`, password: "correct horse battery", orgName: `TF ${n}` });
  assert.equal(r.status, 201, r.text);
  return c;
}
const rc = (address: string, type: string, after: object) => ({ address, mode: "managed", type, change: { actions: ["create"], after, after_unknown: {} } });
const PLAN = { resource_changes: [
  rc("aws_s3_bucket.public", "aws_s3_bucket", { acl: "public-read", tags: { Environment: "production" } }),
  rc("aws_db_instance.db", "aws_db_instance", { publicly_accessible: true, storage_encrypted: true, tags: { Environment: "staging" } }),
  rc("aws_iam_policy.wide", "aws_iam_policy", { policy: JSON.stringify({ Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "*" }] }) }),
] };

test("a plan is checked without storing anything or using a scan, and fail follows the threshold", async () => {
  const c = await signup();
  const r = await c.post("/terraform/check", { plan: PLAN });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.findings.map((f: any) => `${f.ruleId} ${f.address}`).sort(), ["db-public aws_db_instance.db", "iam-wildcard-resource aws_iam_policy.wide", "s3-public-read aws_s3_bucket.public"]);
  assert.equal(r.json.fail, true); assert.equal(r.json.failOn, "high");
  assert.ok(r.json.findings.every((f: any) => f.remediation && f.address));
  assert.equal((await c.post("/terraform/check", { plan: PLAN, failOn: "critical" })).json.fail, r.json.counts.critical > 0);
  // a plan with only a medium finding passes at the default threshold and fails at "medium"
  const mild = { resource_changes: [PLAN.resource_changes[2]] };
  assert.equal((await c.post("/terraform/check", { plan: mild })).json.fail, false);
  assert.equal((await c.post("/terraform/check", { plan: mild, failOn: "medium" })).json.fail, true);
  // nothing was stored and no scan was used
  assert.equal((await c.get("/scans")).json.items.length, 0); assert.equal((await c.get("/findings?status=all")).json.total, 0);
  assert.equal((await c.get("/overview")).json.hasData, false);
});

test("read-only keys can check plans; anonymous callers cannot; a non-plan is a clear 400", async () => {
  const c = await signup();
  const key = (await c.post("/api-keys", { name: "ci", access: "read" })).json.key;
  const ci = new Client(key);
  assert.equal((await ci.post("/terraform/check", { plan: PLAN })).status, 200);
  assert.equal((await new Client().post("/terraform/check", { plan: PLAN })).status, 401);
  const bad = await c.post("/terraform/check", { plan: { hello: 1 } });
  assert.equal(bad.status, 400); assert.equal(bad.json.error.code, "invalid_plan"); assert.match(bad.json.error.message, /terraform show -json/);
  assert.equal((await c.post("/terraform/check", { plan: PLAN, failOn: "extreme" })).status, 400);
});

test("rule suppressions for everywhere or an environment apply; asset-level ones do not; large plans are accepted but limited", async () => {
  const c = await signup();
  await c.post("/scans", { config: [{ type: "s3_bucket", name: "x", public_read: true }] });
  await c.post("/suppressions", { ruleId: "db-public", environment: "staging", reason: "Staging databases are disposable" });
  const r = await c.post("/terraform/check", { plan: PLAN });
  assert.equal(r.json.suppressed, 1);
  assert.ok(!r.json.findings.some((f: any) => f.ruleId === "db-public"));
  // a 3 MB plan (over the general 1 MB limit) is fine; an 9 MB one is refused
  const pad = { resource_changes: [...PLAN.resource_changes, rc("aws_lambda_function.pad", "aws_lambda_function", { blob: "x".repeat(3_000_000) })] };
  assert.equal((await c.post("/terraform/check", { plan: pad })).status, 200);
  const huge = { resource_changes: [rc("aws_lambda_function.pad", "aws_lambda_function", { blob: "x".repeat(9_000_000) })] };
  assert.equal((await c.post("/terraform/check", { plan: huge })).status, 413);
  // other routes still keep the 1 MB limit
  assert.equal((await c.post("/scans", { config: [{ type: "s3_bucket", name: "x", pad: "y".repeat(1_100_000) }] })).status, 413);
});

test("the CI command-line checker: exit 1 on findings, 0 when it passes, 2 when it cannot run", async () => {
  const { execFile } = await import("node:child_process");
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const c = await signup();
  const key = (await c.post("/api-keys", { name: "ci", access: "read" })).json.key;
  const dir = mkdtempSync(join(tmpdir(), "tfplan-"));
  const full = { ...PLAN, resource_changes: [...PLAN.resource_changes, rc("aws_lambda_function.fn", "aws_lambda_function", {})], configuration: { root_module: { resources: [] } } };
  writeFileSync(join(dir, "plan.json"), JSON.stringify(full));
  writeFileSync(join(dir, "clean.json"), JSON.stringify({ resource_changes: [rc("aws_db_instance.ok", "aws_db_instance", { publicly_accessible: false, storage_encrypted: true })] }));
  const api = `http://127.0.0.1:${(server.address() as any).port}`;
  // asynchronous on purpose: this process also hosts the server the checker talks to
  const run = (file: string, extra: string[] = [], env: object = { CSPM_API_KEY: key }) => new Promise<{ status: number; stdout: string; stderr: string }>((resolve) =>
    execFile(process.execPath, [join(import.meta.dirname, "../../../deploy/tf-check.mjs"), join(dir, file), "--api", api, ...extra], { env: { ...process.env, ...env }, encoding: "utf8" },
      (err, stdout, stderr) => resolve({ status: err ? Number((err as any).code ?? 1) : 0, stdout, stderr })));
  const bad = await run("plan.json");
  assert.equal(bad.status, 1, bad.stdout + bad.stderr);
  assert.match(bad.stdout, /aws_s3_bucket\.public/); assert.match(bad.stdout, /fix: /); assert.match(bad.stdout, /not checked \(no rules for these\): aws_lambda_function x1/); assert.match(bad.stdout, /FAILED/);
  const ok = await run("clean.json");
  assert.equal(ok.status, 0, ok.stdout + ok.stderr); assert.match(ok.stdout, /Passed/);
  assert.equal((await run("clean.json", ["--fail-on", "low"])).status, 0);          // nothing to find, whatever the threshold
  assert.equal((await run("plan.json", [], { CSPM_API_KEY: "cspm_wrong" })).status, 2);       // refused: the check could not run
  assert.equal((await run("plan.json", [], { CSPM_API_KEY: "" })).status, 2);                 // no key
  assert.equal((await run("missing.json")).status, 2);
});

test("the CI checker sends no secrets, refuses redirects and odd answers, and rejects a flag without a value", async () => {
  const { execFile } = await import("node:child_process");
  const { createServer } = await import("node:http");
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "tfplan-"));
  writeFileSync(join(dir, "plan.json"), JSON.stringify({ resource_changes: [
    { address: "aws_db_instance.db", mode: "managed", type: "aws_db_instance", change: { actions: ["create"], after: { publicly_accessible: true, storage_encrypted: true, password: "hunter2-secret", username: "admin", kms_key_id: "arn:aws:kms:eu-west-1:111122223333:key/abc", tags: { Environment: "production", Owner: "alice@example.com", Token: "t0ken" } }, after_unknown: {}, after_sensitive: { password: true } } },
    { address: "aws_lambda_function.fn", mode: "managed", type: "aws_lambda_function", change: { actions: ["create"], after: { environment: { variables: { API_KEY: "leaky" } } }, after_unknown: {} } },
  ], configuration: { root_module: { resources: [] } } }));
  const seen: string[] = []; let hits = 0; let mode: "ok" | "redirect" | "html" = "ok";
  const target = createServer((rq, rs) => { hits++; let b = ""; rq.on("data", (d) => (b += d)); rq.on("end", () => { seen.push(b); rs.end("{}"); }); }).listen(0);
  const fake = createServer((rq, rs) => {
    let b = ""; rq.on("data", (d) => (b += d)); rq.on("end", () => {
      if (mode === "redirect") { rs.writeHead(307, { location: `http://127.0.0.1:${(target.address() as any).port}/steal` }); return void rs.end(); }
      if (mode === "html") { rs.writeHead(200, { "content-type": "text/html" }); return void rs.end("<html>Welcome to the captive portal</html>"); }
      seen.push(b); rs.writeHead(200, { "content-type": "application/json" }); rs.end(JSON.stringify({ resourceCount: 1, counts: { critical: 0, high: 1, medium: 0, low: 0 }, suppressed: 0, fail: true, failOn: "high", findings: [{ severity: "high", address: "aws_db_instance.db", title: "t", remediation: "r" }], skipped: [], notes: [] }));
    });
  }).listen(0);
  const api = `http://127.0.0.1:${(fake.address() as any).port}`;
  const raw = (args: string[]) => new Promise<{ status: number; stdout: string; stderr: string }>((resolve) =>
    execFile(process.execPath, [join(import.meta.dirname, "../../../deploy/tf-check.mjs"), ...args], { env: { ...process.env, CSPM_API_KEY: "cspm_test" }, encoding: "utf8" },
      (err, stdout, stderr) => resolve({ status: err ? Number((err as any).code ?? 1) : 0, stdout, stderr })));
  const run = (extra: string[] = [], file = "plan.json") => new Promise<{ status: number; stdout: string; stderr: string }>((resolve) =>
    execFile(process.execPath, [join(import.meta.dirname, "../../../deploy/tf-check.mjs"), join(dir, file), "--api", api, ...extra], { env: { ...process.env, CSPM_API_KEY: "cspm_test" }, encoding: "utf8" },
      (err, stdout, stderr) => resolve({ status: err ? Number((err as any).code ?? 1) : 0, stdout, stderr })));
  try {
    const ok = await run();
    assert.equal(ok.status, 1, ok.stdout + ok.stderr);
    const sent = seen[0]!;
    for (const secret of ["hunter2-secret", "admin", "alice@example.com", "t0ken", "leaky", "arn:aws:kms", "aws_lambda_function"]) assert.equal(sent.includes(secret), false, `${secret} must not be sent`);
    assert.ok(sent.includes('"publicly_accessible":true') && sent.includes('"Environment":"production"')); // what the rules read is sent
    mode = "redirect";
    const red = await run(); assert.equal(red.status, 2); assert.equal(hits, 0, "the plan must not follow a redirect");
    mode = "html";
    const html = await run(); assert.equal(html.status, 2); assert.match(html.stderr, /unexpected response/);
    mode = "ok";
    for (const bad of [["--fail-on"], ["--fail-on", "--api", api], ["--fail-on", "extreme"]]) { const r = await run(bad); assert.equal(r.status, 2, JSON.stringify(bad)); }
    const noApi = await raw([join(dir, "plan.json"), "--api"]); assert.equal(noApi.status, 2); assert.match(noApi.stderr, /--api needs a value/); // not the default endpoint
  } finally { target.close(); fake.close(); }
});

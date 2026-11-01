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

const wl = (name: string, spec: object, ns = "shop") => ({ kind: "Deployment", metadata: { name, namespace: ns }, spec: { template: { spec } } });
const safe = { name: "app", image: "app:1.2.3", securityContext: { allowPrivilegeEscalation: false, runAsNonRoot: true }, resources: { limits: { memory: "256Mi" } } };
const MANIFESTS = [
  wl("web", { containers: [{ ...safe, securityContext: { privileged: true, allowPrivilegeEscalation: false, runAsNonRoot: true } }] }),
  wl("worker", { containers: [{ ...safe, image: "worker" }] }, "staging"),
  { kind: "Service", metadata: { name: "svc" } },
];

test("manifests are checked without storing anything, with fixes as YAML, and fail follows the threshold", async () => {
  const c = await signup();
  const r = await c.post("/kubernetes/check", { manifests: MANIFESTS });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.findings.map((f: any) => `${f.ruleId} ${f.address}`).sort(), ["k8s-latest-image Deployment/staging/worker", "k8s-privileged Deployment/shop/web"]);
  assert.equal(r.json.fail, true); assert.deepEqual(r.json.skipped, [{ type: "Service", count: 1 }]);
  assert.ok(r.json.findings.every((f: any) => f.fix.yaml && !f.fix.terraform));
  const mild = await c.post("/kubernetes/check", { manifests: [MANIFESTS[1]] });
  assert.equal(mild.json.fail, false); assert.equal((await c.post("/kubernetes/check", { manifests: [MANIFESTS[1]], failOn: "low" })).json.fail, true);
  assert.equal((await c.get("/scans")).json.items.length, 0); assert.equal((await c.get("/overview")).json.hasData, false);
});

test("read-only keys can check manifests; anonymous cannot; not-manifests is a clear 400; suppressions apply", async () => {
  const c = await signup();
  const key = (await c.post("/api-keys", { name: "ci", access: "read" })).json.key;
  assert.equal((await new Client(key).post("/kubernetes/check", { manifests: MANIFESTS })).status, 200);
  assert.equal((await new Client().post("/kubernetes/check", { manifests: MANIFESTS })).status, 401);
  const bad = await c.post("/kubernetes/check", { manifests: { hello: 1 } });
  assert.equal(bad.status, 400); assert.equal(bad.json.error.code, "invalid_manifests");
  await c.post("/scans", { config: [{ type: "s3_bucket", name: "x", public_read: true }] });
  await c.post("/suppressions", { ruleId: "k8s-latest-image", environment: "staging", reason: "Staging runs whatever is newest" });
  const r = await c.post("/kubernetes/check", { manifests: MANIFESTS });
  assert.equal(r.json.suppressed, 1); assert.deepEqual(r.json.findings.map((f: any) => f.ruleId), ["k8s-privileged"]);
});

test("pasted resources of type k8s_workload are scanned too, and the rules show up in compliance", async () => {
  const c = await signup();
  await c.post("/scans", { config: [{ type: "s3_bucket", name: "plain", public_read: false }] });
  const before = (await c.get("/compliance")).json.frameworks;
  assert.ok(!before.some((f: any) => f.framework === "CIS-K8s"), "no Kubernetes framework for an organization that never scanned Kubernetes");
  assert.equal((await c.get("/overview")).json.compliance.frameworks.some((f: any) => f.framework === "CIS-K8s"), false);
  const s = await c.post("/scans", { config: [{ type: "k8s_workload", name: "Deployment/shop/web", hostNetwork: true, containers: [] }] });
  assert.equal(s.status, 201, s.text); assert.equal(s.json.findingCount, 1);
  assert.ok((await c.get("/compliance")).json.frameworks.some((f: any) => f.framework === "CIS-K8s"));
});

test("the Kubernetes command-line checker sends no secrets and exits 0, 1 or 2", async () => {
  const { execFile } = await import("node:child_process");
  const { createServer } = await import("node:http");
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "k8s-"));
  const secretive = [{ kind: "Deployment", metadata: { name: "api", namespace: "prod", labels: { environment: "production", owner: "alice@example.com" }, annotations: { note: "s3cret-annotation" } },
    spec: { template: { spec: { containers: [{ name: "api", image: "api:latest", command: ["run", "--token=tok-123"], env: [{ name: "DB_PASSWORD", value: "hunter2-secret" }, { name: "KEY", valueFrom: { secretKeyRef: { name: "my-secret-name", key: "k" } } }], securityContext: { privileged: true }, resources: { limits: { memory: "1Gi" } } }], volumes: [{ name: "cfg", configMap: { name: "private-config" } }] } } } },
    { kind: "Secret", metadata: { name: "creds" }, data: { password: "c2VjcmV0" } }];
  writeFileSync(join(dir, "m.json"), JSON.stringify(secretive));
  writeFileSync(join(dir, "clean.json"), JSON.stringify([wl("ok", { containers: [safe] })]));
  const seen: string[] = [];
  const fake = createServer((rq, rs) => { let b = ""; rq.on("data", (d) => (b += d)); rq.on("end", () => { seen.push(b); rs.writeHead(200, { "content-type": "application/json" }); rs.end(JSON.stringify({ resourceCount: 1, counts: { critical: 1, high: 0, medium: 0, low: 0 }, suppressed: 0, fail: true, findings: [{ severity: "critical", address: "Deployment/prod/api", title: "t", remediation: "r", fix: { yaml: "spec:\n  x: y" } }], skipped: [], notes: [] })); }); }).listen(0);
  const api = `http://127.0.0.1:${(fake.address() as any).port}`;
  const run = (args: string[], env: object = { CSPM_API_KEY: "cspm_test" }) => new Promise<{ status: number; stdout: string; stderr: string }>((resolve) =>
    execFile(process.execPath, [join(import.meta.dirname, "../../../deploy/k8s-check.mjs"), ...args], { env: { ...process.env, ...env }, encoding: "utf8" }, (err, stdout, stderr) => resolve({ status: err ? Number((err as any).code ?? 1) : 0, stdout, stderr })));
  try {
    const r = await run([join(dir, "m.json"), "--api", api, "--show-fixes"]);
    assert.equal(r.status, 1, r.stdout + r.stderr); assert.match(r.stdout, /Deployment\/prod\/api/); assert.match(r.stdout, /\| spec:/); assert.match(r.stdout, /not checked \(no rules for these kinds\): Secret x1/);
    for (const secret of ["hunter2-secret", "tok-123", "my-secret-name", "private-config", "alice@example.com", "s3cret-annotation", "c2VjcmV0", "DB_PASSWORD"]) assert.equal(seen[0]!.includes(secret), false, `${secret} must not be sent`);
    assert.ok(seen[0]!.includes('"privileged":true') && seen[0]!.includes('"environment":"production"'));
    assert.equal((await run([join(dir, "m.json"), "--api", api, "--fail-on"])).status, 2);
    assert.equal((await run([join(dir, "m.json"), "--api", api], { CSPM_API_KEY: "" })).status, 2);
    assert.equal((await run([join(dir, "missing.json"), "--api", api])).status, 2);
  } finally { fake.close(); }
  // against the real server: a clean manifest passes (exit 0), a bad one fails (exit 1)
  const c = await signup(); const key = (await c.post("/api-keys", { name: "ci", access: "read" })).json.key;
  const real = `http://127.0.0.1:${(server.address() as any).port}`;
  assert.equal((await run([join(dir, "clean.json"), "--api", real], { CSPM_API_KEY: key })).status, 0);
  assert.equal((await run([join(dir, "m.json"), "--api", real], { CSPM_API_KEY: key })).status, 1);
});

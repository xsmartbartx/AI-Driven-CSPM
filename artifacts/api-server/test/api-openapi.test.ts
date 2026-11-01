import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { buildOpenApi } = await import("../src/openapi.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");

let server: Server;
let app: any;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;
before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  app = createApp(db, { mailer: { enabled: true, send: async () => true } });
  server = app.listen(0);
  base = `http://127.0.0.1:${(server.address() as any).port}/api`;
});
after(async () => { server.close(); await db.close(); });

const call = async (method: string, path: string, key = "", body: unknown = undefined) => {
  const headers: Record<string, string> = { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1" };
  if (key) headers["authorization"] = `Bearer ${key}`;
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json: any = null; try { json = JSON.parse(text); } catch { /* csv */ }
  return { status: res.status, json, text, type: res.headers.get("content-type") ?? "" };
};
const spec: any = buildOpenApi("http://localhost/api");
const ops: { method: string; path: string; role: string | undefined; op: any }[] = Object.entries<any>(spec.paths).flatMap(([path, item]) => Object.entries<any>(item).map(([method, op]) => ({ method: method.toUpperCase(), path, role: op["x-min-role"], op })));
const UUID = "00000000-0000-0000-0000-000000000000";
const concrete = (p: string) => p.replace(/\{[^}]+\}/g, UUID);

// Routes meant for people in the dashboard (sessions, team, billing, settings, setup). They are deliberately not in the public API.
const PEOPLE_ONLY = new Set([
  "POST /auth/signup", "POST /auth/login", "POST /auth/logout", "POST /auth/logout-all", "GET /auth/me", "DELETE /auth/me", "GET /auth/sso", "POST /auth/forgot-password", "POST /auth/reset-password", "POST /auth/verify-email", "POST /auth/resend-verification",
  "POST /invites/accept", "POST /demo/scan", "GET /team", "POST /team/invite", "PATCH /team/:id", "DELETE /team/:id", "DELETE /team/invites/:id", "GET /audit",
  "GET /api-keys", "POST /api-keys", "DELETE /api-keys/:id", "POST /billing/checkout", "POST /billing/portal", "POST /billing/webhook",
  "POST /cloud-accounts", "POST /cloud-accounts/:id/verify", "GET /cloud-accounts/:id/setup", "PATCH /cloud-accounts/:id", "DELETE /cloud-accounts/:id",
  "GET /notifications", "PUT /notifications", "POST /notifications/test", "POST /suppressions", "DELETE /suppressions/:id", "POST /findings/:id/explain", "GET /openapi.json",
]);

test("the document is well formed: every reference resolves and every operation states its role and the 401", () => {
  assert.equal(spec.openapi, "3.1.0"); assert.ok(spec.info.title && spec.servers[0].url); assert.equal(spec.components.securitySchemes.apiKey.scheme, "bearer");
  const refs = JSON.stringify(spec).match(/#\/components\/schemas\/[A-Za-z]+/g) ?? [];
  assert.ok(refs.length > 5);
  for (const r of new Set(refs)) assert.ok(spec.components.schemas[r.split("/").pop()!], `${r} is not defined`);
  for (const { method, path, role, op } of ops.filter((o) => o.path !== "/healthz")) {
    assert.ok(role === "viewer" || role === "analyst", `${method} ${path} has no x-min-role`);
    assert.ok(op.responses["401"], `${method} ${path} documents no 401`);
    assert.equal(Boolean(op.responses["403"]), role === "analyst", `${method} ${path}: 403 is documented exactly for analyst operations`);
  }
});

test("the document is served without a key, as JSON", async () => {
  const r = await call("GET", "/openapi.json");
  assert.equal(r.status, 200); assert.match(r.type, /application\/json/);
  assert.equal(r.json.openapi, "3.1.0"); assert.deepEqual(Object.keys(r.json.paths).sort(), Object.keys(spec.paths).sort());
  assert.match(r.json.servers[0].url, /\/api$/);
});

test("every documented operation exists and enforces the role it states (read-only key, scan key, no key)", async () => {
  resetRateLimits();
  const owner = await fetch(base + "/auth/signup", { method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1" }, body: JSON.stringify({ email: `oa-${Date.now()}@example.com`, password: "correct horse battery", orgName: "OpenAPI" }) });
  const cookie = owner.headers.get("set-cookie")!.split(";")[0]!;
  const mk = async (access: string) => (await (await fetch(base + "/api-keys", { method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1", cookie }, body: JSON.stringify({ name: access, access }) })).json() as any).key as string;
  const readKey = await mk("read"), scanKey = await mk("scan");
  const real = (r: { status: number; json: any }) => !(r.status === 404 && r.json?.error?.message === "Unknown endpoint");
  for (const { method, path, role } of ops) {
    const p = concrete(path), body = method === "GET" ? undefined : {};
    const tag = `${method} ${path}`;
    if (path === "/healthz") { assert.equal((await call(method, p)).status, 200, tag); continue; }
    assert.equal((await call(method, p, "", body)).status, 401, `${tag} without a key`);
    assert.equal((await call(method, p, "cspm_wrong", body)).status, 401, `${tag} with a wrong key`);
    const asRead = await call(method, p, readKey, body);
    assert.ok(real(asRead), `${tag} is documented but not routed`);
    if (role === "analyst") assert.equal(asRead.status, 403, `${tag} must refuse a read-only key`);
    else assert.ok(![401, 403].includes(asRead.status), `${tag} must accept a read-only key (got ${asRead.status})`);
    const asScan = await call(method, p, scanKey, body);
    assert.ok(![401, 403].includes(asScan.status) && real(asScan), `${tag} must accept a scan key (got ${asScan.status})`);
  }
});

test("no route is public API by accident: every route is documented or on the explicit people-only list", () => {
  const found: string[] = [];
  const walk = (stack: any[]) => { for (const l of stack) { if (l.route) for (const m of Object.keys(l.route.methods)) found.push(`${m.toUpperCase()} ${l.route.path}`); else if (l.handle?.stack) walk(l.handle.stack); } };
  walk((app.router ?? app._router).stack);
  const documented = new Set(ops.map((o) => `${o.method} ${o.path.replace(/\{([^}]+)\}/g, ":$1")}`));
  const unclassified = found.filter((r) => !documented.has(r) && !PEOPLE_ONLY.has(r));
  assert.deepEqual(unclassified, [], "add these to the OpenAPI document, or to PEOPLE_ONLY if they are not for API keys");
  const stale = [...documented, ...PEOPLE_ONLY].filter((r) => !found.includes(r));
  assert.deepEqual(stale, [], "documented or listed, but no such route");
});

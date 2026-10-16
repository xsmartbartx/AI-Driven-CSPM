import { test, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { assertRlsUsable, openDb, type Db } from "../src/index.ts";
import { MIGRATIONS } from "../src/migrations.generated.ts";

let db: Db;
// every tenant view holds a pooled connection until released, exactly as the API releases it when the response closes
const views: Db[] = [];
const scope = (orgId: string) => { const v = db.scoped(orgId); views.push(v); return v; };
afterEach(async () => { await Promise.all(views.splice(0).map((v) => v.release())); });
const ids: Record<string, string> = {};
const TENANT_TABLES = ["members", "cloud_accounts", "scans", "assets", "findings", "risk_snapshots", "ai_briefs", "usage_events", "audit_events", "api_keys", "invites"];

before(async () => {
  db = await openDb({ dataDir: process.env["TEST_DATABASE_URL"] ? undefined : ":memory:", url: process.env["TEST_DATABASE_URL"] });
  // two organizations, each with a user, a scan, an asset, a finding and one row in every other tenant table
  for (const k of ["A", "B"]) {
    const u = (await db.query("insert into users (email, name, password_hash) values ($1,$2,'hash') returning id", [`rls-${k}-${Date.now()}@example.com`, `User ${k}`])).rows[0]!.id;
    const o = (await db.query("insert into organizations (name, plan) values ($1,'free') returning id", [`Org ${k}`])).rows[0]!.id;
    await db.query("insert into members (org_id, user_id, role) values ($1,$2,'owner')", [o, u]);
    const s = (await db.query("insert into scans (org_id, created_by, source) values ($1,$2,'paste') returning id", [o, u])).rows[0]!.id;
    const a = (await db.query("insert into assets (org_id, type, name) values ($1,'s3_bucket',$2) returning id", [o, `bucket-${k}`])).rows[0]!.id;
    const f = (await db.query("insert into findings (org_id, scan_id, asset_id, rule_id, title, severity, risk_score, remediation) values ($1,$2,$3,'r','t','high',70,'fix') returning id", [o, s, a])).rows[0]!.id;
    await db.query("insert into cloud_accounts (org_id, provider, external_id) values ($1,'aws',$2)", [o, `acct-${k}`]);
    await db.query("insert into risk_snapshots (org_id, day, score) values ($1, current_date, 50)", [o]);
    await db.query("insert into ai_briefs (org_id, finding_id, kind, content, model) values ($1,$2,'finding','c','m')", [o, f]);
    await db.query("insert into usage_events (org_id, kind, period) values ($1,'scan','2026-10')", [o]);
    await db.query("insert into audit_events (org_id, actor_id, action) values ($1,$2,'x')", [o, u]);
    await db.query("insert into api_keys (org_id, name, key_hash, prefix) values ($1,'k',$2,'cspm_')", [o, `hash-${k}-${Date.now()}`]);
    await db.query("insert into invites (org_id, email, role, token_hash, expires_at) values ($1,$2,'viewer',$3, now() + interval '1 day')", [o, `inv-${k}@example.com`, `th-${k}-${Date.now()}`]);
    Object.assign(ids, { [`org${k}`]: o, [`user${k}`]: u, [`finding${k}`]: f, [`asset${k}`]: a, [`scan${k}`]: s });
  }
});
after(async () => { await db.close(); });

test("a query with NO org filter still returns only the caller's rows, on every tenant table", async () => {
  const A = scope(ids["orgA"]!);
  for (const t of TENANT_TABLES) {
    const all = (await db.query(`select org_id from ${t} where org_id in ($1,$2)`, [ids["orgA"], ids["orgB"]])).rows;
    assert.ok(all.some((r) => r.org_id === ids["orgB"]), `${t}: seed has rows for B`);
    const mine = (await A.query(`select org_id from ${t}`)).rows; // deliberately forgets WHERE org_id = ...
    assert.ok(mine.length >= 1 && mine.every((r) => r.org_id === ids["orgA"]), `${t} leaked another organization`);
  }
});

test("cross-tenant writes are refused or touch nothing", async () => {
  const A = scope(ids["orgA"]!);
  await assert.rejects(() => A.query("insert into findings (org_id, scan_id, asset_id, rule_id, title, severity, risk_score, remediation) values ($1,$2,$3,'r','t','low',1,'x')", [ids["orgB"], ids["scanB"], ids["assetB"]]), /row-level security/i);
  assert.equal((await A.query("update findings set title = 'pwned' where id = $1 returning id", [ids["findingB"]])).rows.length, 0);
  assert.equal((await A.query("delete from findings where id = $1 returning id", [ids["findingB"]])).rows.length, 0);
  await assert.rejects(() => A.query("update findings set org_id = $1 where id = $2", [ids["orgB"], ids["findingA"]]), /row-level security/i); // cannot hand its own row to another org
  assert.equal((await db.query("select title from findings where id = $1", [ids["findingB"]])).rows[0]!.title, "t"); // B untouched
  assert.equal((await db.query("select org_id from findings where id = $1", [ids["findingA"]])).rows[0]!.org_id, ids["orgA"]);
});

test("organizations: own row only, and plan / Stripe fields cannot be written from a tenant request", async () => {
  const A = scope(ids["orgA"]!);
  assert.deepEqual((await A.query("select id from organizations")).rows.map((r) => r.id), [ids["orgA"]]);
  assert.equal((await A.query("select id from organizations where id = $1 for update", [ids["orgA"]])).rows.length, 1); // the quota lock still works
  await assert.rejects(() => A.query("update organizations set plan = 'enterprise' where id = $1", [ids["orgA"]]), /permission denied/i);
  await assert.rejects(() => A.query("update organizations set stripe_customer_id = 'cus_evil'"), /permission denied/i);
  await assert.rejects(() => A.query("delete from organizations"), /permission denied/i);
  assert.equal((await db.query("select plan from organizations where id = $1", [ids["orgA"]])).rows[0]!.plan, "free");
});

test("users: only people in the caller's organization; no secrets columns", async () => {
  const A = scope(ids["orgA"]!);
  const seen = (await A.query("select id from users")).rows.map((r) => r.id);
  assert.ok(seen.includes(ids["userA"]) && !seen.includes(ids["userB"]));
  await assert.rejects(() => A.query("select password_hash from users"), /permission denied/i);
  await assert.rejects(() => A.query("select token_version from users"), /permission denied/i);
  await assert.rejects(() => A.query("update users set name = 'x'"), /permission denied/i);
  assert.ok((await A.query("select u.email from members m join users u on u.id = m.user_id")).rows.length >= 1); // the team page query works
});

test("system tables are invisible to tenant requests", async () => {
  const A = scope(ids["orgA"]!);
  for (const t of ["email_tokens", "sso_tokens", "stripe_events", "billing_state", "schema_migrations"])
    await assert.rejects(() => A.query(`select * from ${t}`), /permission denied/i, t);
});

test("an organization with no data, or an unknown one, sees nothing", async () => {
  const empty = scope("00000000-0000-4000-8000-000000000000");
  for (const t of TENANT_TABLES) assert.equal((await empty.query(`select 1 from ${t}`)).rows.length, 0, t);
});

test("fail closed: with no org setting the restricted role sees no rows", async () => {
  const n = await db.tx(async (q) => { await q.exec("set local role cspm_app"); return (await q.query("select count(*)::int as n from findings")).rows[0]!.n; });
  assert.equal(n, 0);
});

test("the org id is validated, so it cannot carry SQL", () => {
  for (const bad of ["x'; drop table users; --", "", "123", ids["orgA"] + "'; select 1; --"]) assert.throws(() => scope(bad), /UUID/);
});

test("scoping is per call: the privileged connection still sees everyone afterwards", async () => {
  await scope(ids["orgA"]!).query("select 1");
  assert.ok((await db.query("select distinct org_id from findings where org_id in ($1,$2)", [ids["orgA"], ids["orgB"]])).rows.length === 2);
});

test("transactions run under the same policies and roll back as usual", async () => {
  const A = scope(ids["orgA"]!);
  await assert.rejects(() => A.tx(async (q) => { await q.query("update findings set title = 'temp' where id = $1", [ids["findingA"]]); throw new Error("boom"); }), /boom/);
  assert.equal((await db.query("select title from findings where id = $1", [ids["findingA"]])).rows[0]!.title, "t");
  await A.tx(async (q) => { await q.query("update findings set title = 'kept' where id = $1", [ids["findingA"]]); });
  assert.equal((await db.query("select title from findings where id = $1", [ids["findingA"]])).rows[0]!.title, "kept");
});

test("startup check passes on a migrated database and explains itself when the role is missing", async () => {
  await assertRlsUsable(db);
  if (process.env["TEST_DATABASE_URL"]) return; // the role is cluster-wide on real Postgres; the next case needs an empty cluster
  const bare = await openDb({ dataDir: ":memory:", migrate: false });
  await bare.exec(MIGRATIONS[0]!.sql);
  await assert.rejects(() => assertRlsUsable(bare), /Row level security is not usable/);
  await bare.close();
});

test("real Postgres: pooled connections never leak a role or org between requests", { skip: !process.env["TEST_DATABASE_URL"] }, async () => {
  const org = (id: string) => scope(id);
  // many interleaved scoped requests for two orgs: each only ever sees its own rows
  const results = await Promise.all(Array.from({ length: 40 }, async (_, i) => {
    const id = i % 2 ? ids["orgA"]! : ids["orgB"]!;
    const v = org(id);
    const rows = (await v.query("select org_id from findings where org_id in ($1,$2)", [ids["orgA"], ids["orgB"]])).rows;
    await v.release();
    return rows.every((r) => r.org_id === id) && rows.length >= 1;
  }));
  assert.ok(results.every(Boolean));
  // after release, connections are back to the owner role with no org, however many times they were reused
  for (let i = 0; i < 30; i++) {
    const r = (await db.query("select current_user::text as u, coalesce(current_setting('app.org_id', true), '') as o")).rows[0]!;
    assert.notEqual(r.u, "cspm_app");
    assert.equal(r.o, "");
  }
  // a scoped view that is released and reused re-acquires cleanly
  const v = org(ids["orgA"]!);
  await v.query("select 1"); await v.release();
  assert.ok((await v.query("select org_id from findings")).rows.every((r) => r.org_id === ids["orgA"]));
  await v.release();
});

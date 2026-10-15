import { test } from "node:test";
import assert from "node:assert/strict";
import { migrate, openDb } from "../src/index.ts";
import { MIGRATIONS } from "../src/migrations.generated.ts";

const versions = async (db: Awaited<ReturnType<typeof openDb>>) => (await db.query("select version from schema_migrations order by version")).rows.map((r) => r.version);
const hasCol = async (db: Awaited<ReturnType<typeof openDb>>, t: string, c: string) => (await db.query("select 1 from information_schema.columns where table_name = $1 and column_name = $2", [t, c])).rows.length === 1;

test("a fresh database gets every migration once; running again does nothing", async () => {
  const db = await openDb({ dataDir: ":memory:" });
  assert.deepEqual(await versions(db), MIGRATIONS.map((m) => m.version));
  assert.ok(await hasCol(db, "users", "email_verified_at"));
  assert.deepEqual(await migrate(db), []);
  await db.close();
});

test("a database from before migrations existed is baselined at 0001, keeps its data, and is brought forward", async () => {
  const db = await openDb({ dataDir: ":memory:", migrate: false });
  await db.exec(MIGRATIONS[0]!.sql); // what the old code created
  await db.query("insert into users (email) values ('legacy@example.com')");
  assert.equal(await hasCol(db, "users", "email_verified_at"), false);
  const applied = await migrate(db);
  assert.deepEqual(applied, MIGRATIONS.slice(1).map((m) => m.version)); // 0001 only recorded, never re-run (it would fail)
  assert.deepEqual(await versions(db), MIGRATIONS.map((m) => m.version));
  assert.ok(await hasCol(db, "users", "email_verified_at"));
  assert.equal((await db.query("select email from users")).rows[0]!.email, "legacy@example.com");
  await db.close();
});

test("a legacy database that already has later changes is not broken by the idempotent migrations", async () => {
  const db = await openDb({ dataDir: ":memory:", migrate: false });
  for (const m of MIGRATIONS) await db.exec(m.sql); // head schema, but no schema_migrations table yet
  await migrate(db);
  assert.deepEqual(await versions(db), MIGRATIONS.map((m) => m.version));
  await db.close();
});

test("a failing migration rolls back completely and stops; earlier ones stay applied", async () => {
  const db = await openDb({ dataDir: ":memory:", migrate: false });
  const list = [
    { version: "0001_a", sql: "create table a (id int);" },
    { version: "0002_bad", sql: "create table b (id int); select 1/0;" },
    { version: "0003_c", sql: "create table c (id int);" },
  ];
  await assert.rejects(() => migrate(db, list));
  assert.deepEqual(await versions(db), ["0001_a"]);
  assert.equal((await db.query("select to_regclass('public.b') as t")).rows[0]!.t, null); // nothing from 0002 survived
  assert.equal((await db.query("select to_regclass('public.c') as t")).rows[0]!.t, null); // 0003 never ran
  list[1] = { version: "0002_bad", sql: "create table b (id int);" }; // fixed in the next release
  assert.deepEqual(await migrate(db, list), ["0002_bad", "0003_c"]);
  await db.close();
});

test("migration files are numbered without gaps and the first one is the baseline", () => {
  assert.deepEqual(MIGRATIONS.map((m) => m.version.slice(0, 4)), MIGRATIONS.map((_, i) => String(i + 1).padStart(4, "0")));
  assert.ok(MIGRATIONS[0]!.sql.includes("create table organizations"));
});

test("two instances starting at once on real Postgres do not race (needs TEST_DATABASE_URL)", { skip: !process.env["TEST_DATABASE_URL"] }, async () => {
  const admin = await openDb({ url: process.env["TEST_DATABASE_URL"]!, migrate: false });
  const name = `mig_race_${Date.now()}`;
  await admin.exec(`create database ${name}`);
  const url = new URL(process.env["TEST_DATABASE_URL"]!); url.pathname = `/${name}`;
  const [a, b] = await Promise.all([openDb({ url: url.toString() }), openDb({ url: url.toString() })]);
  assert.deepEqual(await versions(a), MIGRATIONS.map((m) => m.version));
  await a.close(); await b.close(); await admin.exec(`drop database ${name}`); await admin.close();
});

import { MIGRATIONS } from "./migrations.generated";

export type Row = Record<string, any>;
export interface Queryable {
  query<T extends Row = Row>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  /** Run SQL that may contain several statements (no parameters). */
  exec(sql: string): Promise<unknown>;
}
export interface Db extends Queryable {
  /** Run fn inside one transaction. Throwing rolls back. */
  tx<T>(fn: (q: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/** Arbitrary constant: concurrent instances starting together take turns instead of racing. */
const MIGRATION_LOCK = 727274;

/**
 * Applies every migration that has not run yet, in order, each in its own transaction.
 * - Safe to run on every start, and from several instances at once (advisory lock).
 * - A database created before migrations existed (it has tables but no `schema_migrations`) is
 *   recorded as being at 0001, then brought forward by the later migrations, which are written to be idempotent.
 * Returns the versions applied by this call.
 */
export async function migrate(db: Db, migrations: { version: string; sql: string }[] = MIGRATIONS): Promise<string[]> {
  const done = async (q: Queryable) => new Set((await q.query<{ version: string }>("select version from schema_migrations")).rows.map((r) => r.version));

  // Bootstrap under the lock as well: two instances running "create table if not exists" at once can collide inside Postgres.
  await db.tx(async (q) => {
    await q.query("select pg_advisory_xact_lock($1)", [MIGRATION_LOCK]);
    await q.exec("create table if not exists schema_migrations (version text primary key, applied_at timestamptz not null default now())");
    if ((await done(q)).size === 0) {
      const legacy = (await q.query<{ t: string | null }>("select to_regclass('public.organizations') as t")).rows[0]?.t;
      if (legacy) await q.query("insert into schema_migrations (version) values ($1) on conflict do nothing", [migrations[0]!.version]);
    }
  });

  const applied: string[] = [];
  for (const m of migrations) {
    await db.tx(async (q) => {
      await q.query("select pg_advisory_xact_lock($1)", [MIGRATION_LOCK]);
      if ((await done(q)).has(m.version)) return; // another instance did it while we waited
      await q.exec(m.sql);
      await q.query("insert into schema_migrations (version) values ($1)", [m.version]);
      applied.push(m.version);
    });
  }
  return applied;
}

/**
 * url set   -> Postgres via pg (production).
 * otherwise -> PGlite (embedded Postgres) persisted in `dataDir`, or in memory if dataDir is ":memory:".
 * Migrations run on open unless `migrate: false`.
 */
export async function openDb(opts: { url?: string; dataDir?: string; migrate?: boolean } = {}): Promise<Db> {
  let db: Db;
  if (opts.url) {
    const { default: pg } = await import("pg");
    const pool = new pg.Pool({ connectionString: opts.url, max: 10 });
    // an idle client can drop (restart, failover); without a listener Node would crash the process on the pool "error" event
    pool.on("error", (err) => console.error("postgres pool error", err.message));
    db = {
      query: (sql, params) => pool.query(sql, params as any) as any,
      exec: (sql) => pool.query(sql),
      async tx(fn) {
        const c = await pool.connect();
        let broken: Error | undefined;
        try {
          await c.query("begin");
          const r = await fn({ query: (s, p) => c.query(s, p as any) as any, exec: (s) => c.query(s) });
          await c.query("commit");
          return r;
        } catch (e) {
          // keep the ORIGINAL error even if rollback fails on a dead connection, and do not reuse that connection
          await c.query("rollback").catch((re: Error) => { broken = re; });
          throw e;
        } finally {
          c.release(broken);
        }
      },
      close: () => pool.end(),
    };
  } else {
    const { PGlite } = await import("@electric-sql/pglite");
    const lite = new PGlite(opts.dataDir && opts.dataDir !== ":memory:" ? opts.dataDir : undefined);
    await lite.waitReady;
    db = {
      query: (sql, params) => lite.query(sql, params as any) as any,
      exec: (sql) => lite.exec(sql),
      tx: (fn) => lite.transaction((t) => fn({ query: (s, p) => t.query(s, p as any) as any, exec: (s) => t.exec(s) })),
      close: () => lite.close(),
    };
  }
  if (opts.migrate !== false) await migrate(db);
  return db;
}

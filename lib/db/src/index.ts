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
  /**
   * A view of this database for ONE tenant: runs as the restricted role `cspm_app` with `app.org_id` set, so the
   * row level security policies hide every other organization's rows, whatever the SQL says. Call release() when
   * the request ends (and before any long external call, so the connection goes back to the pool).
   * When RLS is switched off (`rls: false`) this returns the database itself.
   */
  scoped(orgId: string): Db;
  release(): Promise<void>;
  close(): Promise<void>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** The org id is placed into a SET statement, so it must be a plain UUID, nothing else. */
function checkOrg(orgId: string): string {
  if (!UUID.test(orgId)) throw new Error("scoped(): orgId must be a UUID");
  return orgId;
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
export async function openDb(opts: { url?: string; dataDir?: string; migrate?: boolean; rls?: boolean; poolMax?: number } = {}): Promise<Db> {
  const rls = opts.rls !== false;
  let db: Db;
  if (opts.url) {
    const { default: pg } = await import("pg");
    const pool = new pg.Pool({ connectionString: opts.url, max: opts.poolMax ?? 10 });
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
      scoped(orgId) {
        if (!rls) return db;
        checkOrg(orgId);
        // one pooled connection for the whole request: role and org are set once, instead of around every query
        let client: import("pg").PoolClient | null = null;
        const acquire = async () => {
          if (client) return client;
          const c = await pool.connect();
          try { await c.query(`set role cspm_app; set app.org_id = '${orgId}'`); } catch (e) { c.release(e as Error); throw e; }
          return (client = c);
        };
        const view: Db = {
          query: async (sql, params) => (await acquire()).query(sql, params as any) as any,
          exec: async (sql) => (await acquire()).query(sql),
          async tx(fn) {
            const c = await acquire();
            let dead = false;
            try {
              await c.query("begin");
              const r = await fn({ query: (s, p) => c.query(s, p as any) as any, exec: (s) => c.query(s) });
              await c.query("commit");
              return r;
            } catch (e) {
              await c.query("rollback").catch(() => { dead = true; });
              if (dead) { client = null; c.release(e as Error); } // never reuse a connection in an unknown state
              throw e;
            }
          },
          scoped: () => { throw new Error("already scoped"); },
          async release() {
            const c = client;
            client = null;
            if (!c) return;
            // the session must go back to the pool exactly as it came: owner role, no org
            try { await c.query("reset role; reset app.org_id"); c.release(); } catch (e) { c.release(e as Error); }
          },
          close: async () => {},
        };
        return view;
      },
      release: async () => {},
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
      scoped(orgId) {
        if (!rls) return db;
        checkOrg(orgId);
        // embedded Postgres has one connection shared by all requests, so the role and org live only inside one transaction
        const run = <T>(fn: (t: any) => Promise<T>) => lite.transaction(async (t) => { await t.exec(`set local role cspm_app; set local app.org_id = '${orgId}'`); return fn(t); });
        return {
          query: (sql, params) => run((t) => t.query(sql, params as any)) as any,
          exec: (sql) => run((t) => t.exec(sql)),
          tx: (fn) => run((t) => fn({ query: (s, p) => t.query(s, p as any) as any, exec: (s) => t.exec(s) })),
          scoped: () => { throw new Error("already scoped"); },
          release: async () => {},
          close: async () => {},
        };
      },
      release: async () => {},
      close: () => lite.close(),
    };
  }
  if (opts.migrate !== false) {
    await migrate(db);
    if (rls) await assertRlsUsable(db);
  }
  return db;
}

/**
 * Fail closed at startup: if the restricted role cannot be used, refuse to run instead of silently serving
 * tenants without the database-level isolation. (Set RLS_ENFORCE=0 to run without it, knowingly.)
 */
export async function assertRlsUsable(db: Db): Promise<void> {
  try {
    await db.tx(async (q) => {
      await q.exec("set local role cspm_app");
      await q.query("select count(*) from findings"); // no org set: allowed, returns nothing
    });
  } catch (e) {
    throw new Error(`Row level security is not usable: ${(e as Error).message}. The database user must be able to SET ROLE cspm_app (migration 0003 creates it and grants it); or set RLS_ENFORCE=0 to run without database-level isolation.`);
  }
}

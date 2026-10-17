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
   * the request ends with release(true), and plain release() before any long external call so the connection goes
   * back to the pool meanwhile.
   * When RLS is switched off (`rls: false`) this returns the database itself.
   */
  scoped(orgId: string): Db;
  /**
   * Waits for in-flight queries and transactions on this view to finish, then resets the session and returns the
   * connection. release() lets the view be used again (it re-acquires); release(true) is FINAL: later use throws,
   * so a request that was abandoned (client disconnected) can never take a connection back.
   */
  release(final?: boolean): Promise<void>;
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
        // One pooled connection for the whole request: role and org are set once, instead of around every query.
        // Every operation goes through one queue, so a release can never overlap a running query or transaction.
        // (Inside a tx callback use the `q` it is given, not this view: the view's queue is busy until the tx ends.)
        let client: import("pg").PoolClient | null = null;
        let closed = false;
        let queue: Promise<unknown> = Promise.resolve();
        const enqueue = <T>(fn: () => Promise<T>, internal = false): Promise<T> => {
          // refuse work submitted after the final release; work submitted before it is already in the queue and finishes first
          if (closed && !internal) return Promise.reject(new Error("this request has already finished; its database session was released"));
          const p = queue.then(fn);
          queue = p.then(() => {}, () => {});
          return p;
        };
        const acquire = async () => {
          if (client) return client;
          const c = await pool.connect();
          try { await c.query(`set role cspm_app; set app.org_id = '${orgId}'`); } catch (e) { c.release(e as Error); throw e; }
          return (client = c);
        };
        const view: Db = {
          query: (sql, params) => enqueue(async () => (await acquire()).query(sql, params as any) as any),
          exec: (sql) => enqueue(async () => (await acquire()).query(sql)),
          tx: (fn) => enqueue(async () => {
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
          }),
          scoped: () => { throw new Error("already scoped"); },
          release(final = false) {
            const done = enqueue(async () => {
              const c = client;
              client = null;
              if (!c) return;
              // the session must go back to the pool exactly as it came: owner role, no org
              try { await c.query("reset role; reset app.org_id"); c.release(); } catch (e) { c.release(e as Error); }
            }, true);
            if (final) closed = true; // queued AFTER the release step is in line, so everything before it still runs
            return done;
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
        let closed = false;
        const run = <T>(fn: (t: any) => Promise<T>) => {
          if (closed) return Promise.reject(new Error("this request has already finished; its database session was released"));
          return lite.transaction(async (t) => { await t.exec(`set local role cspm_app; set local app.org_id = '${orgId}'`); return fn(t); });
        };
        return {
          query: (sql, params) => run((t) => t.query(sql, params as any)) as any,
          exec: (sql) => run((t) => t.exec(sql)),
          tx: (fn) => run((t) => fn({ query: (s, p) => t.query(s, p as any) as any, exec: (s) => t.exec(s) })),
          scoped: () => { throw new Error("already scoped"); },
          release: async (final = false) => { if (final) closed = true; },
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

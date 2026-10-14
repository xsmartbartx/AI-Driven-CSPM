import { SCHEMA_SQL } from "./schema.generated";

export type Row = Record<string, any>;
export interface Queryable {
  query<T extends Row = Row>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}
export interface Db extends Queryable {
  /** Run fn inside one transaction. Throwing rolls back. */
  tx<T>(fn: (q: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

async function migrate(db: Queryable, exec: (sql: string) => Promise<unknown>) {
  const { rows } = await db.query<{ t: string | null }>("select to_regclass('public.organizations') as t");
  if (!rows[0]?.t) await exec(SCHEMA_SQL);
}

/**
 * DATABASE_URL set  -> Postgres via pg (production).
 * otherwise         -> PGlite (embedded Postgres) persisted in `dataDir`, or in memory if dataDir is ":memory:".
 */
export async function openDb(opts: { url?: string; dataDir?: string } = {}): Promise<Db> {
  if (opts.url) {
    const { default: pg } = await import("pg");
    const pool = new pg.Pool({ connectionString: opts.url, max: 10 });
    const db: Db = {
      query: (sql, params) => pool.query(sql, params as any) as any,
      async tx(fn) {
        const c = await pool.connect();
        try {
          await c.query("begin");
          const r = await fn({ query: (s, p) => c.query(s, p as any) as any });
          await c.query("commit");
          return r;
        } catch (e) {
          await c.query("rollback");
          throw e;
        } finally {
          c.release();
        }
      },
      close: () => pool.end(),
    };
    await migrate(db, (sql) => pool.query(sql));
    return db;
  }
  const { PGlite } = await import("@electric-sql/pglite");
  const lite = new PGlite(opts.dataDir && opts.dataDir !== ":memory:" ? opts.dataDir : undefined);
  await lite.waitReady;
  const db: Db = {
    query: (sql, params) => lite.query(sql, params as any) as any,
    tx: (fn) => lite.transaction((t) => fn({ query: (s, p) => t.query(s, p as any) as any })),
    close: () => lite.close(),
  };
  await migrate(db, (sql) => lite.exec(sql));
  return db;
}

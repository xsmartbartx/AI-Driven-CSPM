import type { Db, Queryable } from "@workspace/db";
import { logger } from "../lib/logger";

export interface ActiveSuppression { id: string; ruleId: string; assetId: string | null; environment: string | null; reason: string }
export const MAX_SUPPRESSIONS = 100;
export const suppressedReason = (reason: string) => `Suppressed: ${reason}`;

/** Serialises everything that changes suppression state with scans: runScan takes the same lock. */
export async function lockOrg(q: Queryable, orgId: string): Promise<void> {
  await q.query("select id from organizations where id = $1 for update", [orgId]);
}

/**
 * Brings every finding in line with the suppressions that are active right now, in one statement. The caller holds the
 * organization lock. A finding is suppressed by the most specific matching suppression (one asset, then one
 * environment, then everywhere; oldest first). A finding whose suppression ended or was removed is reopened, one that
 * only lost its suppression to a still-matching one is moved to it, and an open finding that now matches (a new
 * suppression, or the asset moved to another environment) is suppressed. Findings reopened by hand are left alone.
 * `excluding` is a suppression about to be deleted: it is treated as already gone.
 */
export async function reconcile(q: Queryable, orgId: string, excluding: string | null = null): Promise<void> {
  await q.query(
    `with m as (
       select f.id as fid,
         (select s.id from suppressions s
           where s.org_id = f.org_id and s.rule_id = f.rule_id
             and (s.asset_id is null or s.asset_id = f.asset_id) and (s.environment is null or s.environment = a.environment)
             and (s.expires_at is null or s.expires_at > now()) and ($2::uuid is null or s.id <> $2)
           order by (s.asset_id is not null) desc, (s.environment is not null) desc, s.created_at, s.id limit 1) as want
       from findings f join assets a on a.id = f.asset_id
       where f.org_id = $1 and ((f.status = 'open' and not f.suppress_exempt) or (f.status = 'false_positive' and f.suppression_id is not null)))
     update findings f set
       status = case when m.want is null then 'open' else 'false_positive' end,
       suppression_id = m.want,
       status_reason = case when m.want is null then null else 'Suppressed: ' || (select reason from suppressions where id = m.want) end,
       accepted_until = null, updated_at = now()
     from m where f.id = m.fid and (f.suppression_id is distinct from m.want or (m.want is not null and f.status <> 'false_positive'))`,
    [orgId, excluding]);
}

/** With the lock held: expired suppressions stop counting (their findings reopen or move to another match), then they are deleted. */
export async function expireLocked(q: Queryable, orgId: string): Promise<void> {
  await reconcile(q, orgId);
  await q.query("delete from suppressions where org_id = $1 and expires_at is not null and expires_at <= now()", [orgId]);
}

/** Cheap when nothing has expired. Called before anything that reads open findings. */
export async function refreshSuppressions(db: Db, orgId: string): Promise<void> {
  const due = await db.query("select 1 from suppressions where org_id = $1 and expires_at is not null and expires_at <= now() limit 1", [orgId]);
  if (!due.rows[0]) return;
  await db.tx(async (q) => { await lockOrg(q, orgId); await expireLocked(q, orgId); });
}

/** For the scheduler: expiry must not wait for somebody to open a page. */
export async function sweepExpiredSuppressions(sysDb: Db): Promise<void> {
  const { rows } = await sysDb.query("select distinct org_id from suppressions where expires_at is not null and expires_at <= now() limit 50");
  for (const r of rows) {
    const db = sysDb.scoped(r.org_id);
    try { await refreshSuppressions(db, r.org_id); }
    catch (e) { logger.warn({ org: r.org_id, err: e instanceof Error ? e.name : "error" }, "could not expire suppressions"); } // one organization must not stop the others
    finally { await db.release(true).catch(() => {}); }
  }
}

export async function activeSuppressions(q: Queryable, orgId: string): Promise<(ActiveSuppression & { createdAt: string })[]> {
  const { rows } = await q.query(
    `select id, rule_id as "ruleId", asset_id as "assetId", environment, reason, created_at as "createdAt" from suppressions
     where org_id = $1 and (expires_at is null or expires_at > now()) order by created_at, id`, [orgId]);
  return rows as unknown as (ActiveSuppression & { createdAt: string })[];
}

/** Same choice reconcile() makes in SQL: the most specific match, then the oldest. The list arrives oldest first. */
export function matchSuppression(list: ActiveSuppression[], ruleId: string, assetId: string, environment: string): ActiveSuppression | undefined {
  const hits = list.filter((s) => s.ruleId === ruleId && (!s.assetId || s.assetId === assetId) && (!s.environment || s.environment === environment));
  const rank = (s: ActiveSuppression) => (s.assetId ? 2 : s.environment ? 1 : 0);
  return hits.reduce<ActiveSuppression | undefined>((best, s) => (!best || rank(s) > rank(best) ? s : best), undefined);
}

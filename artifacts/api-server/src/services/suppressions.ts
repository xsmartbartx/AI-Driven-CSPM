import type { Queryable } from "@workspace/db";

export interface ActiveSuppression { id: string; ruleId: string; assetId: string | null; environment: string | null; reason: string }
export const MAX_SUPPRESSIONS = 100;
export const suppressedReason = (reason: string) => `Suppressed: ${reason}`;

/** Suppressions that ended: their findings come back as open (the next scan or the list view does this, no timer needed). */
export async function expireSuppressions(q: Queryable, orgId: string): Promise<void> {
  await q.query(
    `update findings set status = 'open', status_reason = null, suppression_id = null, updated_at = now()
     where org_id = $1 and status = 'false_positive' and suppression_id in (select id from suppressions where org_id = $1 and expires_at is not null and expires_at <= now())`, [orgId]);
  await q.query("delete from suppressions where org_id = $1 and expires_at is not null and expires_at <= now()", [orgId]);
}

export async function activeSuppressions(q: Queryable, orgId: string): Promise<ActiveSuppression[]> {
  const { rows } = await q.query(`select id, rule_id as "ruleId", asset_id as "assetId", environment, reason from suppressions where org_id = $1`, [orgId]);
  return rows as unknown as ActiveSuppression[];
}

export function matchSuppression(list: ActiveSuppression[], ruleId: string, assetId: string, environment: string): ActiveSuppression | undefined {
  return list.find((s) => s.ruleId === ruleId && (s.assetId ? s.assetId === assetId : s.environment ? s.environment === environment : true));
}

/** Suppress the findings that are open right now and match. Returns how many. */
export async function applyToOpenFindings(q: Queryable, orgId: string, s: ActiveSuppression): Promise<number> {
  const { rows } = await q.query(
    `update findings f set status = 'false_positive', status_reason = $3, suppression_id = $2, accepted_until = null, updated_at = now()
     from assets a where a.id = f.asset_id and f.org_id = $1 and f.rule_id = $4 and f.status = 'open'
       and ($5::uuid is null or f.asset_id = $5) and ($6::text is null or a.environment = $6) returning f.id`,
    [orgId, s.id, suppressedReason(s.reason), s.ruleId, s.assetId, s.environment]);
  return rows.length;
}

export async function releaseFindings(q: Queryable, orgId: string, suppressionId: string): Promise<number> {
  const { rows } = await q.query(
    "update findings set status = 'open', status_reason = null, suppression_id = null, updated_at = now() where org_id = $1 and suppression_id = $2 and status = 'false_positive' returning id", [orgId, suppressionId]);
  return rows.length;
}

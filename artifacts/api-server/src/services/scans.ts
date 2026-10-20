import type { Queryable } from "@workspace/db";
import { complianceFrom, defaultCriticality, evaluate, parseInput, postureScore, type Severity } from "@workspace/cspm-engine";
import { PLANS, type PlanId } from "../config";
import { bad, HttpError } from "../lib/errors";
import type { Auth } from "../lib/context";

const SEVS: Severity[] = ["critical", "high", "medium", "low"];
export const period = (d = new Date()) => d.toISOString().slice(0, 7);

export async function openCounts(q: Queryable, orgId: string): Promise<Record<Severity, number>> {
  const { rows } = await q.query("select severity, count(*)::int as n from findings where org_id = $1 and status = 'open' group by severity", [orgId]);
  const c = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  for (const r of rows) c[r.severity as Severity] = r.n;
  return c;
}
export const postureOf = (c: Record<Severity, number>) => postureScore(c);

export async function usageOf(q: Queryable, orgId: string) {
  const { rows: o } = await q.query("select plan from organizations where id = $1", [orgId]);
  const plan = (o[0]?.plan ?? "free") as PlanId;
  const p = period();
  const { rows } = await q.query("select kind, count(*)::int as n from usage_events where org_id = $1 and period = $2 group by kind", [orgId, p]);
  const used = (k: string) => rows.find((r) => r.kind === k)?.n ?? 0;
  const now = new Date();
  return {
    plan, planLabel: PLANS[plan].label, period: p,
    scans: { used: used("scan"), limit: PLANS[plan].scans },
    ai: { used: used("ai"), limit: PLANS[plan].ai },
    resetsAt: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString(),
  };
}

export function demoScan(config: unknown) {
  const { resources, errors } = parseInput(config);
  if (errors.length) throw bad(errors.join(" "), "invalid_config");
  const { findings, unknownTypes } = evaluate(resources);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  findings.forEach((f) => counts[f.severity]++);
  return { resourceCount: resources.length, findings, unknownTypes, counts, score: postureScore(counts) };
}

export async function runScan(db: { tx: <T>(fn: (q: Queryable) => Promise<T>) => Promise<T> }, auth: Auth, config: unknown, opts: { accountId?: string; complete?: boolean } = {}) {
  const { resources, errors } = parseInput(config);
  if (errors.length) throw bad(errors.join(" "), "invalid_config");
  const { findings, unknownTypes } = evaluate(resources);

  return db.tx(async (q) => {
    // lock the org row so two concurrent scans cannot both pass the quota check
    const { rows: o } = await q.query("select plan from organizations where id = $1 for update", [auth.orgId]);
    const plan = (o[0]?.plan ?? "free") as PlanId;
    const per = period();
    const { rows: u } = await q.query("select count(*)::int as n from usage_events where org_id = $1 and kind = 'scan' and period = $2", [auth.orgId, per]);
    if (u[0].n >= PLANS[plan].scans)
      throw new HttpError(402, "quota_exceeded", `You have used all ${PLANS[plan].scans} scans on the ${PLANS[plan].label} plan this month.`);

    const { rows: s } = await q.query(
      "insert into scans (org_id, created_by, source, account_id, status, resource_count) values ($1,$2,$3,$4,'completed',$5) returning id, created_at",
      [auth.orgId, auth.userId, opts.accountId ? "account" : "paste", opts.accountId ?? null, resources.length]);
    const scanId = s[0].id as string;
    await q.query("insert into usage_events (org_id, kind, period) values ($1,'scan',$2)", [auth.orgId, per]);

    const assetId = new Map<string, string>();
    for (const r of resources) {
      const { rows } = await q.query(
        `insert into assets (org_id, provider, type, name, environment, criticality, owner, raw, account_id)
         values ($1,'aws',$2,$3,$4,$5,$6,$7::jsonb,$8)
         on conflict (org_id, provider, type, name) do update
           set environment = excluded.environment, criticality = excluded.criticality, owner = excluded.owner,
               raw = excluded.raw, account_id = coalesce(excluded.account_id, assets.account_id), last_seen_at = now(), updated_at = now()
         returning id`,
        [auth.orgId, r.type, r.name,
          ["production", "staging", "development"].includes(r.environment as string) ? r.environment : "production",
          Math.min(10, Math.max(1, Math.round(Number(r.criticality ?? defaultCriticality(r))) || 5)),
          typeof r.owner === "string" ? r.owner.slice(0, 100) : null, JSON.stringify(r), opts.accountId ?? null]);
      assetId.set(`${r.type}/${r.name}`, rows[0].id);
    }

    const ids = [...assetId.values()];
    const { rows: existing } = await q.query(
      "select id, asset_id, rule_id, status, accepted_until from findings where org_id = $1 and asset_id = any($2::uuid[])", [auth.orgId, ids]);
    const exMap = new Map(existing.map((e) => [`${e.asset_id}/${e.rule_id}`, e]));
    const seen = new Set<string>();
    let created = 0, reopened = 0, persisting = 0, fixed = 0;

    for (const f of findings) {
      const aid = assetId.get(`${f.resourceType}/${f.resourceName}`)!;
      const key = `${aid}/${f.ruleId}`;
      seen.add(key);
      const ex = exMap.get(key);
      if (ex) {
        const expired = ex.status === "accepted" && ex.accepted_until && new Date(ex.accepted_until) < new Date();
        const reopen = ex.status === "fixed" || expired;
        await q.query(
          `update findings set scan_id=$2, title=$3, severity=$4, risk_score=$5, evidence=$6::jsonb, remediation=$7, frameworks=$8::text[],
             last_seen_at=now(), updated_at=now(),
             status = case when $9 then 'open' else status end,
             status_reason = case when $9 then null else status_reason end,
             accepted_until = case when $9 then null else accepted_until end,
             first_seen_at = case when $10 then now() else first_seen_at end
           where id=$1`,
          [ex.id, scanId, f.title, f.severity, f.riskScore, JSON.stringify(f.evidence), f.remediation, f.frameworks, reopen, ex.status === "fixed"]);
        reopen ? reopened++ : persisting++;
      } else {
        await q.query(
          `insert into findings (org_id, scan_id, asset_id, rule_id, title, severity, risk_score, evidence, remediation, frameworks)
           values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::text[])`,
          [auth.orgId, scanId, aid, f.ruleId, f.title, f.severity, f.riskScore, JSON.stringify(f.evidence), f.remediation, f.frameworks]);
        created++;
      }
    }
    // findings on scanned assets that no longer trigger are fixed
    for (const e of existing) {
      if (seen.has(`${e.asset_id}/${e.rule_id}`) || !["open", "accepted"].includes(e.status)) continue;
      await q.query("update findings set status='fixed', updated_at=now() where id=$1", [e.id]);
      fixed++;
    }

    // A COMPLETE account scan also knows which resources are gone: findings on assets of this account that were not
    // seen this time are fixed. An incomplete scan (a denied service, the resource cap) must never conclude that.
    if (opts.accountId && opts.complete) {
      const gone = await q.query(
        "update findings set status = 'fixed', updated_at = now() where org_id = $1 and status in ('open','accepted') and asset_id in (select id from assets where org_id = $1 and account_id = $2 and id <> all($3::uuid[])) returning id",
        [auth.orgId, opts.accountId, ids]);
      fixed += gone.rows.length;
    }
    const c = await openCounts(q, auth.orgId);
    const score = postureScore(c);
    const counts = { new: created + reopened, fixed, persisting, open: c };
    await q.query("update scans set finding_count=$2, score=$3, counts=$4::jsonb, updated_at=now() where id=$1", [scanId, findings.length, score, JSON.stringify(counts)]);
    await q.query(
      `insert into risk_snapshots (org_id, day, score, critical, high, medium, low) values ($1, (now() at time zone 'utc')::date, $2,$3,$4,$5,$6)
       on conflict (org_id, day) do update set score=excluded.score, critical=excluded.critical, high=excluded.high, medium=excluded.medium, low=excluded.low`,
      [auth.orgId, score, c.critical, c.high, c.medium, c.low]);
    return { id: scanId, resourceCount: resources.length, findingCount: findings.length, score, counts, unknownTypes };
  });
}

export async function overview(q: Queryable, orgId: string, days: number) {
  const c = await openCounts(q, orgId);
  const score = postureScore(c);
  const { rows: snaps } = await q.query(
    `select to_char(day,'YYYY-MM-DD') as day, score, critical, high, medium, low from risk_snapshots
     where org_id = $1 and day >= (now() at time zone 'utc')::date - $2::int order by day`, [orgId, days]);
  const first = snaps[0];
  const today = new Date().toISOString().slice(0, 10);
  const delta = first && first.day !== today ? score - first.score : null;
  const { rows: byProv } = await q.query("select provider, count(*)::int as n from assets where org_id = $1 group by provider order by n desc", [orgId]);
  const { rows: byType } = await q.query("select type, count(*)::int as n from assets where org_id = $1 group by type order by n desc", [orgId]);
  const { rows: top } = await q.query(
    `select f.id, f.title, f.severity, f.risk_score as "riskScore", a.name as "assetName", a.type as "assetType", a.provider
     from findings f join assets a on a.id = f.asset_id where f.org_id = $1 and f.status = 'open' order by f.risk_score desc, f.created_at limit 5`, [orgId]);
  const { rows: rules } = await q.query("select distinct rule_id from findings where org_id = $1 and status = 'open'", [orgId]);
  const comp = complianceFrom(rules.map((r) => r.rule_id));
  const { rows: sc } = await q.query("select count(*)::int as n from scans where org_id = $1", [orgId]);
  const { rows: last } = await q.query("select id, created_at as \"createdAt\", score, finding_count as \"findingCount\" from scans where org_id = $1 order by created_at desc limit 1", [orgId]);
  return {
    hasData: sc[0].n > 0, score, delta, counts: c, openTotal: c.critical + c.high + c.medium + c.low,
    assets: { total: byProv.reduce((s, r) => s + r.n, 0), byProvider: byProv, byType },
    trend: snaps, topActions: top,
    compliance: { total: comp.reduce((s, f) => s + f.controls, 0), passing: comp.reduce((s, f) => s + f.controls - f.failed, 0), frameworks: comp.map((f) => ({ framework: f.framework, coverage: f.coverage, failed: f.failed, controls: f.controls })) },
    lastScan: last[0] ?? null, usage: await usageOf(q, orgId),
  };
}
export { SEVS };

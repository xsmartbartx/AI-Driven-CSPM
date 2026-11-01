import type { Queryable } from "@workspace/db";

export interface Brief {
  hours: number; since: string; hasData: boolean;
  score: number | null; scoreChange: number | null;
  open: Record<"critical" | "high" | "medium" | "low", number>;
  newFindings: { total: number; items: { id: string; title: string; severity: string; assetName: string }[] };
  fixed: number;
  topRisks: { id: string; title: string; severity: string; riskScore: number; assetName: string }[];
  expiring: { acceptedRisks: number; suppressions: number }; // within 14 days
  headline: string; lines: string[];
}

const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;

/**
 * What changed, in plain sentences, from the data already stored: no model involved, so every line can be traced to a
 * finding. "New" means first seen inside the window and still open (suppressed or fixed ones are not news).
 */
export async function buildBrief(q: Queryable, orgId: string, hours = 24, topN = 3): Promise<Brief> {
  const since = new Date(Date.now() - hours * 3600_000);
  const sinceIso = since.toISOString();
  const { rows: cnt } = await q.query("select severity, count(*)::int as n from findings where org_id = $1 and status = 'open' group by severity", [orgId]);
  const open = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of cnt) open[r.severity as keyof typeof open] = r.n;
  const openTotal = open.critical + open.high + open.medium + open.low;
  const { rows: scans } = await q.query("select 1 from scans where org_id = $1 limit 1", [orgId]);
  if (!scans[0]) return { hours, since: sinceIso, hasData: false, score: null, scoreChange: null, open, newFindings: { total: 0, items: [] }, fixed: 0, topRisks: [], expiring: { acceptedRisks: 0, suppressions: 0 }, headline: "No scans yet.", lines: ["Run a scan to get a daily summary."] };

  const { rows: snaps } = await q.query(
    `select score, created_at from risk_snapshots where org_id = $1 order by day desc limit 1`, [orgId]);
  const { rows: older } = await q.query(
    `select score from risk_snapshots where org_id = $1 and created_at < $2 order by day desc limit 1`, [orgId, sinceIso]);
  const score = snaps[0]?.score ?? null, scoreChange = score !== null && older[0] ? score - older[0].score : null;

  const { rows: fresh } = await q.query(
    `select f.id, f.title, f.severity, a.name as "assetName" from findings f join assets a on a.id = f.asset_id
     where f.org_id = $1 and f.status = 'open' and f.first_seen_at >= $2 order by f.risk_score desc, f.title limit 5`, [orgId, sinceIso]);
  const totalNew = (await q.query("select count(*)::int as n from findings where org_id = $1 and status = 'open' and first_seen_at >= $2", [orgId, sinceIso])).rows[0].n as number;
  const fixed = (await q.query("select count(*)::int as n from findings where org_id = $1 and status = 'fixed' and updated_at >= $2", [orgId, sinceIso])).rows[0].n as number;
  const { rows: top } = await q.query(
    `select f.id, f.title, f.severity, f.risk_score as "riskScore", a.name as "assetName" from findings f join assets a on a.id = f.asset_id
     where f.org_id = $1 and f.status = 'open' order by f.risk_score desc, f.title limit $2`, [orgId, topN]);
  const accepted = (await q.query("select count(*)::int as n from findings where org_id = $1 and status = 'accepted' and accepted_until <= now() + interval '14 days'", [orgId])).rows[0].n as number;
  const sups = (await q.query("select count(*)::int as n from suppressions where org_id = $1 and expires_at is not null and expires_at <= now() + interval '14 days'", [orgId])).rows[0].n as number;

  const window = hours === 24 ? "in the last day" : hours === 168 ? "in the last week" : `in the last ${hours} hours`;
  const lines: string[] = [];
  lines.push(openTotal === 0 ? "There are no open findings." : `${plural(openTotal, "open finding")}: ${open.critical} critical, ${open.high} high, ${open.medium} medium, ${open.low} low.`);
  if (totalNew) lines.push(`${plural(totalNew, "new finding")} ${window}${fresh.length < totalNew ? `, the ${fresh.length} highest are listed` : ""}.`);
  else lines.push(`No new findings ${window}.`);
  if (fixed) lines.push(`${plural(fixed, "finding")} ${fixed === 1 ? "was" : "were"} fixed ${window}.`);
  if (scoreChange !== null && scoreChange !== 0) lines.push(`The posture score ${scoreChange > 0 ? "rose" : "fell"} by ${Math.abs(scoreChange)} to ${score}.`);
  else if (score !== null) lines.push(`The posture score is ${score}${scoreChange === 0 ? ", unchanged" : ""}.`);
  if (accepted) lines.push(`${plural(accepted, "accepted risk")} ${accepted === 1 ? "is" : "are"} due for review within 14 days.`);
  if (sups) lines.push(`${plural(sups, "rule suppression")} ${sups === 1 ? "ends" : "end"} within 14 days; the findings will reopen.`);
  const headline = open.critical > 0 ? `${plural(open.critical, "critical finding")} open${totalNew ? `, ${totalNew} new` : ""}` : totalNew ? `${plural(totalNew, "new finding")} ${window}` : openTotal ? `${plural(openTotal, "open finding")}, nothing new ${window}` : "All clear";
  return { hours, since: sinceIso, hasData: true, score, scoreChange, open, newFindings: { total: totalNew, items: fresh as unknown as Brief["newFindings"]["items"] }, fixed, topRisks: top as unknown as Brief["topRisks"], expiring: { acceptedRisks: accepted, suppressions: sups }, headline, lines };
}

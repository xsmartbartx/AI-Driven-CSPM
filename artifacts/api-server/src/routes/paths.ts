import { Router } from "express";
import { analyzePaths, type Resource } from "@workspace/cspm-engine";
import { requireRole } from "../lib/http";

import { refreshSuppressions } from "../services/suppressions";

const r = Router();
const LIMIT = 2000;

/**
 * Attack paths for the organization, computed on request from what the scans found (no stored copy that could go stale).
 * "Current" assets: for a connected AWS account, exactly those its latest scan saw; for pasted configurations, those seen in
 * the last 30 days. Findings that already exist on the assets in a path are attached so the page can link to them.
 */
r.get("/attack-paths", requireRole("viewer"), async (req, res) => {
  await refreshSuppressions(req.db, req.auth!.orgId);
  const orgId = req.auth!.orgId;
  const { rows } = await req.db.query(
    `select a.type, a.name, a.environment, a.criticality, a.raw
     from assets a left join cloud_accounts c on c.id = a.account_id
     where a.org_id = $1 and (
       (a.account_id is not null and a.last_scan_id is not null and a.last_scan_id = c.last_scan_id)
       or (a.account_id is null and a.last_seen_at >= now() - interval '30 days'))
     order by a.type, a.name limit ${LIMIT + 1}`, [orgId]);
  const truncated = rows.length > LIMIT;
  const resources: Resource[] = rows.slice(0, LIMIT).map((x) => ({ ...(x.raw ?? {}), type: x.type, name: x.name, environment: x.environment, criticality: x.criticality }));
  const analysis = analyzePaths(resources);
  // never silently drop data: the paths that need the dropped assets would just be missing, with no hint why
  if (truncated) analysis.notes.unshift(`This organization has more than ${LIMIT} current assets; only the first ${LIMIT} (by type and name) were used, so some paths may be missing.`);

  const names = [...new Set(analysis.paths.flatMap((p) => [...p.nodes.filter((n) => !["internet", "account"].includes(n.kind)).map((n) => n.name), ...p.edges.flatMap((e) => [e.fix.asset, ...e.assets])]))];
  const found = names.length
    ? (await req.db.query(
        `select f.id, f.title, f.severity, f.risk_score as "riskScore", a.name as "assetName"
         from findings f join assets a on a.id = f.asset_id where f.org_id = $1 and f.status = 'open' and a.name = any($2::text[]) order by f.risk_score desc`, [orgId, names])).rows
    : [];
  const byAsset = new Map<string, typeof found>();
  for (const f of found) byAsset.set(f.assetName, [...(byAsset.get(f.assetName) ?? []), f]);
  const paths = analysis.paths.map((p) => {
    const assets = new Set([...p.nodes.map((n) => n.name), ...p.edges.flatMap((e) => [e.fix.asset, ...e.assets])]);
    return { ...p, findings: [...assets].flatMap((a) => (byAsset.get(a) ?? []).slice(0, 3)).slice(0, 8) };
  });
  res.json({ ...analysis, paths, assetCount: resources.length });
});

export default r;

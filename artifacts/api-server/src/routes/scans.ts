import { Router } from "express";
import { z } from "zod";
import { rateLimit } from "../lib/ratelimit";
import { parse, requireRole, uuidParam } from "../lib/http";
import { demoScan, runScan, overview } from "../services/scans";
import { notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { notifyScan } from "../services/notifications";
import { refreshSuppressions } from "../services/suppressions";

const r = Router();
const body = z.object({ config: z.unknown() });

r.post("/demo/scan", rateLimit("demo", 5, 3600_000), (req, res) => {
  res.json(demoScan(parse(body, req.body).config));
});

r.post("/scans", requireRole("analyst"), async (req, res) => {
  const { alerts, ...result } = await runScan(req.db, req.auth!, parse(body, req.body).config);
  await audit(req, "scan.run", result.id);
  void notifyScan({ db: req.sysDb, mailer: req.mailer, fetchImpl: req.notifyFetch }, req.auth!.orgId, alerts); // after the response is decided; never fails the scan
  res.status(201).json(result);
});

r.get("/scans", requireRole("viewer"), async (req, res) => {
  const { rows } = await req.db.query(
    `select s.id, s.source, s.status, s.resource_count as "resourceCount", s.finding_count as "findingCount", s.score, s.counts, s.created_at as "createdAt", u.email as "createdBy"
     from scans s left join users u on u.id = s.created_by where s.org_id = $1 order by s.created_at desc limit 100`, [req.auth!.orgId]);
  res.json({ items: rows });
});

r.get("/scans/:id", requireRole("viewer"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const { rows } = await req.db.query(
    `select s.id, s.source, s.status, s.resource_count as "resourceCount", s.finding_count as "findingCount", s.score, s.counts, s.created_at as "createdAt" from scans s where s.id = $1 and s.org_id = $2`, [id, req.auth!.orgId]);
  if (!rows[0]) throw notFound("Scan not found");
  const f = await req.db.query(
    `select f.id, f.title, f.severity, f.risk_score as "riskScore", f.status, a.name as "assetName", a.type as "assetType"
     from findings f join assets a on a.id = f.asset_id where f.scan_id = $1 and f.org_id = $2 order by f.risk_score desc`, [id, req.auth!.orgId]);
  res.json({ ...rows[0], findings: f.rows });
});

r.get("/overview", requireRole("viewer"), async (req, res) => {
  await refreshSuppressions(req.db, req.auth!.orgId);
  const days = ({ "30d": 30, "3m": 90, "6m": 180 } as Record<string, number>)[String(req.query["range"] ?? "30d")] ?? 30;
  res.json(await overview(req.db, req.auth!.orgId, days));
});

export default r;

import { Router } from "express";
import { z } from "zod";
import { complianceFrom, ruleById, explain } from "@workspace/cspm-engine";
import { PLANS } from "../config";
import { parse, requireRole, uuidParam } from "../lib/http";
import { bad, HttpError, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { explainFinding } from "../services/ai";
import { period, usageOf } from "../services/scans";

const r = Router();
const COLS = `f.id, f.title, f.severity, f.risk_score as "riskScore", f.status, f.rule_id as "ruleId", f.first_seen_at as "firstSeenAt", f.last_seen_at as "lastSeenAt",
  a.name as "assetName", a.type as "assetType", a.provider, a.environment`;
const esc = (s: string) => s.replace(/[\\%_]/g, (m) => "\\" + m);

r.get("/findings", requireRole("viewer"), async (req, res) => {
  const q = parse(z.object({
    q: z.string().max(100).optional(), severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    status: z.enum(["open", "fixed", "accepted", "false_positive", "all"]).default("open"),
    type: z.string().max(50).optional(), sort: z.enum(["risk", "recent"]).default("risk"),
    page: z.coerce.number().int().min(1).default(1), pageSize: z.coerce.number().int().min(1).max(100).default(25),
  }), req.query);
  const where = ["f.org_id = $1"]; const p: unknown[] = [req.auth!.orgId];
  const add = (sql: string, v: unknown) => { p.push(v); where.push(sql.replace("?", `$${p.length}`)); };
  if (q.status !== "all") add("f.status = ?", q.status);
  if (q.severity) add("f.severity = ?", q.severity);
  if (q.type) add("a.type = ?", q.type);
  if (q.q) { p.push(`%${esc(q.q)}%`); where.push(`(f.title ilike $${p.length} escape '\\' or a.name ilike $${p.length} escape '\\')`); }
  const w = where.join(" and ");
  const order = q.sort === "risk" ? "f.risk_score desc, f.created_at" : "f.last_seen_at desc";
  const total = await req.db.query(`select count(*)::int as n from findings f join assets a on a.id = f.asset_id where ${w}`, p);
  const rows = await req.db.query(`select ${COLS} from findings f join assets a on a.id = f.asset_id where ${w} order by ${order} limit ${q.pageSize} offset ${(q.page - 1) * q.pageSize}`, p);
  res.json({ items: rows.rows, total: total.rows[0].n, page: q.page, pageSize: q.pageSize });
});

r.get("/findings/:id", requireRole("viewer"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const { rows } = await req.db.query(
    `select ${COLS}, f.evidence, f.remediation, f.frameworks, f.status_reason as "statusReason", f.accepted_until as "acceptedUntil", a.id as "assetId", a.criticality, a.owner
     from findings f join assets a on a.id = f.asset_id where f.id = $1 and f.org_id = $2`, [id, req.auth!.orgId]);
  if (!rows[0]) throw notFound("Finding not found");
  const brief = await req.db.query("select content, model, created_at as \"createdAt\" from ai_briefs where finding_id = $1 and org_id = $2 and kind = 'finding' order by created_at desc limit 1", [id, req.auth!.orgId]);
  const rule = ruleById(rows[0].ruleId);
  res.json({ ...rows[0], ruleBase: rule?.base ?? null, brief: brief.rows[0] ?? null, ruleExplanation: explain({ ...rows[0], resourceName: rows[0].assetName, resourceType: rows[0].assetType } as any) });
});

r.patch("/findings/:id", requireRole("analyst"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const b = parse(z.object({
    status: z.enum(["open", "accepted", "false_positive"]), reason: z.string().trim().max(500).optional(), acceptedUntil: z.string().optional(),
  }), req.body);
  let until: Date | null = null;
  if (b.status !== "open" && (!b.reason || b.reason.length < 5)) throw bad("Give a reason (at least 5 characters)", "reason_required");
  if (b.status === "accepted") {
    until = b.acceptedUntil ? new Date(b.acceptedUntil) : null;
    if (!until || Number.isNaN(+until) || until <= new Date()) throw bad("Accepted risk needs an expiry date in the future", "expiry_required");
    if (+until - Date.now() > 366 * 86400_000) throw bad("Accepted risk can last at most one year", "expiry_too_long");
  }
  const { rows } = await req.db.query(
    `update findings set status=$3, status_reason=$4, accepted_until=$5, updated_at=now() where id=$1 and org_id=$2 and status <> 'fixed' returning id`,
    [id, req.auth!.orgId, b.status, b.status === "open" ? null : b.reason, until]);
  if (!rows[0]) throw notFound("Finding not found, or already fixed");
  await audit(req, `finding.${b.status}`, id);
  res.json({ ok: true });
});

r.post("/findings/:id/explain", requireRole("analyst"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const orgId = req.auth!.orgId;
  const cached = await req.db.query("select content, model, created_at as \"createdAt\" from ai_briefs where finding_id = $1 and org_id = $2 and kind = 'finding' order by created_at desc limit 1", [id, orgId]);
  const { rows } = await req.db.query(
    `select f.rule_id as "ruleId", f.title, f.risk_score as "riskScore", f.evidence, f.remediation, f.frameworks, a.name as "resourceName", a.type as "resourceType"
     from findings f join assets a on a.id = f.asset_id where f.id = $1 and f.org_id = $2`, [id, orgId]);
  if (!rows[0]) throw notFound("Finding not found");
  if (cached.rows[0] && !req.body?.refresh) return void res.json(cached.rows[0]);
  // Reserve the quota BEFORE the slow, paid call: lock the org row, check, insert. Concurrent calls queue on the lock,
  // so they cannot all pass the check. A failed generation gives the reservation back.
  const reservation: string = await req.db.tx(async (q) => {
    await q.query("select 1 from organizations where id = $1 for update", [orgId]);
    const u = await usageOf(q, orgId);
    if (u.ai.used >= u.ai.limit) throw new HttpError(402, "quota_exceeded", `You have used all ${PLANS[u.plan].ai} AI explanations on the ${u.planLabel} plan this month.`);
    return (await q.query("insert into usage_events (org_id, kind, period) values ($1,'ai',$2) returning id", [orgId, period()])).rows[0]!.id;
  });
  await req.db.release(); // do not hold a pooled connection during the slow external call
  let out;
  try {
    out = await explainFinding(rows[0] as any);
    await req.db.query("insert into ai_briefs (org_id, finding_id, kind, content, model) values ($1,$2,'finding',$3,$4)", [orgId, id, out.text, out.model]);
  } catch (e) {
    await req.db.query("delete from usage_events where id = $1", [reservation]).catch(() => {});
    throw e;
  }
  res.json({ content: out.text, model: out.model, createdAt: new Date().toISOString() });
});

r.get("/assets", requireRole("viewer"), async (req, res) => {
  const q = parse(z.object({ type: z.string().max(50).optional(), q: z.string().max(100).optional() }), req.query);
  const p: unknown[] = [req.auth!.orgId]; let w = "a.org_id = $1";
  if (q.type) { p.push(q.type); w += ` and a.type = $${p.length}`; }
  if (q.q) { p.push(`%${esc(q.q)}%`); w += ` and a.name ilike $${p.length} escape '\\'`; }
  const { rows } = await req.db.query(
    `select a.id, a.name, a.type, a.provider, a.environment, a.criticality, a.owner, a.last_seen_at as "lastSeenAt",
       count(f.id) filter (where f.status = 'open')::int as "openFindings", coalesce(max(f.risk_score) filter (where f.status = 'open'), 0)::int as "maxRisk"
     from assets a left join findings f on f.asset_id = a.id where ${w} group by a.id order by "maxRisk" desc, a.name limit 500`, p);
  const { rows: types } = await req.db.query("select type, count(*)::int as n from assets where org_id = $1 group by type order by n desc", [req.auth!.orgId]);
  res.json({ items: rows, types });
});

r.get("/compliance", requireRole("viewer"), async (req, res) => {
  const { rows } = await req.db.query("select distinct rule_id from findings where org_id = $1 and status = 'open'", [req.auth!.orgId]);
  const frameworks = complianceFrom(rows.map((x) => x.rule_id));
  const titles = Object.fromEntries(frameworks.flatMap((f) => f.failedControls.flatMap((c) => c.ruleIds)).map((id) => [id, ruleById(id)?.title ?? id]));
  res.json({ frameworks, ruleTitles: titles, note: "Control IDs are indicative mappings from this scanner's rules. They are not an audit result. Check them against the benchmark version you are audited against." });
});

r.get("/reports/summary.csv", requireRole("viewer"), async (req, res) => {
  const { rows } = await req.db.query(
    `select f.title, f.severity, f.risk_score, f.status, a.type, a.name, a.environment, f.first_seen_at from findings f join assets a on a.id = f.asset_id where f.org_id = $1 order by f.risk_score desc`, [req.auth!.orgId]);
  // cells starting with = + - @ would execute as formulas in spreadsheets
  const cell = (v: unknown) => { let s = v instanceof Date ? v.toISOString() : String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const lines = [["Finding", "Severity", "Risk", "Status", "Asset type", "Asset", "Environment", "First seen"].map(cell).join(",")];
  for (const x of rows) lines.push([x.title, x.severity, x.risk_score, x.status, x.type, x.name, x.environment, x.first_seen_at].map(cell).join(","));
  res.setHeader("content-type", "text/csv; charset=utf-8").setHeader("content-disposition", 'attachment; filename="cspm-findings.csv"').send(lines.join("\r\n"));
});

export default r;

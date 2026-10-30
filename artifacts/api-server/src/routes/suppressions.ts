import { Router } from "express";
import { z } from "zod";
import { RULES, ruleById } from "@workspace/cspm-engine";
import { parse, requireRole, uuidParam } from "../lib/http";
import { bad, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { lockOrg, MAX_SUPPRESSIONS, reconcile, refreshSuppressions } from "../services/suppressions";

const r = Router();

r.get("/suppressions", requireRole("analyst"), async (req, res) => {
  await refreshSuppressions(req.db, req.auth!.orgId);
  const { rows } = await req.db.query(
    `select s.id, s.rule_id as "ruleId", s.asset_id as "assetId", a.name as "assetName", s.environment, s.reason, s.expires_at as "expiresAt", s.created_at as "createdAt", u.email as "createdBy",
            (select count(*)::int from findings f where f.suppression_id = s.id) as suppressed
     from suppressions s left join assets a on a.id = s.asset_id left join users u on u.id = s.created_by where s.org_id = $1 order by s.created_at desc`, [req.auth!.orgId]);
  res.json({ items: rows.map((s) => ({ ...s, ruleTitle: ruleById(s.ruleId)?.title ?? s.ruleId })) });
});

r.post("/suppressions", requireRole("admin"), async (req, res) => {
  const orgId = req.auth!.orgId;
  const b = parse(z.object({
    ruleId: z.string().refine((id) => RULES.some((x) => x.id === id), "unknown rule"),
    assetId: z.string().optional(),
    environment: z.enum(["production", "staging", "development"]).optional(),
    reason: z.string().trim().min(5, "Give a reason (at least 5 characters)").max(500),
    expiresInDays: z.number().int().min(1).max(365).nullable().default(null),
  }), req.body);
  if (b.assetId && b.environment) throw bad("Choose one scope: a single asset, or an environment, or everywhere", "scope_conflict");
  const rule = ruleById(b.ruleId)!;
  const assetId = b.assetId ? uuidParam(b.assetId) : null;
  const { id, suppressed } = await req.db.tx(async (q) => {
    await lockOrg(q, orgId); // scans and every other change to suppressions wait here
    if (assetId) {
      const { rows } = await q.query("select type from assets where id = $1 and org_id = $2", [assetId, orgId]);
      if (!rows[0]) throw notFound("Asset not found");
      if (rows[0].type !== rule.resourceType) throw bad("That rule does not apply to this kind of asset", "rule_asset_mismatch");
    }
    const n = (await q.query("select count(*)::int as n from suppressions where org_id = $1", [orgId])).rows[0].n;
    if (n >= MAX_SUPPRESSIONS) throw bad(`At most ${MAX_SUPPRESSIONS} suppressions per organization`, "too_many_suppressions");
    const { rows } = await q.query(
      `insert into suppressions (org_id, rule_id, asset_id, environment, reason, expires_at, created_by)
       values ($1,$2,$3,$4,$5, case when $6::int is null then null else now() + make_interval(days => $6::int) end, $7) returning id`,
      [orgId, b.ruleId, assetId, b.environment ?? null, b.reason, b.expiresInDays, req.auth!.userId]);
    await reconcile(q, orgId);
    const linked = await q.query("select count(*)::int as n from findings where suppression_id = $1", [rows[0].id]);
    return { id: rows[0].id as string, suppressed: linked.rows[0].n as number };
  });
  await audit(req, "suppression.created", `${b.ruleId} (${assetId ? "one asset" : b.environment ?? "everywhere"}), ${suppressed} findings`);
  res.status(201).json({ id, suppressed });
});

r.delete("/suppressions/:id", requireRole("admin"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const orgId = req.auth!.orgId;
  const out = await req.db.tx(async (q) => {
    await lockOrg(q, orgId);
    const { rows } = await q.query("select rule_id from suppressions where id = $1 and org_id = $2", [id, orgId]);
    if (!rows[0]) throw notFound("Suppression not found");
    const ids = (await q.query("select id from findings where suppression_id = $1", [id])).rows.map((x) => x.id as string);
    await reconcile(q, orgId, id); // findings another suppression still covers move to it; the rest reopen
    await q.query("delete from suppressions where id = $1 and org_id = $2", [id, orgId]);
    const reopened = ids.length ? (await q.query("select count(*)::int as n from findings where id = any($1::uuid[]) and status = 'open'", [ids])).rows[0].n as number : 0;
    return { rule: rows[0].rule_id as string, had: ids.length, reopened };
  });
  await audit(req, "suppression.removed", `${out.rule}, ${out.had} findings released`);
  res.json({ ok: true, reopened: out.reopened });
});

export default r;

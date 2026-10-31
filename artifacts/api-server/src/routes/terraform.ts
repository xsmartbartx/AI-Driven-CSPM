import express, { Router } from "express";
import { z } from "zod";
import { evaluate, fromTerraformPlan, postureScore, type Severity } from "@workspace/cspm-engine";
import { parse, requireRole } from "../lib/http";
import { bad } from "../lib/errors";
import { rateLimit } from "../lib/ratelimit";
import { activeSuppressions, refreshSuppressions } from "../services/suppressions";

const r = Router();
const RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/**
 * Checks a Terraform plan (terraform show -json) before it is applied. Nothing is stored and no scan is used: it is a
 * check, not a scan of the account. Read-only API keys can call it, so a CI job needs no more than that.
 * Rule suppressions that are not tied to one asset (everywhere, or an environment read from the resource's tags) are honoured.
 */
r.post("/terraform/check", requireRole("viewer"), rateLimit("tf-check", 60, 3600_000, (q) => q.auth?.orgId ?? "?"), express.json({ limit: "8mb" }), async (req, res) => {
  const b = parse(z.object({ plan: z.unknown(), failOn: z.enum(["critical", "high", "medium", "low"]).default("high") }), req.body);
  const t = fromTerraformPlan(b.plan);
  if (t.errors.length) throw bad(t.errors.join(" "), "invalid_plan");
  await refreshSuppressions(req.db, req.auth!.orgId);
  const sup = (await activeSuppressions(req.db, req.auth!.orgId)).filter((s) => !s.assetId);
  const env = new Map(t.resources.map((x) => [x.name, x.environment as string | undefined]));
  const { findings } = evaluate(t.resources);
  let suppressed = 0;
  const kept = findings.filter((f) => {
    const e = env.get(f.resourceName);
    const hit = sup.find((s) => s.ruleId === f.ruleId && (!s.environment || s.environment === e));
    if (hit) suppressed++;
    return !hit;
  });
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  kept.forEach((f) => counts[f.severity]++);
  res.json({
    resourceCount: t.resources.length, counts, score: postureScore(counts), suppressed,
    failOn: b.failOn, fail: kept.some((f) => RANK[f.severity] >= RANK[b.failOn]),
    findings: kept.map((f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, riskScore: f.riskScore, address: f.resourceName, resourceType: f.resourceType, evidence: f.evidence, remediation: f.remediation })),
    skipped: t.skipped, notes: t.notes,
  });
});

export default r;

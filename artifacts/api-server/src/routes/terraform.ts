import express, { Router } from "express";
import { z } from "zod";
import { fromTerraformPlan } from "@workspace/cspm-engine";
import { parse, requireRole } from "../lib/http";
import { bad } from "../lib/errors";
import { rateLimit } from "../lib/ratelimit";
import { refreshSuppressions } from "../services/suppressions";
import { checkResources } from "../services/checks";

const r = Router();

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
  const result = await checkResources(req.db, req.auth!.orgId, t.resources, b.failOn);
  res.json({ ...result, skipped: t.skipped, notes: t.notes });
});

export default r;

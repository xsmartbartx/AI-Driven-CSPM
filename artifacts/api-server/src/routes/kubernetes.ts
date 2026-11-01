import express, { Router } from "express";
import { z } from "zod";
import { fromKubernetesManifests } from "@workspace/cspm-engine";
import { parse, requireRole } from "../lib/http";
import { bad } from "../lib/errors";
import { rateLimit } from "../lib/ratelimit";
import { refreshSuppressions } from "../services/suppressions";
import { checkResources } from "../services/checks";

const r = Router();

/**
 * Checks Kubernetes workload manifests (as JSON) before they are deployed, with the same rules as a scan of pasted
 * resources. Nothing is stored and no scan is used. Read-only API keys can call it.
 */
r.post("/kubernetes/check", requireRole("viewer"), rateLimit("k8s-check", 60, 3600_000, (q) => q.auth?.orgId ?? "?"), express.json({ limit: "8mb" }), async (req, res) => {
  const b = parse(z.object({ manifests: z.unknown(), failOn: z.enum(["critical", "high", "medium", "low"]).default("high") }), req.body);
  const k = fromKubernetesManifests(b.manifests);
  if (k.errors.length) throw bad(k.errors.join(" "), "invalid_manifests");
  await refreshSuppressions(req.db, req.auth!.orgId);
  const result = await checkResources(req.db, req.auth!.orgId, k.resources, b.failOn);
  res.json({ ...result, skipped: k.skipped, notes: k.notes });
});

export default r;

import { Router } from "express";
import { z } from "zod";
import { parse, requireRole } from "../lib/http";
import { buildBrief } from "../services/brief";
import { refreshSuppressions } from "../services/suppressions";

const r = Router();

r.get("/brief", requireRole("viewer"), async (req, res) => {
  const q = parse(z.object({ hours: z.coerce.number().int().min(1).max(720).default(24) }), req.query);
  await refreshSuppressions(req.db, req.auth!.orgId);
  res.json(await buildBrief(req.db, req.auth!.orgId, q.hours));
});

export default r;

import type { Request } from "express";
import type { Queryable } from "@workspace/db";
export async function audit(req: Request, action: string, target?: string, q: Queryable = req.db, auth = req.auth) {
  if (!auth) return;
  await q.query("insert into audit_events (org_id, actor_id, action, target, ip) values ($1,$2,$3,$4,$5)", [auth.orgId, auth.userId, action, target ?? null, req.ip ?? null]);
}

import type { Request } from "express";
import type { Queryable } from "@workspace/db";
/** Audit entry without an HTTP request (background jobs). */
export async function auditEvent(q: Queryable, orgId: string, actorId: string | null, action: string, target?: string) {
  await q.query("insert into audit_events (org_id, actor_id, action, target) values ($1,$2,$3,$4)", [orgId, actorId, action, target ?? null]);
}
export async function audit(req: Request, action: string, target?: string, q: Queryable = req.db, auth = req.auth) {
  if (!auth) return;
  await q.query("insert into audit_events (org_id, actor_id, action, target, ip) values ($1,$2,$3,$4,$5)", [auth.orgId, auth.userId, action, target ?? null, req.ip ?? null]);
}

import type { Request, Response, NextFunction } from "express";
import { z, type ZodTypeAny } from "zod";
import { config } from "../config";
import { bad, forbidden, unauthorized } from "./errors";
import { ROLE_RANK, type Auth, type Role } from "./context";
import { sha256, signJwt, verifyJwt } from "./crypto";

export const COOKIE = "cspm_session";
const SESSION_TTL = 7 * 24 * 3600;

export function parse<S extends ZodTypeAny>(schema: S, data: unknown): z.infer<S> {
  const r = schema.safeParse(data);
  if (!r.success) throw bad(r.error.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; "), "validation_error");
  return r.data;
}

export function setSession(res: Response, userId: string, orgId: string, version = 0) {
  const token = signJwt({ sub: userId, org: orgId, v: version }, config.jwtSecret, SESSION_TTL);
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: "lax", secure: config.prod, maxAge: SESSION_TTL * 1000, path: "/" });
}
export const clearSession = (res: Response) => void res.clearCookie(COOKIE, { httpOnly: true, sameSite: "lax", secure: config.prod, path: "/" });

/** Cookie sessions must prove they come from our own front ends: allowed Origin + custom header. */
function csrfOk(req: Request) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return true;
  const origin = req.headers.origin;
  if (origin && !config.origins.includes(origin)) return false;
  return req.headers["x-csrf"] === "1";
}

export async function loadAuth(req: Request): Promise<Auth | null> {
  const bearer = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.slice(7).trim() : "";
  if (bearer.startsWith("cspm_")) {
    const { rows } = await req.db.query("select id, org_id from api_keys where key_hash = $1", [sha256(bearer)]);
    if (!rows[0]) return null;
    void req.db.query("update api_keys set last_used_at = now() where id = $1", [rows[0].id]).catch(() => {});
    return { userId: null, orgId: rows[0].org_id, role: "analyst", email: null, via: "key" };
  }
  const token = (req.headers.cookie ?? "").split(/;\s*/).map((c) => c.split("=")).find(([k]) => k === COOKIE)?.[1];
  if (!token) return null;
  const p = verifyJwt<{ sub: string; org: string; v?: number }>(decodeURIComponent(token), config.jwtSecret);
  if (!p) return null;
  if (!csrfOk(req)) throw forbidden("Cross-site request blocked");
  // role is read from the DB every request, so removing a member takes effect immediately
  const { rows } = await req.db.query(
    "select m.role, u.email, u.token_version as v from members m join users u on u.id = m.user_id where m.user_id = $1 and m.org_id = $2", [p.sub, p.org]);
  if (!rows[0] || rows[0].v !== (p.v ?? 0)) return null;
  return { userId: p.sub, orgId: p.org, role: rows[0].role, email: rows[0].email, via: "session" };
}

/** Sets req.auth. Every data query downstream takes req.auth.orgId, never an org id from the client. */
export function requireRole(min: Role) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    const a = await loadAuth(req);
    if (!a) throw unauthorized();
    if (ROLE_RANK[a.role] < ROLE_RANK[min]) throw forbidden();
    req.auth = a;
    req.db = req.sysDb.scoped(a.orgId); // from here on every query runs under row level security for this organization
    next();
  };
}
export const uuidParam = (v: unknown) => {
  if (typeof v !== "string" || !/^[0-9a-f-]{36}$/i.test(v)) throw bad("Invalid id");
  return v;
};

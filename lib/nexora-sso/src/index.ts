// NEXORA -> NEXORA CSPM single sign-on. Runs on the Nexora console SERVER only (never in a browser):
// it needs the shared secret. Copy this file as is; it uses only Node built-ins.
//
//   const url = createCspmSignInUrl({
//     secret: process.env.CSPM_SSO_SECRET!,            // same value as SSO_SECRET on the CSPM API
//     apiUrl: "https://api.cspm.onenexora.com",
//     user: { id: session.userId, email: session.email, name: session.name, orgId: org.id, orgName: org.name, role: "viewer" },
//   });
//   return Response.redirect(url, 302);                  // from a route that first checks the user is signed in to Nexora
//
// What the CSPM API enforces on its side (so do not rely on this file for security): HS256 signature, expiry at most
// 10 minutes ahead, a one-time `jti` (a replayed link is refused), the role claim capped at "admin", and the first
// user of a Nexora organization becoming its CSPM owner.
import { createHmac, randomUUID } from "node:crypto";

export type CspmRole = "admin" | "analyst" | "viewer";

export interface CspmUser {
  /** Stable Nexora user id. */
  id: string;
  /** Must be an address Nexora has verified: CSPM trusts it and marks it confirmed. */
  email: string;
  name?: string;
  /** Stable Nexora organization id. All users with the same orgId land in the same CSPM organization. */
  orgId: string;
  orgName?: string;
  /** Default "viewer". "owner" is never granted through this link: the first user of a new organization becomes owner. */
  role?: CspmRole;
}

const b64u = (v: string | object) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

/** Signed token only. Prefer createCspmSignInUrl. */
export function createCspmToken(opts: { secret: string; user: CspmUser; ttlSeconds?: number; now?: () => number }): string {
  const { secret, user } = opts;
  if (!secret || secret.length < 32) throw new Error("secret must be at least 32 characters");
  if (!user.id || !user.orgId || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(user.email)) throw new Error("user needs id, orgId and a valid email");
  const ttl = Math.min(Math.max(opts.ttlSeconds ?? 120, 10), 600); // CSPM rejects tokens valid for more than 10 minutes
  const now = Math.floor((opts.now?.() ?? Date.now()) / 1000);
  const head = b64u({ alg: "HS256", typ: "JWT" });
  const body = b64u({
    sub: user.id, email: user.email, name: user.name, org: user.orgId, orgName: user.orgName,
    role: user.role ?? "viewer", jti: randomUUID(), iat: now, exp: now + ttl,
  });
  const sig = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

export function createCspmSignInUrl(opts: { secret: string; apiUrl: string; user: CspmUser; ttlSeconds?: number }): string {
  const base = opts.apiUrl.replace(/\/+$/, "");
  if (!/^https:\/\//.test(base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(base)) throw new Error("apiUrl must be https (http only for localhost)");
  return `${base}/api/auth/sso?token=${createCspmToken(opts)}`;
}

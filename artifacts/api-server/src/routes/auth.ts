import { Router } from "express";
import { z } from "zod";
import { config } from "../config";
import { conflict, forbidden, HttpError, unauthorized, bad } from "../lib/errors";
import { hashPassword, randomToken, sha256, verifyJwt, verifyPassword } from "../lib/crypto";
import { clearSession, loadAuth, parse, setSession } from "../lib/http";
import { rateLimit } from "../lib/ratelimit";
import { audit } from "../lib/audit";
import { resetEmail, verifyEmail } from "../services/mail-templates";
import type { Queryable } from "@workspace/db";

/** One-time email token: only its hash is stored, the token exists only in the email. */
async function issueEmailToken(q: Queryable, userId: string, kind: "reset" | "verify", ttl: string) {
  await q.query("update email_tokens set used_at = now() where user_id = $1 and kind = $2 and used_at is null", [userId, kind]); // newest link wins
  const token = randomToken(32);
  await q.query(`insert into email_tokens (user_id, kind, token_hash, expires_at) values ($1,$2,$3, now() + interval '${ttl}')`, [userId, kind, sha256(token)]);
  return token;
}
const byEmailKey = (req: { body?: { email?: unknown } }) => String(req.body?.email ?? "").toLowerCase().slice(0, 254);

const r = Router();
const email = z.string().trim().toLowerCase().email().max(254);
const password = z.string().min(10, "Use at least 10 characters").max(200);

const meOf = async (req: any, userId: string, orgId: string) => {
  const { rows } = await req.db.query(
    `select u.id as "userId", u.email, u.name, (u.password_hash is not null) as "hasPassword", (u.email_verified_at is not null) as "emailVerified", o.id as "orgId", o.name as "orgName", o.plan, m.role
     from members m join users u on u.id = m.user_id join organizations o on o.id = m.org_id where m.user_id = $1 and m.org_id = $2`, [userId, orgId]);
  const x = rows[0];
  return { user: { id: x.userId, email: x.email, name: x.name, hasPassword: x.hasPassword, emailVerified: x.emailVerified }, org: { id: x.orgId, name: x.orgName, plan: x.plan }, role: x.role };
};

r.post("/auth/signup", rateLimit("signup", 10, 3600_000), async (req, res) => {
  const b = parse(z.object({ email, password, name: z.string().trim().max(100).optional(), orgName: z.string().trim().min(1).max(100).optional() }), req.body);
  const exists = await req.db.query("select 1 from users where email = $1", [b.email]);
  if (exists.rows.length) throw conflict("An account with this email already exists. Sign in instead.", "email_taken");
  const hash = await hashPassword(b.password);
  const ids = await req.db.tx(async (q) => {
    const u = await q.query("insert into users (email, name, password_hash) values ($1,$2,$3) returning id", [b.email, b.name ?? null, hash]);
    const o = await q.query("insert into organizations (name) values ($1) returning id", [b.orgName ?? `${b.name ?? b.email.split("@")[0]}'s organization`]);
    await q.query("insert into members (org_id, user_id, role) values ($1,$2,'owner')", [o.rows[0].id, u.rows[0].id]);
    return { userId: u.rows[0].id as string, orgId: o.rows[0].id as string };
  });
  setSession(res, ids.userId, ids.orgId);
  const vt = await issueEmailToken(req.db, ids.userId, "verify", "24 hours");
  await req.mailer.send(verifyEmail(b.email, vt)); // a failed send never fails signup; the user can resend from the banner
  await audit(req, "auth.signup", b.email, req.db, { userId: ids.userId, orgId: ids.orgId, role: "owner", email: b.email, via: "session" });
  res.status(201).json(await meOf(req, ids.userId, ids.orgId));
});

r.post("/auth/login", rateLimit("login", 10, 15 * 60_000), async (req, res) => {
  const b = parse(z.object({ email, password: z.string().min(1).max(200) }), req.body);
  const { rows } = await req.db.query("select id, password_hash, token_version from users where email = $1", [b.email]);
  const ok = await verifyPassword(b.password, rows[0]?.password_hash ?? null);
  if (!rows[0] || !ok) throw unauthorized("Email or password is incorrect");
  const m = await req.db.query("select org_id, role from members where user_id = $1 order by created_at limit 1", [rows[0].id]);
  if (!m.rows[0]) throw forbidden("This account does not belong to an organization");
  setSession(res, rows[0].id, m.rows[0].org_id, rows[0].token_version);
  await audit(req, "auth.login", b.email, req.db, { userId: rows[0].id, orgId: m.rows[0].org_id, role: m.rows[0].role, email: b.email, via: "session" });
  res.json(await meOf(req, rows[0].id, m.rows[0].org_id));
});

r.post("/auth/logout", (_req, res) => { clearSession(res); res.json({ ok: true }); });

r.get("/auth/me", async (req, res) => {
  const a = await loadAuth(req);
  if (!a || !a.userId) throw unauthorized();
  res.json(await meOf(req, a.userId, a.orgId));
});

/** Nexora handoff: onenexora.com signs a short-lived token with SSO_SECRET and sends the user here. */
r.get("/auth/sso", rateLimit("sso", 30, 60_000), async (req, res) => {
  if (!config.ssoSecret) throw new HttpError(503, "sso_disabled", "Single sign-on is not configured");
  const c = verifyJwt<{ sub: string; email: string; name?: string; org: string; orgName?: string; role?: string; jti?: string; exp: number }>(String(req.query["token"] ?? ""), config.ssoSecret);
  if (!c || typeof c.sub !== "string" || typeof c.org !== "string" || !z.string().email().safeParse(c.email).success) throw unauthorized("Invalid or expired sign-in link");
  if (c.exp - Date.now() / 1000 > 600) throw unauthorized("Sign-in link is valid for too long");
  if (typeof c.jti !== "string" || c.jti.length < 8) throw unauthorized("Invalid sign-in link");
  // one-time use: a replayed link is rejected
  await req.db.query("delete from sso_tokens where expires_at < now()");
  const fresh = await req.db.query("insert into sso_tokens (jti, expires_at) values ($1, to_timestamp($2)) on conflict do nothing returning jti", [c.jti, c.exp]);
  if (!fresh.rows[0]) throw unauthorized("This sign-in link was already used");
  const role = ["admin", "analyst", "viewer"].includes(c.role ?? "") ? (c.role as string) : "viewer";
  const em = c.email.toLowerCase();
  const ids = await req.db.tx(async (q) => {
    let u = (await q.query("select id from users where nexora_user_id = $1", [c.sub])).rows[0]
      ?? (await q.query("select id from users where email = $1", [em])).rows[0];
    // Nexora has already verified this address
    if (u) await q.query("update users set nexora_user_id = $2, email_verified_at = coalesce(email_verified_at, now()), updated_at = now() where id = $1", [u.id, c.sub]);
    else u = (await q.query("insert into users (email, name, nexora_user_id, email_verified_at) values ($1,$2,$3, now()) returning id", [em, c.name ?? null, c.sub])).rows[0];
    let o = (await q.query("select id from organizations where nexora_org_id = $1", [c.org])).rows[0];
    let isNew = false;
    if (!o) { o = (await q.query("insert into organizations (name, nexora_org_id) values ($1,$2) returning id", [c.orgName ?? "Nexora organization", c.org])).rows[0]; isNew = true; }
    await q.query("insert into members (org_id, user_id, role) values ($1,$2,$3) on conflict (org_id, user_id) do nothing", [o.id, u.id, isNew ? "owner" : role]);
    const v = (await q.query("select token_version from users where id = $1", [u.id])).rows[0].token_version as number;
    return { userId: u.id as string, orgId: o.id as string, v };
  });
  setSession(res, ids.userId, ids.orgId, ids.v);
  await audit(req, "auth.sso", em, req.db, { userId: ids.userId, orgId: ids.orgId, role: "viewer", email: em, via: "session" });
  res.redirect(302, config.appUrl);
});

r.post("/invites/accept", rateLimit("invite", 20, 3600_000), async (req, res) => {
  const b = parse(z.object({ token: z.string().min(10).max(200), password: password.optional(), name: z.string().trim().max(100).optional() }), req.body);
  const { rows } = await req.db.query("select id, org_id, email, role, expires_at, accepted_at from invites where token_hash = $1", [sha256(b.token)]);
  const inv = rows[0];
  if (!inv || inv.accepted_at || new Date(inv.expires_at) < new Date()) throw bad("This invitation is invalid or has expired", "invite_invalid");
  const ex = (await req.db.query("select id, password_hash, token_version from users where email = $1", [inv.email])).rows[0];
  let userId: string;
  let version = 0; // an existing user may have signed out everywhere: the new cookie must carry their current version
  if (ex) {
    // A Nexora SSO user has no password: they accept through their own signed-in session. Everyone else proves the password.
    const cur = ex.password_hash ? null : await loadAuth(req);
    const viaSession = !ex.password_hash && cur?.userId === ex.id;
    if (!viaSession && (!b.password || !(await verifyPassword(b.password, ex.password_hash)))) throw unauthorized("Email or password is incorrect");
    userId = ex.id;
    version = ex.token_version;
  } else {
    if (!b.password) throw bad("Choose a password of at least 10 characters", "password_required");
    userId = (await req.db.query("insert into users (email, name, password_hash) values ($1,$2,$3) returning id", [inv.email, b.name ?? null, await hashPassword(b.password)])).rows[0].id;
  }
  await req.db.tx(async (q) => {
    await q.query("insert into members (org_id, user_id, role) values ($1,$2,$3) on conflict (org_id, user_id) do nothing", [inv.org_id, userId, inv.role]);
    await q.query("update invites set accepted_at = now() where id = $1", [inv.id]);
  });
  setSession(res, userId, inv.org_id, version);
  await audit(req, "team.invite_accepted", inv.email, req.db, { userId, orgId: inv.org_id, role: inv.role, email: inv.email, via: "session" });
  res.status(201).json(await meOf(req, userId, inv.org_id));
});

/** Always answers 202, whether or not the address has an account, so it cannot be used to find out who is registered. */
r.post("/auth/forgot-password", rateLimit("forgot-ip", 10, 3600_000), rateLimit("forgot-email", 3, 3600_000, byEmailKey), async (req, res) => {
  const b = parse(z.object({ email }), req.body);
  const u = (await req.db.query("select id from users where email = $1", [b.email])).rows[0];
  if (u) {
    const token = await issueEmailToken(req.db, u.id, "reset", "1 hour");
    void req.mailer.send(resetEmail(b.email, token)); // not awaited: response time must not reveal whether the account exists
  }
  res.status(202).json({ ok: true });
});

r.post("/auth/reset-password", rateLimit("reset", 20, 3600_000), async (req, res) => {
  const b = parse(z.object({ token: z.string().min(20).max(200), password }), req.body);
  const hash = await hashPassword(b.password);
  // single atomic statement: the token can be spent exactly once, even by two simultaneous requests
  const t = (await req.db.query("update email_tokens set used_at = now() where token_hash = $1 and kind = 'reset' and used_at is null and expires_at > now() returning user_id", [sha256(b.token)])).rows[0];
  if (!t) throw bad("This reset link is invalid or has expired. Ask for a new one.", "reset_invalid");
  // new password; bump token_version (signs out every session); proving mailbox access also verifies the address
  const u = (await req.db.query("update users set password_hash = $2, token_version = token_version + 1, email_verified_at = coalesce(email_verified_at, now()), updated_at = now() where id = $1 returning email", [t.user_id, hash])).rows[0];
  const m = (await req.db.query("select org_id, role from members where user_id = $1 order by created_at limit 1", [t.user_id])).rows[0];
  if (m) await audit(req, "auth.password_reset", u.email, req.db, { userId: t.user_id, orgId: m.org_id, role: m.role, email: u.email, via: "session" });
  res.json({ ok: true });
});

r.post("/auth/verify-email", rateLimit("verify", 30, 3600_000), async (req, res) => {
  const b = parse(z.object({ token: z.string().min(20).max(200) }), req.body);
  const t = (await req.db.query("update email_tokens set used_at = now() where token_hash = $1 and kind = 'verify' and used_at is null and expires_at > now() returning user_id", [sha256(b.token)])).rows[0];
  if (!t) throw bad("This confirmation link is invalid or has expired.", "verify_invalid");
  await req.db.query("update users set email_verified_at = coalesce(email_verified_at, now()), updated_at = now() where id = $1", [t.user_id]);
  res.json({ ok: true });
});

r.post("/auth/resend-verification", rateLimit("resend-verify", 5, 3600_000), async (req, res) => {
  const a = await loadAuth(req);
  if (!a?.userId) throw unauthorized();
  const u = (await req.db.query("select email, email_verified_at from users where id = $1", [a.userId])).rows[0];
  if (u.email_verified_at) return void res.json({ alreadyVerified: true });
  const token = await issueEmailToken(req.db, a.userId, "verify", "24 hours");
  const sent = await req.mailer.send(verifyEmail(u.email, token));
  res.status(202).json({ sent });
});

/** Sign out everywhere: invalidates every session of this user, on every device. */
r.post("/auth/logout-all", async (req, res) => {
  const a = await loadAuth(req);
  if (!a?.userId) throw unauthorized();
  await req.db.query("update users set token_version = token_version + 1, updated_at = now() where id = $1", [a.userId]);
  await audit(req, "auth.logout_all", undefined, req.db, a);
  clearSession(res);
  res.json({ ok: true });
});

/** Delete my account for real. Blocked while I am the only owner of an org that still has other members. */
r.delete("/auth/me", async (req, res) => {
  const a = await loadAuth(req);
  if (!a?.userId) throw unauthorized();
  const b = parse(z.object({ password: z.string().max(200).optional(), confirmEmail: z.string().max(254).optional() }), req.body);
  const u = (await req.db.query("select password_hash, email from users where id = $1", [a.userId])).rows[0];
  if (u?.password_hash) {
    if (!b.password || !(await verifyPassword(b.password, u.password_hash))) throw unauthorized("Password is incorrect");
  } else if ((b.confirmEmail ?? "").trim().toLowerCase() !== u?.email) {
    // Nexora SSO accounts have no password: they confirm by typing their email address
    throw bad("Type your email address to confirm", "confirmation_required");
  }
  await req.db.tx(async (q) => {
    const orgs = (await q.query("select org_id, role from members where user_id = $1", [a.userId])).rows;
    for (const m of orgs) {
      const others = (await q.query("select count(*)::int as n from members where org_id = $1 and user_id <> $2", [m.org_id, a.userId])).rows[0].n;
      const owners = (await q.query("select count(*)::int as n from members where org_id = $1 and role = 'owner' and user_id <> $2", [m.org_id, a.userId])).rows[0].n;
      if (others > 0 && m.role === "owner" && owners === 0) throw conflict("You are the only owner of an organization with other members. Make someone else an owner first.", "sole_owner");
      if (others === 0) await q.query("delete from organizations where id = $1", [m.org_id]); // last member: org data goes too
    }
    await q.query("delete from users where id = $1", [a.userId]);
  });
  clearSession(res);
  res.json({ ok: true });
});

export const _ = randomToken;
export default r;

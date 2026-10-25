import { Router } from "express";
import { z } from "zod";
import { config, PLANS } from "../config";
import { bad, conflict, forbidden, HttpError, notFound } from "../lib/errors";
import { randomToken, sha256, verifyHmacHex } from "../lib/crypto";
import { parse, requireRole, uuidParam } from "../lib/http";
import { ROLE_RANK, type Role } from "../lib/context";
import { audit } from "../lib/audit";
import { usageOf } from "../services/scans";
import { inviteEmail } from "../services/mail-templates";

const r = Router();
const role = z.enum(["admin", "analyst", "viewer"]);

r.get("/team", requireRole("admin"), async (req, res) => {
  const o = req.auth!.orgId;
  const m = await req.db.query(`select m.id, m.role, m.created_at as "createdAt", u.email, u.name from members m join users u on u.id = m.user_id where m.org_id = $1 order by m.created_at`, [o]);
  const i = await req.db.query(`select id, email, role, expires_at as "expiresAt" from invites where org_id = $1 and accepted_at is null and expires_at > now() order by created_at desc`, [o]);
  res.json({ members: m.rows, invites: i.rows });
});

r.post("/team/invite", requireRole("admin"), async (req, res) => {
  const b = parse(z.object({ email: z.string().trim().toLowerCase().email().max(254), role }), req.body);
  const o = req.auth!.orgId;
  const dup = await req.db.query("select 1 from members m join users u on u.id = m.user_id where m.org_id = $1 and u.email = $2", [o, b.email]);
  if (dup.rows.length) throw conflict("This person is already a member", "already_member");
  const token = randomToken(24);
  await req.db.query("insert into invites (org_id, email, role, token_hash, expires_at) values ($1,$2,$3,$4, now() + interval '7 days')", [o, b.email, b.role, sha256(token)]);
  await audit(req, "team.invite", b.email);
  const org = (await req.db.query("select name from organizations where id = $1", [o])).rows[0];
  const emailed = await req.mailer.send(inviteEmail(b.email, token, org.name, b.role, req.auth!.email));
  // the link is still returned once so the inviter can copy it if the email does not arrive
  res.status(201).json({ link: `${config.appUrl}/invite/${token}`, email: b.email, role: b.role, emailed });
});

r.patch("/team/:id", requireRole("admin"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const b = parse(z.object({ role: z.enum(["owner", "admin", "analyst", "viewer"]) }), req.body);
  const orgId = req.auth!.orgId;
  // lock the org row so two concurrent requests cannot each see "two owners" and both remove one
  await req.db.tx(async (q) => {
    await q.query("select 1 from organizations where id = $1 for update", [orgId]);
    const target = (await q.query("select role from members where id = $1 and org_id = $2", [id, orgId])).rows[0];
    if (!target) throw notFound("Member not found");
    if ((b.role === "owner" || target.role === "owner") && req.auth!.role !== "owner") throw forbidden("Only an owner can change owners");
    if (target.role === "owner" && b.role !== "owner") {
      const n = (await q.query("select count(*)::int as n from members where org_id = $1 and role = 'owner'", [orgId])).rows[0].n;
      if (n <= 1) throw bad("An organization needs at least one owner", "last_owner");
    }
    await q.query("update members set role = $3, updated_at = now() where id = $1 and org_id = $2", [id, orgId, b.role]);
  });
  await audit(req, "team.role_changed", `${id}:${b.role}`);
  res.json({ ok: true });
});

r.delete("/team/:id", requireRole("admin"), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  const orgId = req.auth!.orgId;
  await req.db.tx(async (q) => {
    await q.query("select 1 from organizations where id = $1 for update", [orgId]);
    const target = (await q.query("select role from members where id = $1 and org_id = $2", [id, orgId])).rows[0];
    if (!target) throw notFound("Member not found");
    if (target.role === "owner") {
      if (req.auth!.role !== "owner") throw forbidden("Only an owner can remove an owner");
      const n = (await q.query("select count(*)::int as n from members where org_id = $1 and role = 'owner'", [orgId])).rows[0].n;
      if (n <= 1) throw bad("An organization needs at least one owner", "last_owner");
    }
    await q.query("delete from members where id = $1 and org_id = $2", [id, orgId]);
  });
  await audit(req, "team.removed", id);
  res.json({ ok: true });
});

r.delete("/team/invites/:id", requireRole("admin"), async (req, res) => {
  await req.db.query("delete from invites where id = $1 and org_id = $2", [uuidParam(req.params["id"]), req.auth!.orgId]);
  res.json({ ok: true });
});

r.get("/audit", requireRole("admin"), async (req, res) => {
  const page = Math.max(1, Number(req.query["page"]) || 1);
  const { rows } = await req.db.query(
    `select e.id, e.action, e.target, e.ip, e.created_at as "createdAt", u.email as actor from audit_events e left join users u on u.id = e.actor_id
     where e.org_id = $1 order by e.created_at desc limit 50 offset $2`, [req.auth!.orgId, (page - 1) * 50]);
  res.json({ items: rows, page });
});

r.get("/api-keys", requireRole("admin"), async (req, res) => {
  const { rows } = await req.db.query(`select id, name, prefix, role, expires_at as "expiresAt", last_used_at as "lastUsedAt", created_at as "createdAt" from api_keys where org_id = $1 order by created_at desc`, [req.auth!.orgId]);
  res.json({ items: rows });
});
r.post("/api-keys", requireRole("admin"), async (req, res) => {
  const b = parse(z.object({
    name: z.string().trim().min(1).max(60),
    access: z.enum(["read", "scan"]).default("scan"),           // read = viewer (findings, assets, paths); scan = analyst (also runs scans)
    expiresInDays: z.number().int().min(1).max(365).nullable().default(null),
  }), req.body);
  const n = (await req.db.query("select count(*)::int as n from api_keys where org_id = $1", [req.auth!.orgId])).rows[0].n;
  if (n >= 10) throw bad("At most 10 API keys per organization", "too_many_keys");
  const key = `cspm_${randomToken(32)}`;
  const { rows } = await req.db.query("insert into api_keys (org_id, name, key_hash, prefix, role, expires_at) values ($1,$2,$3,$4,$5, case when $6::int is null then null else now() + make_interval(days => $6::int) end) returning id, expires_at as \"expiresAt\"", [req.auth!.orgId, b.name, sha256(key), key.slice(0, 10), b.access === "read" ? "viewer" : "analyst", b.expiresInDays]);
  await audit(req, "apikey.created", `${b.name} (${b.access}${b.expiresInDays ? `, ${b.expiresInDays} days` : ""})`);
  res.status(201).json({ id: rows[0].id, key, access: b.access, expiresAt: rows[0].expiresAt }); // shown once
});
r.delete("/api-keys/:id", requireRole("admin"), async (req, res) => {
  await req.db.query("delete from api_keys where id = $1 and org_id = $2", [uuidParam(req.params["id"]), req.auth!.orgId]);
  await audit(req, "apikey.revoked", String(req.params["id"]));
  res.json({ ok: true });
});

r.get("/usage", requireRole("viewer"), async (req, res) => res.json({ ...(await usageOf(req.db, req.auth!.orgId)), plans: Object.entries(PLANS).map(([id, p]) => ({ id, ...p })) }));

// ---- billing (Stripe, test mode until you swap keys) ----
r.post("/billing/checkout", requireRole("owner"), async (req, res) => {
  if (!config.stripeSecret || !config.stripeStarterPrice) throw new HttpError(503, "billing_not_configured", "Billing is not set up yet");
  const org = (await req.db.query("select plan, stripe_customer_id from organizations where id = $1", [req.auth!.orgId])).rows[0];
  // a second subscription would keep billing while the first is forgotten: send subscribed orgs to the portal
  if (org.plan !== "free") throw conflict("This organization already has a paid plan. Manage it in the billing portal.", "already_subscribed");
  const body = new URLSearchParams({
    mode: "subscription", "line_items[0][price]": config.stripeStarterPrice, "line_items[0][quantity]": "1",
    client_reference_id: req.auth!.orgId, success_url: `${config.appUrl}/usage?upgraded=1`, cancel_url: `${config.appUrl}/usage`,
  });
  if (org.stripe_customer_id) body.set("customer", org.stripe_customer_id); // reuse the customer, do not create a second one
  await req.db.release(); // no pooled connection held during the Stripe call
  const s = await fetch("https://api.stripe.com/v1/checkout/sessions", { method: "POST", headers: { authorization: `Bearer ${config.stripeSecret}`, "content-type": "application/x-www-form-urlencoded" }, body, signal: AbortSignal.timeout(15000) });
  const j: any = await s.json();
  if (!s.ok || !j.url) throw new HttpError(502, "billing_error", "Could not start checkout");
  await audit(req, "billing.checkout_started");
  res.json({ url: j.url });
});

export function verifyStripeSignature(raw: Buffer, header: string, secret: string, now = Date.now()): boolean {
  // during secret rotation Stripe sends one v1 per active secret: accept if ANY verifies
  const pairs = header.split(",").map((p) => p.split("=") as [string, string]);
  const t = Number(pairs.find(([k]) => k === "t")?.[1]);
  const sigs = pairs.filter(([k]) => k === "v1").map(([, v]) => v);
  if (!t || Math.abs(now / 1000 - t) > 300 || sigs.length === 0) return false;
  const signed = `${t}.${raw.toString("utf8")}`;
  return sigs.some((v) => verifyHmacHex(secret, signed, v));
}

r.post("/billing/portal", requireRole("owner"), async (req, res) => {
  if (!config.stripeSecret) throw new HttpError(503, "billing_not_configured", "Billing is not set up yet");
  const cust = (await req.db.query("select stripe_customer_id from organizations where id = $1", [req.auth!.orgId])).rows[0]?.stripe_customer_id;
  if (!cust) throw bad("This organization has no subscription to manage", "no_subscription");
  await req.db.release();
  const s = await fetch("https://api.stripe.com/v1/billing_portal/sessions", { method: "POST", headers: { authorization: `Bearer ${config.stripeSecret}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ customer: cust, return_url: `${config.appUrl}/usage`, ...(config.stripePortalConfig ? { configuration: config.stripePortalConfig } : {}) }), signal: AbortSignal.timeout(15000) });
  const j: any = await s.json();
  if (!s.ok || !j.url) throw new HttpError(502, "billing_error", "Could not open the billing portal");
  res.json({ url: j.url });
});

r.post("/billing/webhook", async (req, res) => {
  if (!config.stripeWebhookSecret) throw new HttpError(503, "billing_not_configured", "Billing is not set up yet");
  if (!req.rawBody || !verifyStripeSignature(req.rawBody, String(req.headers["stripe-signature"] ?? ""), config.stripeWebhookSecret)) throw bad("Invalid signature", "bad_signature");
  const ev = req.body;
  if (typeof ev?.id !== "string") throw bad("Bad event");
  // Record + apply in ONE transaction: if applying fails the event is not marked seen, so Stripe's retry works.
  const duplicate = await req.db.tx(async (q) => {
    const first = await q.query("insert into stripe_events (id) values ($1) on conflict do nothing returning id", [ev.id]);
    if (!first.rows[0]) return true;
    const obj = ev.data?.object ?? {};
    // Stripe does not guarantee delivery order. Keep the newest known state per customer (by event time) and
    // derive the organization's plan from it, so a late "checkout completed" cannot undo an earlier cancellation.
    const at = Number(ev.created) || Math.floor(Date.now() / 1000);
    const customer: string | undefined = obj.customer ?? undefined;
    const setState = (plan: string) => q.query(
      "insert into billing_state (customer, plan, event_at) values ($1,$2,to_timestamp($3)) on conflict (customer) do update set plan = excluded.plan, event_at = excluded.event_at where billing_state.event_at <= excluded.event_at",
      [customer, plan, at]);
    const apply = () => q.query("update organizations set plan = (select plan from billing_state where customer = $1), updated_at = now() where stripe_customer_id = $1", [customer]);
    if (customer) {
      if (ev.type === "checkout.session.completed" && obj.client_reference_id) {
        await setState("starter");
        await q.query("update organizations set stripe_customer_id = $2 where id = $1", [obj.client_reference_id, customer]);
        await apply();
      } else if (ev.type === "customer.subscription.deleted" || (ev.type === "customer.subscription.updated" && ["canceled", "unpaid", "incomplete_expired"].includes(obj.status))) {
        await setState("free");
        await apply();
      } else if (ev.type === "customer.subscription.updated" && ["active", "trialing"].includes(obj.status)) {
        await setState("starter");
        await apply();
      } else if (ev.type === "invoice.payment_failed") {
        const o = (await q.query("select id from organizations where stripe_customer_id = $1", [customer])).rows[0];
        if (o) await q.query("insert into audit_events (org_id, action, target) values ($1,'billing.payment_failed',$2)", [o.id, String(obj.id ?? "")]);
      }
    }
    return false;
  });
  res.json({ ok: true, ...(duplicate ? { duplicate: true } : {}) });
});

export const _roles: Role[] = (Object.keys(ROLE_RANK) as Role[]);
export default r;

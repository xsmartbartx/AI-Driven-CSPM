import { Router } from "express";
import { z } from "zod";
import { parse, requireRole } from "../lib/http";
import { bad } from "../lib/errors";
import { audit } from "../lib/audit";
import { rateLimit } from "../lib/ratelimit";
import { SLACK_WEBHOOK, sendTest } from "../services/notifications";

const r = Router();

r.get("/notifications", requireRole("admin"), async (req, res) => {
  const { rows } = await req.db.query(
    `select email_enabled as "emailEnabled", min_severity as "minSeverity", slack_webhook is not null as "slackConfigured", last_sent_at as "lastSentAt", last_error as "lastError"
     from notification_settings where org_id = $1`, [req.auth!.orgId]);
  res.json(rows[0] ?? { emailEnabled: false, minSeverity: "high", slackConfigured: false, lastSentAt: null, lastError: null });
});

/** Omitted fields keep their value; slackWebhook: null removes the webhook. The webhook URL is never sent back. */
r.put("/notifications", requireRole("admin"), async (req, res) => {
  const b = parse(z.object({
    emailEnabled: z.boolean().optional(),
    minSeverity: z.enum(["critical", "high"]).optional(),
    slackWebhook: z.string().trim().max(300).nullable().optional(),
  }), req.body);
  if (typeof b.slackWebhook === "string" && !SLACK_WEBHOOK.test(b.slackWebhook))
    throw bad("That is not a Slack incoming webhook URL (https://hooks.slack.com/services/…)", "invalid_webhook");
  const setHook = b.slackWebhook !== undefined;
  await req.db.query(
    `insert into notification_settings (org_id, email_enabled, min_severity, slack_webhook) values ($1, coalesce($2, false), coalesce($3, 'high'), $4)
     on conflict (org_id) do update set
       email_enabled = coalesce($2, notification_settings.email_enabled),
       min_severity = coalesce($3, notification_settings.min_severity),
       slack_webhook = case when $5 then $4 else notification_settings.slack_webhook end,
       last_error = case when $5 then null else notification_settings.last_error end,
       updated_at = now()`,
    [req.auth!.orgId, b.emailEnabled ?? null, b.minSeverity ?? null, b.slackWebhook ?? null, setHook]);
  await audit(req, "notifications.updated", [b.emailEnabled !== undefined && `email ${b.emailEnabled ? "on" : "off"}`, b.minSeverity, setHook && `slack ${b.slackWebhook ? "set" : "removed"}`].filter(Boolean).join(", "));
  res.json({ ok: true });
});

r.post("/notifications/test", requireRole("admin"), rateLimit("notify-test", 10, 3600_000, (q) => q.auth?.orgId ?? "?"), async (req, res) => {
  res.json(await sendTest({ db: req.sysDb, mailer: req.mailer, fetchImpl: req.notifyFetch }, req.auth!.orgId, req.auth!.email));
});

export default r;

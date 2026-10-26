import type { Db } from "@workspace/db";
import type { Severity } from "@workspace/cspm-engine";
import { config } from "../config";
import { logger } from "../lib/logger";
import type { Mailer } from "./mail";
import { securityAlertEmail } from "./mail-templates";

/** A finding that appeared (or came back) in a scan. */
export interface Alert { title: string; severity: Severity; asset: string; type: string }
export interface NotifyDeps { db: Db; mailer: Mailer; fetchImpl?: typeof fetch }
export const SLACK_WEBHOOK = /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/;
const MAX_LISTED = 10;
const MAX_RECIPIENTS = 10;

const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const slackEsc = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]!);
const base = () => config.appUrl.replace(/\/$/, "");

export function slackText(orgName: string, alerts: Alert[]): string {
  const lines = alerts.slice(0, MAX_LISTED).map((a) => `• *${a.severity.toUpperCase()}* ${slackEsc(a.title)} on \`${slackEsc(a.asset)}\``);
  const more = alerts.length > MAX_LISTED ? [`…and ${alerts.length - MAX_LISTED} more`] : [];
  return [`*NEXORA CSPM*: ${alerts.length} new ${alerts.length === 1 ? "finding" : "findings"} for ${slackEsc(orgName)}`, ...lines, ...more, `<${base()}/findings|Open findings>`].join("\n");
}

async function postSlack(url: string, text: string, fetchImpl: typeof fetch): Promise<string | null> {
  try {
    const res = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }), redirect: "error", signal: AbortSignal.timeout(5000) });
    return res.ok ? null : `Slack answered ${res.status}`;
  } catch { return "Slack could not be reached"; }
}

/** Sends the alerts a scan produced, if the organization asked for them. Never throws: a notification problem must not fail a scan. */
export async function notifyScan(d: NotifyDeps, orgId: string, alerts: Alert[]): Promise<void> {
  try {
    const { rows } = await d.db.query("select email_enabled, min_severity, slack_webhook from notification_settings where org_id = $1", [orgId]);
    const s = rows[0];
    if (!s || (!s.email_enabled && !s.slack_webhook)) return;
    const limit = s.min_severity === "critical" ? 0 : 1;
    const hits = alerts.filter((a) => rank[a.severity]! <= limit).sort((a, b) => rank[a.severity]! - rank[b.severity]!);
    if (hits.length === 0) return;
    const org = (await d.db.query("select name from organizations where id = $1", [orgId])).rows[0]?.name ?? "your organization";
    const errors: string[] = [];
    if (s.email_enabled) {
      const to = (await d.db.query("select u.email from members m join users u on u.id = m.user_id where m.org_id = $1 and m.role in ('owner','admin') order by m.created_at limit $2", [orgId, MAX_RECIPIENTS])).rows;
      for (const r of to) if (!(await d.mailer.send(securityAlertEmail(r.email, org, hits, MAX_LISTED)))) errors.push("Email could not be sent");
    }
    if (s.slack_webhook) { const e = await postSlack(s.slack_webhook, slackText(org, hits), d.fetchImpl ?? fetch); if (e) errors.push(e); }
    await d.db.query("update notification_settings set last_sent_at = now(), last_error = $2 where org_id = $1", [orgId, errors.length ? [...new Set(errors)].join("; ") : null]);
  } catch (e) {
    logger.warn({ err: e instanceof Error ? e.message : String(e) }, "scan notification failed");
  }
}

/** The "send a test" button: tells the admin exactly what worked. */
export async function sendTest(d: NotifyDeps, orgId: string, adminEmail: string | null): Promise<{ email: string; slack: string }> {
  const { rows } = await d.db.query("select email_enabled, slack_webhook from notification_settings where org_id = $1", [orgId]);
  const s = rows[0];
  const sample: Alert[] = [{ title: "Test alert from NEXORA CSPM", severity: "high", asset: "example-resource", type: "test" }];
  let email = "off", slack = "off";
  if (s?.email_enabled) {
    email = !adminEmail ? "no address to send to (API keys cannot receive the test)" : (await d.mailer.send(securityAlertEmail(adminEmail, "your organization", sample, MAX_LISTED))) ? `sent to ${adminEmail}` : "could not be sent";
  }
  if (s?.slack_webhook) slack = (await postSlack(s.slack_webhook, slackText("your organization", sample), d.fetchImpl ?? fetch)) ?? "sent";
  return { email, slack };
}

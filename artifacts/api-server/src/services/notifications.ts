import type { Db } from "@workspace/db";
import type { Severity } from "@workspace/cspm-engine";
import { config } from "../config";
import { logger } from "../lib/logger";
import type { Mailer } from "./mail";
import { dailyBriefEmail, securityAlertEmail, weeklyReportEmail } from "./mail-templates";
import { buildBrief } from "./brief";

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

/**
 * The optional daily summary and weekly report. Rules that keep delivery safe:
 * - an organization is claimed one at a time, right before it is processed, so a crash loses at most the one in hand;
 * - only organizations that have scanned are claimed (otherwise a first scan later the same day would wait a week);
 * - a claim is atomic (FOR UPDATE SKIP LOCKED), so several instances never send twice;
 * - a tick stops after a time budget, so slow mail never holds up the scheduled scans that run next to it.
 */
const BUDGET_MS = 20_000;
type Kind = { flag: string; at: string; every: string; when: string };
const DAILY: Kind = { flag: "daily_digest", at: "last_digest_at", every: "23 hours", when: "extract(hour from now() at time zone 'utc') >= $1" };
const WEEKLY: Kind = { flag: "weekly_report", at: "last_weekly_at", every: "6 days", when: "($2::boolean or extract(isodow from now() at time zone 'utc') = 1) and extract(hour from now() at time zone 'utc') >= $1" };

async function claimNext(db: Db, k: Kind, minHour: number, anyDay: boolean): Promise<string | null> {
  const params = k === WEEKLY ? [minHour, anyDay] : [minHour];
  const { rows } = await db.query(
    `update notification_settings set ${k.at} = now() where org_id = (
       select n.org_id from notification_settings n
       where n.${k.flag} and (n.${k.at} is null or n.${k.at} < now() - interval '${k.every}') and ${k.when}
         and exists (select 1 from scans s where s.org_id = n.org_id)
       order by n.${k.at} nulls first limit 1 for update skip locked)
     returning org_id`, params);
  return (rows[0]?.org_id as string | undefined) ?? null;
}

async function deliver(d: NotifyDeps, k: Kind, minHour: number, anyDay: boolean, budgetMs: number, send: (orgId: string) => Promise<void>): Promise<void> {
  const deadline = Date.now() + budgetMs;
  for (let n = 0; n < 200 && Date.now() < deadline; n++) {
    let orgId: string | null;
    try { orgId = await claimNext(d.db, k, minHour, anyDay); }
    catch (e) { logger.warn({ err: e instanceof Error ? e.message : String(e) }, "report claim failed"); return; }
    if (!orgId) return;
    try { await send(orgId); } catch (e) { logger.warn({ org: orgId, err: e instanceof Error ? e.message : String(e) }, "report failed"); }
  }
}

async function recipients(d: NotifyDeps, orgId: string) {
  const org = (await d.db.query("select name from organizations where id = $1", [orgId])).rows[0]?.name ?? "your organization";
  const to = (await d.db.query("select u.email from members m join users u on u.id = m.user_id where m.org_id = $1 and m.role in ('owner','admin') order by m.created_at limit $2", [orgId, MAX_RECIPIENTS])).rows;
  return { org: org as string, to: to.map((r) => r.email as string) };
}

/** The optional daily summary: after 07:00 UTC, only when there is something to say. */
export async function sendDueDigests(d: NotifyDeps, minHourUtc = 7, budgetMs = BUDGET_MS): Promise<void> {
  await deliver(d, DAILY, minHourUtc, false, budgetMs, async (orgId) => {
    const brief = await buildBrief(d.db, orgId, 24);
    const news = brief.newFindings.total > 0 || brief.fixed > 0 || brief.open.critical > 0 || brief.expiring.acceptedRisks > 0 || brief.expiring.suppressions > 0;
    if (!brief.hasData || !news) return;
    const { org, to } = await recipients(d, orgId);
    for (const email of to) await d.mailer.send(dailyBriefEmail(email, org, brief));
  });
}

/** The optional weekly report: Mondays after 07:00 UTC. Sent on a quiet week too, but not before the first scan. */
export async function sendDueWeeklyReports(d: NotifyDeps, minHourUtc = 7, anyDay = false, budgetMs = BUDGET_MS): Promise<void> {
  await deliver(d, WEEKLY, minHourUtc, anyDay, budgetMs, async (orgId) => {
    const brief = await buildBrief(d.db, orgId, 168, 5);
    if (!brief.hasData) return;
    const { org, to } = await recipients(d, orgId);
    for (const email of to) await d.mailer.send(weeklyReportEmail(email, org, brief));
  });
}

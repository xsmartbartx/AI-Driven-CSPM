import type { Db } from "@workspace/db";
import { auditEvent } from "../lib/audit";
import type { Auth } from "../lib/context";
import { HttpError } from "../lib/errors";
import { logger } from "../lib/logger";
import type { Mailer } from "./mail";
import { scheduledScanStoppedEmail } from "./mail-templates";
import { scanConnection, type Conn } from "./aws/scan";
import { notifyScan } from "./notifications";
import { sweepExpiredSuppressions } from "./suppressions";
import type { AwsConnector } from "./aws/types";

export interface SchedulerDeps { db: Db; aws: AwsConnector; mailer: Mailer }

const INTERVAL = { daily: "24 hours", weekly: "7 days" } as const;
/** After this many failures in a row the schedule is switched off and the admins are told. */
export const MAX_FAILURES = 5;
const jitter = () => Math.floor(Math.random() * 600); // seconds: spread accounts that became due together

interface Due extends Conn { orgId: string; schedule: "daily" | "weekly"; failures: number }

/**
 * Picks the accounts that are due and scans them, one after the other. Safe to run on several instances at once:
 * the claim uses FOR UPDATE SKIP LOCKED and moves next_run_at forward in the same statement, and each scan also takes
 * the account's database lease. Runs on the privileged connection (it spans organizations); every scan itself runs
 * under that organization's row level security.
 */
export async function runDueScans(d: SchedulerDeps, limit = 3): Promise<{ scanned: number; failed: number; skipped: number }> {
  const out = { scanned: 0, failed: 0, skipped: 0 };
  if (!d.aws.enabled) return out;
  const due = (await d.db.query<Due>(
    `update cloud_accounts set next_run_at = now() + interval '30 minutes', updated_at = now()
     where id in (
       select id from cloud_accounts
       where provider = 'aws' and schedule <> 'off' and status = 'connected' and next_run_at is not null and next_run_at <= now()
         and (scan_started_at is null or scan_started_at < now() - interval '20 minutes')
       order by next_run_at limit $1 for update skip locked)
     returning id, org_id as "orgId", external_id as "accountId", region, role_arn as "roleArn", sts_external_id as "externalId", status, schedule, failure_count as "failures"`,
    [limit])).rows;
  // the 30 minutes above is a safety net: if this process dies mid-scan the account is retried later, not lost
  for (const row of due) {
    const r = await runOne(d, row);
    out[r]++;
  }
  return out;
}

async function runOne(d: SchedulerDeps, row: Due): Promise<"scanned" | "failed" | "skipped"> {
  const auth: Auth = { userId: null, orgId: row.orgId, role: "analyst", email: null, via: "key" };
  const db = d.db.scoped(row.orgId);
  const label = `${row.accountId}/${row.region}`;
  try {
    const res = await scanConnection(db, d.aws, auth, row);
    void notifyScan({ db: d.db, mailer: d.mailer }, row.orgId, res.alerts);
    await db.query(
      `update cloud_accounts set failure_count = 0, last_scheduled_at = now(), next_run_at = now() + interval '${INTERVAL[row.schedule]}' + make_interval(secs => $2), updated_at = now() where id = $1`,
      [row.id, jitter()]);
    await auditEvent(db, row.orgId, null, "cloud.scan.scheduled", label);
    logger.info({ account: row.id, scan: res.id, findings: res.findingCount, complete: res.complete }, "scheduled scan finished");
    return "scanned";
  } catch (e) {
    return await onFailure(d, db, row, e, label);
  } finally {
    await db.release(true).catch(() => {});
  }
}

async function onFailure(d: SchedulerDeps, db: Db, row: Due, e: unknown, label: string): Promise<"failed" | "skipped"> {
  const code = e instanceof HttpError ? e.code : "internal";
  const message = e instanceof HttpError ? e.message : "The scheduled scan failed unexpectedly.";
  const later = (interval: string) => db.query("update cloud_accounts set next_run_at = now() + $2::interval + make_interval(secs => $3), updated_at = now() where id = $1", [row.id, interval, jitter()]);
  const noteError = () => db.query("update cloud_accounts set last_error = $2 where id = $1", [row.id, message]);

  // not the account's fault: someone else is scanning it right now, or the plan has no scans left. No failure is counted.
  if (code === "scan_running") { await later("15 minutes"); return "skipped"; }
  if (code === "quota_exceeded") { await noteError(); await later("6 hours"); return "skipped"; }

  // the customer's role no longer works: nothing will succeed until they fix it, so stop and say so (once)
  if (code === "assume_denied" || code === "account_mismatch") {
    await db.query("update cloud_accounts set status = 'error', schedule = 'off', next_run_at = null, failure_count = 0, last_error = $2, updated_at = now() where id = $1", [row.id, message]);
    await stop(d, db, row, label, `the read-only role no longer works. ${message}`);
    return "failed";
  }

  // anything else (our AWS credentials, network, throttling, an empty account): retry with a growing delay, give up after MAX_FAILURES
  const failures = row.failures + 1;
  logger.warn({ account: row.id, code, failures }, "scheduled scan failed");
  if (failures >= MAX_FAILURES) {
    await db.query("update cloud_accounts set schedule = 'off', next_run_at = null, failure_count = $2, last_error = $3, updated_at = now() where id = $1", [row.id, failures, message]);
    await stop(d, db, row, label, `it failed ${failures} times in a row. Last error: ${message}`);
    return "failed";
  }
  const backoffHours = Math.min(2 ** row.failures, row.schedule === "daily" ? 24 : 168); // 1h, 2h, 4h, 8h ...
  await db.query("update cloud_accounts set failure_count = $2, last_error = $3, next_run_at = now() + make_interval(hours => $4) + make_interval(secs => $5), updated_at = now() where id = $1", [row.id, failures, message, backoffHours, jitter()]);
  return "failed";
}

/** Switch-off notice: audit entry plus one email to the organization's owners and admins. */
async function stop(d: SchedulerDeps, db: Db, row: Due, label: string, reason: string) {
  await auditEvent(db, row.orgId, null, "cloud.schedule_disabled", label);
  const org = (await d.db.query("select name from organizations where id = $1", [row.orgId])).rows[0]?.name ?? "your organization";
  const admins = (await d.db.query(
    "select distinct u.email from members m join users u on u.id = m.user_id where m.org_id = $1 and m.role in ('owner','admin')", [row.orgId])).rows;
  for (const a of admins) await d.mailer.send(scheduledScanStoppedEmail(a.email, org, label, reason));
}

/** Starts the periodic check. Returns stop(), which waits for the scan that is running, if any. */
export function startScheduler(d: SchedulerDeps, tickMs = 60_000): { stop(): Promise<void> } {
  let stopped = false;
  let inflight: Promise<void> | null = null; // the run in progress; later ticks see it and do nothing, so runs never overlap
  const tick = () => {
    if (stopped || inflight) return;
    inflight = (async () => {
      try { await sweepExpiredSuppressions(d.db); } catch (e) { logger.error({ err: (e as Error).name }, "suppression sweep failed"); } // never blocks the scans below
      try { await runDueScans(d); } catch (e) { logger.error({ err: (e as Error).name }, "scheduler tick failed"); }
    })().finally(() => { inflight = null; });
  };
  const timer = setInterval(tick, tickMs);
  return { async stop() { stopped = true; clearInterval(timer); await inflight; } };
}

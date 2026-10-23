import type { Db } from "@workspace/db";
import { PLANS } from "../../config";
import { conflict, HttpError } from "../../lib/errors";
import type { Auth } from "../../lib/context";
import { runScan, usageOf } from "../scans";
import { AwsError, type AwsConnector } from "./types";

/** What a scan needs to know about a connection. */
export interface Conn { id: string; accountId: string; region: string; roleArn: string; externalId: string; status: string }

/** A lease older than this is treated as abandoned (the process that held it died). Keep in step with migration 0005. */
export const LEASE_MINUTES = 20;

export const STATUS_FOR: Record<string, number> = { assume_denied: 422, account_mismatch: 422, platform_credentials: 503, throttled: 429, network: 502, aws_error: 502, aws_not_configured: 503 };
export const awsToHttp = (e: unknown) => (e instanceof AwsError ? new HttpError(STATUS_FOR[e.code] ?? 502, e.code, e.message) : e);
export const target = (c: Conn) => ({ accountId: c.accountId, roleArn: c.roleArn, externalId: c.externalId, region: c.region });

/**
 * The one way an AWS account gets scanned, for a person pressing "Scan now" and for the scheduler alike.
 * `db` must already be scoped to the organization (row level security). Throws HttpError with a stable `code`.
 *
 * - A database lease makes sure only one scan of an account runs at a time, across all instances.
 * - The plan's scan quota is checked BEFORE AWS is read, so no AWS calls are wasted.
 * - A scan that could not read everything is incomplete and never closes findings on resources it did not see (see runScan).
 */
export async function scanConnection(db: Db, aws: AwsConnector, auth: Auth, conn: Conn) {
  if (conn.status !== "connected") throw conflict("Verify the connection first.", "not_verified");
  const claimed = await db.query(
    `update cloud_accounts set scan_started_at = now() where id = $1 and org_id = $2 and (scan_started_at is null or scan_started_at < now() - interval '${LEASE_MINUTES} minutes') returning id`,
    [conn.id, auth.orgId]);
  if (!claimed.rows[0]) throw conflict("A scan of this account is already running.", "scan_running");
  try {
    const u = await usageOf(db, auth.orgId);
    if (u.scans.used >= u.scans.limit) throw new HttpError(402, "quota_exceeded", `You have used all ${PLANS[u.plan].scans} scans on the ${u.planLabel} plan this month.`);
    await db.release(); // AWS reads can take a while: do not hold a pooled connection
    let found;
    try { found = await aws.collect(target(conn)); }
    catch (e) {
      const err = e instanceof AwsError ? e : new AwsError("aws_error", "AWS returned an error. Try again.");
      await db.query("update cloud_accounts set last_error = $2, updated_at = now() where id = $1", [conn.id, err.message]);
      throw awsToHttp(err);
    }
    if (found.resources.length === 0) {
      await db.query("update cloud_accounts set last_error = $2, updated_at = now() where id = $1", [conn.id, "Nothing was found to scan."]);
      throw new HttpError(422, "no_resources", `Nothing was found to scan in this account and region. ${found.notes.join(" ")}`.trim());
    }
    const result = await runScan(db, auth, found.resources, { accountId: conn.id, complete: found.complete });
    await db.query("update cloud_accounts set last_sync_at = now(), last_scan_id = $2, last_error = null, updated_at = now() where id = $1", [conn.id, result.id]);
    return { ...result, notes: found.notes, complete: found.complete };
  } finally {
    await db.query("update cloud_accounts set scan_started_at = null where id = $1 and org_id = $2", [conn.id, auth.orgId]).catch(() => {});
  }
}

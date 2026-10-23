import { Router } from "express";
import { z } from "zod";
import { audit } from "../lib/audit";
import { bad, conflict, HttpError, notFound } from "../lib/errors";
import { parse, requireRole, uuidParam } from "../lib/http";
import { randomToken } from "../lib/crypto";
import { rateLimit } from "../lib/ratelimit";
import { ROLE_RANK } from "../lib/context";
import { cloudFormationTemplate, DEFAULT_ROLE_NAME, isAccountId, isRoleName, READ_ONLY_ACTIONS, roleArnFor } from "../services/aws/setup";
import { AwsError, REGIONS } from "../services/aws/types";
import { awsToHttp, scanConnection, target } from "../services/aws/scan";

const r = Router();
const MAX_CONNECTIONS = 10;

const byOrg = (req: { auth?: { orgId: string } }) => req.auth?.orgId ?? "?";

const COLS = `id, external_id as "accountId", region, role_arn as "roleArn", status, last_sync_at as "lastSyncAt", last_error as "lastError", verified_at as "verifiedAt", last_scan_id as "lastScanId", created_at as "createdAt",
  schedule, next_run_at as "nextRunAt", failure_count as "failureCount", last_scheduled_at as "lastScheduledAt"`;

r.get("/cloud-accounts", requireRole("viewer"), async (req, res) => {
  const { rows } = await req.db.query(`select ${COLS}, sts_external_id as "externalId" from cloud_accounts where org_id = $1 and provider = 'aws' order by created_at`, [req.auth!.orgId]);
  const admin = ROLE_RANK[req.auth!.role] >= ROLE_RANK["admin"];
  res.json({
    connector: { enabled: req.aws.enabled, principalAccountId: req.aws.enabled && admin ? req.aws.principalAccountId : null },
    regions: REGIONS, readOnlyActions: READ_ONLY_ACTIONS, defaultRoleName: DEFAULT_ROLE_NAME,
    items: rows.map((x) => ({ ...x, externalId: admin ? x.externalId : undefined })), // the External ID is only for people who set the role up
  });
});

r.post("/cloud-accounts", requireRole("admin"), async (req, res) => {
  if (!req.aws.enabled) throw new HttpError(503, "aws_not_configured", "AWS connections are not enabled on this server.");
  const b = parse(z.object({ accountId: z.string().trim(), region: z.enum(REGIONS), roleName: z.string().trim().optional() }), req.body);
  if (!isAccountId(b.accountId)) throw bad("An AWS account id is 12 digits", "invalid_account_id");
  const roleName = b.roleName || DEFAULT_ROLE_NAME;
  if (!isRoleName(roleName)) throw bad("That is not a valid IAM role name", "invalid_role_name");
  const orgId = req.auth!.orgId;
  const n = (await req.db.query("select count(*)::int as n from cloud_accounts where org_id = $1", [orgId])).rows[0].n;
  if (n >= MAX_CONNECTIONS) throw bad(`At most ${MAX_CONNECTIONS} connections per organization`, "too_many_connections");
  const externalId = `nx-${randomToken(24)}`; // per connection, so a role set up for someone else cannot be used to read this account
  const dup = await req.db.query("select 1 from cloud_accounts where org_id = $1 and provider = 'aws' and external_id = $2 and region = $3", [orgId, b.accountId, b.region]);
  if (dup.rows.length) throw conflict("This account and region are already connected", "already_connected");
  const { rows } = await req.db.query(
    `insert into cloud_accounts (org_id, provider, external_id, region, role_arn, sts_external_id, status) values ($1,'aws',$2,$3,$4,$5,'pending') returning ${COLS}`,
    [orgId, b.accountId, b.region, roleArnFor(b.accountId, roleName), externalId]);
  await audit(req, "cloud.connect", `${b.accountId}/${b.region}`);
  res.status(201).json({ ...rows[0], externalId, principalAccountId: req.aws.principalAccountId, template: cloudFormationTemplate({ principalAccountId: req.aws.principalAccountId, externalId, roleName }) });
});

const load = async (req: any) => {
  const row = (await req.db.query(`select ${COLS}, sts_external_id as "externalId" from cloud_accounts where id = $1 and org_id = $2 and provider = 'aws'`, [uuidParam(req.params["id"]), req.auth!.orgId])).rows[0];
  if (!row) throw notFound("Connection not found");
  return row;
};

r.get("/cloud-accounts/:id/setup", requireRole("admin"), async (req, res) => {
  const row = await load(req);
  if (!req.aws.enabled) throw new HttpError(503, "aws_not_configured", "AWS connections are not enabled on this server.");
  const roleName = row.roleArn.split("/").pop();
  res.json({ principalAccountId: req.aws.principalAccountId, externalId: row.externalId, roleArn: row.roleArn, template: cloudFormationTemplate({ principalAccountId: req.aws.principalAccountId, externalId: row.externalId, roleName }) });
});

r.post("/cloud-accounts/:id/verify", requireRole("admin"), rateLimit("aws-verify", 30, 3600_000, byOrg), async (req, res) => {
  const row = await load(req);
  await req.db.release(); // do not hold a pooled connection during the AWS call
  try {
    await req.aws.verify(target(row));
  } catch (e) {
    const err = e instanceof AwsError ? e : new AwsError("aws_error", "AWS returned an error. Try again.");
    // a problem on NEXORA's side (credentials, network, throttling) says nothing about the customer's role: keep its status
    const theirs = err.code === "assume_denied" || err.code === "account_mismatch";
    await req.db.query("update cloud_accounts set last_error = $2, status = case when $3 then 'error' else status end, updated_at = now() where id = $1", [row.id, err.message, theirs]);
    throw awsToHttp(err);
  }
  await req.db.query("update cloud_accounts set status = 'connected', verified_at = now(), last_error = null, updated_at = now() where id = $1", [row.id]);
  await audit(req, "cloud.verify", `${row.accountId}/${row.region}`);
  res.json({ status: "connected" });
});

r.post("/cloud-accounts/:id/scan", requireRole("analyst"), rateLimit("aws-scan", 12, 3600_000, byOrg), async (req, res) => {
  const row = await load(req);
  const out = await scanConnection(req.db, req.aws, req.auth!, row);
  await audit(req, "cloud.scan", `${row.accountId}/${row.region}`);
  res.status(201).json(out);
});

/** Turn automatic scans on or off. The scheduler (services/scheduler.ts) picks the account up when next_run_at is due. */
r.patch("/cloud-accounts/:id", requireRole("admin"), async (req, res) => {
  const b = parse(z.object({ schedule: z.enum(["off", "daily", "weekly"]) }), req.body);
  const row = await load(req);
  if (b.schedule !== "off") {
    if (!req.aws.enabled) throw new HttpError(503, "aws_not_configured", "AWS connections are not enabled on this server.");
    if (row.status !== "connected") throw conflict("Verify the connection before turning on automatic scans.", "not_verified");
  }
  const jitter = 60 + Math.floor(Math.random() * 540); // 1-10 minutes: accounts enabled together do not all fire together
  // the first automatic scan waits for one full interval after the last scan of any kind, but never longer than needed to start soon
  await req.db.query(
    `update cloud_accounts set schedule = $2, failure_count = 0,
       next_run_at = case when $2 = 'off' then null
                          else greatest(now() + make_interval(secs => $3), coalesce(last_sync_at, '-infinity'::timestamptz) + (case when $2 = 'daily' then interval '24 hours' else interval '7 days' end)) end,
       updated_at = now() where id = $1`, [row.id, b.schedule, jitter]);
  await audit(req, "cloud.schedule", `${row.accountId}/${row.region}:${b.schedule}`);
  res.json({ ok: true });
});

r.delete("/cloud-accounts/:id", requireRole("admin"), async (req, res) => {
  const row = await load(req);
  await req.db.query("delete from cloud_accounts where id = $1 and org_id = $2", [row.id, req.auth!.orgId]);
  await audit(req, "cloud.disconnect", `${row.accountId}/${row.region}`);
  res.json({ ok: true });
});

export default r;

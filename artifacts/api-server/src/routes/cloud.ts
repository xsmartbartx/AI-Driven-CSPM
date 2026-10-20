import { Router } from "express";
import { z } from "zod";
import { PLANS } from "../config";
import { audit } from "../lib/audit";
import { bad, conflict, HttpError, notFound } from "../lib/errors";
import { parse, requireRole, uuidParam } from "../lib/http";
import { randomToken } from "../lib/crypto";
import { rateLimit } from "../lib/ratelimit";
import { ROLE_RANK } from "../lib/context";
import { cloudFormationTemplate, DEFAULT_ROLE_NAME, isAccountId, isRoleName, READ_ONLY_ACTIONS, roleArnFor } from "../services/aws/setup";
import { AwsError, REGIONS } from "../services/aws/types";
import { runScan, usageOf } from "../services/scans";

const r = Router();
const MAX_CONNECTIONS = 10;
const running = new Set<string>(); // scans in progress in THIS process; across several instances the plan quota is still enforced

const STATUS_FOR: Record<string, number> = { assume_denied: 422, account_mismatch: 422, platform_credentials: 503, throttled: 429, network: 502, aws_error: 502, aws_not_configured: 503 };
const asHttp = (e: unknown) => (e instanceof AwsError ? new HttpError(STATUS_FOR[e.code] ?? 502, e.code, e.message) : e);
const byOrg = (req: { auth?: { orgId: string } }) => req.auth?.orgId ?? "?";

const COLS = `id, external_id as "accountId", region, role_arn as "roleArn", status, last_sync_at as "lastSyncAt", last_error as "lastError", verified_at as "verifiedAt", last_scan_id as "lastScanId", created_at as "createdAt"`;

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
const target = (row: any) => ({ accountId: row.accountId, roleArn: row.roleArn, externalId: row.externalId, region: row.region });

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
    throw asHttp(err);
  }
  await req.db.query("update cloud_accounts set status = 'connected', verified_at = now(), last_error = null, updated_at = now() where id = $1", [row.id]);
  await audit(req, "cloud.verify", `${row.accountId}/${row.region}`);
  res.json({ status: "connected" });
});

r.post("/cloud-accounts/:id/scan", requireRole("analyst"), rateLimit("aws-scan", 12, 3600_000, byOrg), async (req, res) => {
  const id = uuidParam(req.params["id"]);
  // Reserve the slot in the same tick as the check: any await between them would let two simultaneous requests both pass.
  if (running.has(id)) throw conflict("A scan of this account is already running.", "scan_running");
  running.add(id);
  try {
    const row = await load(req);
    if (row.status !== "connected") throw conflict("Verify the connection first.", "not_verified");
    // refuse before reading from AWS if the plan has no scans left, so no AWS calls are wasted
    const u = await usageOf(req.db, req.auth!.orgId);
    if (u.scans.used >= u.scans.limit) throw new HttpError(402, "quota_exceeded", `You have used all ${PLANS[u.plan].scans} scans on the ${u.planLabel} plan this month.`);
    await req.db.release(); // AWS reads can take a while: do not hold a pooled connection
    let found;
    try { found = await req.aws.collect(target(row)); }
    catch (e) {
      const err = e instanceof AwsError ? e : new AwsError("aws_error", "AWS returned an error. Try again.");
      await req.db.query("update cloud_accounts set last_error = $2, updated_at = now() where id = $1", [row.id, err.message]);
      throw asHttp(err);
    }
    if (found.resources.length === 0) {
      await req.db.query("update cloud_accounts set last_error = $2, updated_at = now() where id = $1", [row.id, "Nothing was found to scan."]);
      throw new HttpError(422, "no_resources", `Nothing was found to scan in this account and region. ${found.notes.join(" ")}`.trim());
    }
    const result = await runScan(req.db, req.auth!, found.resources, { accountId: row.id, complete: found.complete });
    await req.db.query("update cloud_accounts set last_sync_at = now(), last_scan_id = $2, last_error = null, updated_at = now() where id = $1", [row.id, result.id]);
    await audit(req, "cloud.scan", `${row.accountId}/${row.region}`);
    res.status(201).json({ ...result, notes: found.notes, complete: found.complete });
  } finally { running.delete(id); }
});

r.delete("/cloud-accounts/:id", requireRole("admin"), async (req, res) => {
  const row = await load(req);
  await req.db.query("delete from cloud_accounts where id = $1 and org_id = $2", [row.id, req.auth!.orgId]);
  await audit(req, "cloud.disconnect", `${row.accountId}/${row.region}`);
  res.json({ ok: true });
});

export default r;

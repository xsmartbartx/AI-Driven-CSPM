import { test, before, after } from "node:test";
import assert from "node:assert/strict";

process.env["NODE_ENV"] = "test";
const { openDb } = await import("@workspace/db");
const { runDueScans, startScheduler, MAX_FAILURES } = await import("../src/services/scheduler.ts");
const { scanConnection } = await import("../src/services/aws/scan.ts");
const { AwsError } = await import("../src/services/aws/types.ts");
import type { AwsConnector, AwsTarget, CollectResult } from "../src/services/aws/types.ts";

let db: Awaited<ReturnType<typeof openDb>>;
before(async () => { db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" }); });
after(async () => { await db.close(); });

// ---- a fake AWS, and a mailbox -------------------------------------------------------------------------------------
const aws = {
  collected: [] as string[],
  delayMs: 0,
  result: (_t: AwsTarget): CollectResult | Error => ({ resources: [{ type: "s3_bucket", name: `b-${Math.random().toString(36).slice(2, 8)}`, public_read: true, encrypted: true }], notes: [], complete: true }),
  reset() { this.collected = []; this.delayMs = 0; this.result = () => ({ resources: [{ type: "s3_bucket", name: `b-${Math.random().toString(36).slice(2, 8)}`, public_read: true, encrypted: true }], notes: [], complete: true }); },
};
const fakeAws: AwsConnector = {
  enabled: true, principalAccountId: "123456789012",
  async verify() {},
  async collect(t) {
    aws.collected.push(t.accountId);
    if (aws.delayMs) await new Promise((r) => setTimeout(r, aws.delayMs));
    const r = aws.result(t);
    if (r instanceof Error) throw r;
    return r;
  },
};
const outbox: { to: string; subject: string; text: string }[] = [];
const mailer = { enabled: true, send: async (m: any) => { outbox.push(m); return true; } };
const deps = () => ({ db, aws: fakeAws, mailer });

// ---- fixtures (privileged inserts) ---------------------------------------------------------------------------------
let n = 0;
async function org(plan = "free") {
  const o = (await db.query("insert into organizations (name, plan) values ($1,$2) returning id", [`Sched ${++n} ${Date.now()}`, plan])).rows[0]!.id as string;
  const user = async (role: string) => {
    const email = `${role}${n}-${Math.random().toString(36).slice(2, 7)}@example.com`;
    const u = (await db.query("insert into users (email) values ($1) returning id", [email])).rows[0]!.id;
    await db.query("insert into members (org_id, user_id, role) values ($1,$2,$3)", [o, u, role]);
    return { id: u as string, email };
  };
  return { id: o, owner: await user("owner"), admin: await user("admin"), viewer: await user("viewer") };
}
let acct = 100000000000;
async function account(orgId: string, o: { schedule?: string; due?: string | null; status?: string; failures?: number; lease?: string | null; region?: string } = {}) {
  const external = String(acct++);
  const due = o.due === undefined ? "now() - interval '1 minute'" : o.due === null ? "null" : o.due;
  const lease = o.lease ? o.lease : "null";
  const r = await db.query(
    `insert into cloud_accounts (org_id, provider, external_id, region, role_arn, sts_external_id, status, schedule, next_run_at, failure_count, scan_started_at)
     values ($1,'aws',$2,$3,$4,$5,$6,$7, ${due}, $8, ${lease}) returning id`,
    [orgId, external, o.region ?? "eu-west-1", `arn:aws:iam::${external}:role/NexoraCSPMReadOnly`, `nx-${"x".repeat(20)}${external}`, o.status ?? "connected", o.schedule ?? "daily", o.failures ?? 0]);
  return { id: r.rows[0]!.id as string, accountId: external };
}
const row = async (id: string) => (await db.query(`select status, schedule, failure_count, last_error, last_scheduled_at, last_sync_at, extract(epoch from (next_run_at - now())) as secs, scan_started_at from cloud_accounts where id = $1`, [id])).rows[0]!;
const hours = (secs: number) => secs / 3600;
const near = (secs: number, h: number, extraMin = 11) => hours(secs) >= h - 0.02 && hours(secs) <= h + extraMin / 60; // interval plus up to 10 min of jitter
// every test starts clean: the scheduler scans ALL due accounts, so schedules left over from earlier tests are switched off
const reset = async () => { aws.reset(); outbox.length = 0; await db.query("update cloud_accounts set schedule = 'off', next_run_at = null"); };

test("only accounts that are due, connected and switched on are scanned; the scan is an account scan with no user", async () => {
  await reset(); const o = await org();
  const a = await account(o.id);                                                 // due
  const notYet = await account(o.id, { due: "now() + interval '1 hour'" });
  const off = await account(o.id, { schedule: "off", due: "now() - interval '1 hour'" });
  const pending = await account(o.id, { status: "pending" });
  const broken = await account(o.id, { status: "error" });
  const res = await runDueScans(deps(), 10);
  assert.deepEqual(res, { scanned: 1, failed: 0, skipped: 0 });
  assert.deepEqual(aws.collected, [a.accountId]);
  const after = await row(a.id);
  assert.equal(after.failure_count, 0); assert.ok(after.last_scheduled_at); assert.ok(after.last_sync_at);
  assert.ok(near(after.secs, 24), `next run in ${hours(after.secs)} h`);        // a day later (plus jitter)
  for (const x of [notYet, off, pending, broken]) assert.equal((await row(x.id)).last_scheduled_at, null);
  const scan = (await db.query("select source, created_by, account_id, finding_count from scans where org_id = $1", [o.id])).rows;
  assert.deepEqual(scan.map((s) => [s.source, s.created_by, s.account_id]), [["account", null, a.id]]);
  const log = (await db.query("select action, actor_id from audit_events where org_id = $1", [o.id])).rows;
  assert.deepEqual(log.map((l) => [l.action, l.actor_id]), [["cloud.scan.scheduled", null]]);
});

test("weekly accounts come back after a week; the batch limit leaves the rest due", async () => {
  await reset(); const o = await org();
  const weekly = await account(o.id, { schedule: "weekly" });
  await runDueScans(deps(), 10);
  assert.ok(near((await row(weekly.id)).secs, 24 * 7));
  const many = await Promise.all(Array.from({ length: 5 }, () => account(o.id)));
  aws.collected = [];
  const r = await runDueScans(deps(), 3);
  assert.equal(r.scanned, 3);
  const untouched = (await Promise.all(many.map((m) => row(m.id)))).filter((x) => x.last_scheduled_at === null);
  assert.equal(untouched.length, 2); assert.ok(untouched.every((x) => x.secs <= 0)); // still due, picked up by the next tick
});

test("two scheduler instances running at once scan each account exactly once", async () => {
  await reset(); const o = await org(); aws.delayMs = 80;
  const accts = await Promise.all(Array.from({ length: 4 }, () => account(o.id, { due: "now() - interval '2 minutes'" })));
  const [a, b] = await Promise.all([runDueScans(deps(), 10), runDueScans(deps(), 10)]);
  assert.equal(a.scanned + b.scanned, 4);
  assert.deepEqual([...aws.collected].sort(), accts.map((x) => x.accountId).sort());
});

test("an account being scanned right now is left alone; an abandoned lease (older than 20 minutes) is taken over", async () => {
  await reset(); const o = await org();
  const busy = await account(o.id, { lease: "now() - interval '2 minutes'" });
  const stale = await account(o.id, { lease: "now() - interval '30 minutes'" });
  const r = await runDueScans(deps(), 10);
  assert.equal(r.scanned, 1); assert.deepEqual(aws.collected, [stale.accountId]);
  assert.ok((await row(busy.id)).secs <= 0);       // not claimed, still due
  assert.equal((await row(stale.id)).scan_started_at, null); // the lease is released after the scan
  // the shared scan service refuses a second scan of a leased account (this is what protects manual scans too)
  const auth = { userId: null, orgId: o.id, role: "analyst" as const, email: null, via: "key" as const };
  const view = db.scoped(o.id);
  try {
    await assert.rejects(() => scanConnection(view, fakeAws, auth, { id: busy.id, accountId: busy.accountId, region: "eu-west-1", roleArn: "x", externalId: "y", status: "connected" }), (e: any) => e.code === "scan_running" && e.status === 409);
  } finally { await view.release(true); } // a scoped view holds a pooled connection until released
});

test("a plan with no scans left is skipped without calling AWS, retried later, and not counted as a failure", async () => {
  await reset(); const o = await org("free");
  for (let i = 0; i < 10; i++) await db.query("insert into usage_events (org_id, kind, period) values ($1,'scan',to_char(now() at time zone 'utc','YYYY-MM'))", [o.id]);
  const a = await account(o.id);
  const r = await runDueScans(deps(), 10);
  assert.deepEqual(r, { scanned: 0, failed: 0, skipped: 1 });
  assert.equal(aws.collected.length, 0);
  const x = await row(a.id);
  assert.equal(x.failure_count, 0); assert.match(x.last_error, /used all 10 scans/); assert.ok(near(x.secs, 6));
  assert.equal(x.schedule, "daily");
});

test("a transient failure backs off 1h, 2h, ... and a success resets the count", async () => {
  await reset(); const o = await org(); const a = await account(o.id);
  aws.result = () => new AwsError("throttled", "AWS is rate limiting the requests. Try again in a minute.");
  assert.deepEqual(await runDueScans(deps(), 10), { scanned: 0, failed: 1, skipped: 0 });
  let x = await row(a.id);
  assert.equal(x.failure_count, 1); assert.match(x.last_error, /rate limiting/); assert.ok(near(x.secs, 1), `${hours(x.secs)}`); assert.equal(x.schedule, "daily");
  await db.query("update cloud_accounts set next_run_at = now() - interval '1 minute' where id = $1", [a.id]);
  await runDueScans(deps(), 10);
  x = await row(a.id); assert.equal(x.failure_count, 2); assert.ok(near(x.secs, 2));
  assert.equal(outbox.length, 0); // nobody is emailed for a failure that may fix itself
  aws.reset();
  await db.query("update cloud_accounts set next_run_at = now() - interval '1 minute' where id = $1", [a.id]);
  await runDueScans(deps(), 10);
  x = await row(a.id); assert.equal(x.failure_count, 0); assert.equal(x.last_error, null); assert.ok(near(x.secs, 24));
});

test("after five failures in a row the schedule is switched off and owners and admins (not viewers) are emailed once", async () => {
  await reset(); const o = await org(); const a = await account(o.id, { failures: MAX_FAILURES - 1 });
  aws.result = () => new AwsError("platform_credentials", "NEXORA's own AWS credentials are not working on the server.");
  await runDueScans(deps(), 10);
  const x = await row(a.id);
  assert.equal(x.schedule, "off"); assert.equal(x.secs, null); assert.equal(x.failure_count, MAX_FAILURES);
  assert.deepEqual(outbox.map((m) => m.to).sort(), [o.admin.email, o.owner.email].sort());
  assert.match(outbox[0]!.subject, /Automatic AWS scans stopped/); assert.match(outbox[0]!.text, /failed 5 times in a row/);
  assert.equal(outbox.some((m) => m.to === o.viewer.email), false);
  assert.ok((await db.query("select 1 from audit_events where org_id = $1 and action = 'cloud.schedule_disabled'", [o.id])).rows.length === 1);
  outbox.length = 0; aws.collected = [];
  await runDueScans(deps(), 10);
  assert.equal(aws.collected.length, 0); assert.equal(outbox.length, 0); // it stays off and quiet
});

test("a role that can no longer be assumed stops the schedule at once, marks the connection, and tells the admins", async () => {
  await reset(); const o = await org(); const a = await account(o.id);
  aws.result = () => new AwsError("assume_denied", "NEXORA could not assume the role. Check the trust policy.");
  assert.deepEqual(await runDueScans(deps(), 10), { scanned: 0, failed: 1, skipped: 0 });
  const x = await row(a.id);
  assert.equal(x.status, "error"); assert.equal(x.schedule, "off"); assert.equal(x.failure_count, 0); assert.match(x.last_error, /trust policy/);
  assert.equal(outbox.length, 2); assert.match(outbox[0]!.text, /read-only role no longer works/);
  await runDueScans(deps(), 10); assert.equal(aws.collected.length, 1); // not retried
});

test("an account with nothing in it counts as a failure and is retried later", async () => {
  await reset(); const o = await org(); const a = await account(o.id);
  aws.result = () => ({ resources: [], notes: ["S3: access denied on 1 bucket."], complete: false });
  await runDueScans(deps(), 10);
  const x = await row(a.id); assert.equal(x.failure_count, 1); assert.match(x.last_error, /Nothing was found/);
});

test("an incomplete scheduled scan never closes findings on resources it did not see", async () => {
  await reset(); const o = await org(); const a = await account(o.id);
  const b = (name: string) => ({ type: "s3_bucket", name, public_read: true, encrypted: true });
  aws.result = () => ({ resources: [b("keep"), b("other")], notes: [], complete: true });
  await runDueScans(deps(), 10);
  assert.equal((await db.query("select count(*)::int as n from findings where org_id = $1 and status = 'open'", [o.id])).rows[0]!.n, 2);
  await db.query("update cloud_accounts set next_run_at = now() - interval '1 minute' where id = $1", [a.id]);
  aws.result = () => ({ resources: [b("keep")], notes: ["S3: access denied on 1 bucket."], complete: false });
  await runDueScans(deps(), 10);
  assert.equal((await db.query("select count(*)::int as n from findings where org_id = $1 and status = 'open'", [o.id])).rows[0]!.n, 2); // "other" stays open
  await db.query("update cloud_accounts set next_run_at = now() - interval '1 minute' where id = $1", [a.id]);
  aws.result = () => ({ resources: [b("keep")], notes: [], complete: true });
  await runDueScans(deps(), 10);
  assert.equal((await db.query("select count(*)::int as n from findings where org_id = $1 and status = 'open'", [o.id])).rows[0]!.n, 1); // a complete scan does close it
});

test("organizations stay apart: each scheduled scan writes only to its own organization", async () => {
  await reset(); const o1 = await org(); const o2 = await org();
  const a1 = await account(o1.id), a2 = await account(o2.id);
  await runDueScans(deps(), 10);
  for (const [o, a] of [[o1, a1], [o2, a2]] as const) {
    const scans = (await db.query("select account_id from scans where org_id = $1", [o.id])).rows;
    assert.deepEqual(scans.map((s) => s.account_id), [a.id]);
    const stray = (await db.query("select count(*)::int as n from assets where org_id = $1 and account_id is not null and account_id <> $2", [o.id, a.id])).rows[0]!.n;
    assert.equal(stray, 0);
  }
  assert.equal((await db.query("select count(*)::int as n from findings f join assets a on a.id = f.asset_id where f.org_id <> a.org_id")).rows[0]!.n, 0);
});

test("nothing runs when the AWS connector is not enabled", async () => {
  await reset(); const o = await org(); const a = await account(o.id);
  const r = await runDueScans({ db, aws: { ...fakeAws, enabled: false }, mailer }, 10);
  assert.deepEqual(r, { scanned: 0, failed: 0, skipped: 0 });
  assert.ok((await row(a.id)).secs <= 0); // not even claimed
});

test("the periodic loop picks up due accounts, never overlaps itself, and stop() waits for a running scan", async () => {
  await reset(); const o = await org(); const a = await account(o.id); aws.delayMs = 300;
  const s = startScheduler(deps(), 40);
  await new Promise((r) => setTimeout(r, 200));      // several ticks pass while the first scan is still running
  assert.equal(aws.collected.length, 1);             // one scan, not one per tick
  await s.stop();                                    // waits for it to finish
  assert.ok((await row(a.id)).last_scheduled_at);
  const before = aws.collected.length;
  await db.query("update cloud_accounts set next_run_at = now() - interval '1 minute' where id = $1", [a.id]);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(aws.collected.length, before);        // stopped: no more scans
});

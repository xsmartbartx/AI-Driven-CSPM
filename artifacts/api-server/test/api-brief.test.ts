import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");
const { sendDueDigests, sendDueWeeklyReports } = await import("../src/services/notifications.ts");
const { schedulerEnabled } = await import("../src/config.ts");

let server: Server;
let base: string;
let db: Awaited<ReturnType<typeof openDb>>;
const sent: any[] = [];
const mailer = { enabled: true, send: async (m: any) => { sent.push(m); return true; } };
before(async () => {
  db = await openDb(process.env["TEST_DATABASE_URL"] ? { url: process.env["TEST_DATABASE_URL"] } : { dataDir: ":memory:" });
  server = createApp(db, { mailer }).listen(0);
  base = `http://127.0.0.1:${(server.address() as any).port}/api`;
});
after(async () => { server.close(); await db.close(); });

class Client {
  cookie = "";
  async call(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { "content-type": "application/json", origin: "http://localhost:5174", "x-csrf": "1" };
    if (this.cookie) headers["cookie"] = this.cookie;
    const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = res.headers.get("set-cookie"); if (sc) this.cookie = sc.split(";")[0]!;
    const text = await res.text(); let json: any = null; try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json, text };
  }
  get = (p: string) => this.call("GET", p);
  post = (p: string, b?: unknown) => this.call("POST", p, b ?? {});
  put = (p: string, b?: unknown) => this.call("PUT", p, b ?? {});
  patch = (p: string, b?: unknown) => this.call("PATCH", p, b ?? {});
}
let n = 0;
async function signup() {
  resetRateLimits();
  const c = new Client();
  const email = `brief${++n}-${Date.now()}@example.com`;
  const r = await c.post("/auth/signup", { email, password: "correct horse battery", orgName: `Brief ${n}` });
  assert.equal(r.status, 201, r.text);
  await new Promise((r) => setTimeout(r, 50)); sent.length = 0;
  return { c, me: r.json, email };
}
const bucket = (name: string, extra: object = {}) => ({ type: "s3_bucket", name, public_read: true, ...extra });

test("before any scan there is nothing to report", async () => {
  const { c } = await signup();
  const b = (await c.get("/brief")).json;
  assert.equal(b.hasData, false); assert.match(b.headline, /No scans yet/);
  assert.equal((await new Client().get("/brief")).status, 401);
});

test("the brief states what is open, what is new, what was fixed and what is coming due, each traceable to findings", async () => {
  const { c, me } = await signup();
  await c.post("/scans", { config: [bucket("a"), bucket("b")] });
  let b = (await c.get("/brief")).json;
  assert.equal(b.hasData, true);
  assert.equal(b.newFindings.total, 2); assert.equal(b.newFindings.items.length, 2);
  assert.equal(b.fixed, 0); assert.equal(b.topRisks.length, 2);
  assert.match(b.lines[0], /2 open findings/); assert.match(b.lines.join(" "), /2 new findings in the last day/);
  assert.match(b.headline, /critical finding|new findings/);
  // time passes: nothing is new any more; then one bucket is fixed
  await db.query("update findings set first_seen_at = now() - interval '3 days' where org_id = $1", [me.org.id]);
  b = (await c.get("/brief")).json;
  assert.equal(b.newFindings.total, 0); assert.match(b.lines.join(" "), /No new findings in the last day/);
  assert.equal((await c.get("/brief?hours=720")).json.newFindings.total, 2);                // a wider window sees them
  await c.post("/scans", { config: [bucket("a"), bucket("b", { public_read: false })] });
  b = (await c.get("/brief")).json;
  assert.equal(b.fixed, 1); assert.match(b.lines.join(" "), /1 finding was fixed in the last day/); assert.match(b.lines[0], /1 open finding/);
  // an accepted risk due for review soon, and a suppression about to end
  const f = (await c.get("/findings")).json.items[0];
  const soon = new Date(Date.now() + 5 * 86400_000).toISOString();
  await c.patch(`/findings/${f.id}`, { status: "accepted", reason: "Tracked in the backlog", acceptedUntil: soon });
  await c.post("/scans", { config: [bucket("c")] });
  await c.post("/suppressions", { ruleId: "s3-public-read", reason: "Short exception", expiresInDays: 3 });
  b = (await c.get("/brief")).json;
  assert.equal(b.expiring.acceptedRisks, 1); assert.equal(b.expiring.suppressions, 1);
  assert.match(b.lines.join(" "), /1 accepted risk is due for review within 14 days/); assert.match(b.lines.join(" "), /1 rule suppression ends within 14 days/);
  // suppressed findings are not news and not open
  assert.equal(b.open.critical + b.open.high + b.open.medium + b.open.low, 0);
  assert.equal(b.newFindings.total, 0);
  assert.equal((await c.get("/brief?hours=0")).status, 400); assert.equal((await c.get("/brief?hours=9999")).status, 400);
});

test("the daily summary email: off by default, sent once to owners and admins when on and there is news, never on a quiet day", async () => {
  const a = await signup(), quiet = await signup(), off = await signup();
  for (const x of [a, quiet, off]) await x.c.post("/scans", { config: [bucket("pub")] });
  await a.c.put("/notifications", { dailyDigest: true });
  assert.equal((await a.c.get("/notifications")).json.dailyDigest, true);
  await quiet.c.put("/notifications", { dailyDigest: true });
  await db.query("update findings set first_seen_at = now() - interval '3 days' where org_id = $1", [quiet.me.org.id]);
  await db.query("update findings set severity = 'low' where org_id = $1", [quiet.me.org.id]); // no critical, nothing new, nothing fixed, nothing due: a quiet day
  // an analyst in org a must not get it
  const inv = await a.c.post("/team/invite", { email: `an-${Date.now()}@example.com`, role: "analyst" });
  const analyst = new Client(); await analyst.post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "analyst password 12" });
  sent.length = 0;
  await sendDueDigests({ db, mailer }, 0);
  assert.deepEqual(sent.map((m) => m.to), [a.email]);                                          // not quiet, not off, not the analyst
  assert.match(sent[0].subject, /Brief \d+: /); assert.match(sent[0].text, /open finding/); assert.match(sent[0].text, /Open the dashboard/);
  sent.length = 0;
  await sendDueDigests({ db, mailer }, 0);
  assert.equal(sent.length, 0);                                                                // once a day
  await db.query("update notification_settings set last_digest_at = now() - interval '25 hours' where org_id = $1", [a.me.org.id]);
  await sendDueDigests({ db, mailer }, 0);
  assert.equal(sent.length, 1);                                                                // and again the next day
  sent.length = 0;
  await db.query("update notification_settings set last_digest_at = null where org_id = $1", [a.me.org.id]);
  await sendDueDigests({ db, mailer }, 24);                                                    // before the hour it is allowed to go out
  assert.equal(sent.length, 0);
  assert.equal((await off.c.get("/notifications")).json.dailyDigest, false);
});

test("the weekly report: off by default, once a week to owners and admins, even on a quiet week, never before the first scan", async () => {
  const a = await signup(), fresh = await signup(), off = await signup();
  await a.c.post("/scans", { config: [bucket("pub")] }); await off.c.post("/scans", { config: [bucket("pub")] });
  assert.equal((await a.c.get("/notifications")).json.weeklyReport, false);
  await a.c.put("/notifications", { weeklyReport: true }); await fresh.c.put("/notifications", { weeklyReport: true });
  assert.equal((await a.c.get("/notifications")).json.weeklyReport, true);
  await db.query("update findings set first_seen_at = now() - interval '30 days' where org_id = $1", [a.me.org.id]); // a quiet week
  const inv = await a.c.post("/team/invite", { email: `an-${Date.now()}@example.com`, role: "analyst" });
  await new Client().post("/invites/accept", { token: inv.json.link.split("/invite/")[1], password: "analyst password 12" });
  sent.length = 0;
  await sendDueWeeklyReports({ db, mailer }, 0, true);
  assert.deepEqual(sent.map((m) => m.to), [a.email]);                                            // not the analyst, not the org that is off, not the one without scans
  assert.match(sent[0].subject, /Brief \d+: your week in cloud security \(score \d+\)/);
  assert.match(sent[0].text, /No new findings in the last week/); assert.match(sent[0].text, /Highest risks right now:/); assert.match(sent[0].text, /1\. \w+ .+ on pub/);
  assert.match(sent[0].text, /\/report/);
  sent.length = 0;
  await sendDueWeeklyReports({ db, mailer }, 0, true);
  assert.equal(sent.length, 0);                                                                  // once a week
  await db.query("update notification_settings set last_weekly_at = now() - interval '7 days' where org_id = $1", [a.me.org.id]);
  await sendDueWeeklyReports({ db, mailer }, 0, true);
  assert.equal(sent.length, 1);
  // Monday only, and after the hour
  sent.length = 0;
  await db.query("update notification_settings set last_weekly_at = null where org_id = $1", [a.me.org.id]);
  await sendDueWeeklyReports({ db, mailer }, 24, true);
  assert.equal(sent.length, 0);
  const isMonday = new Date().getUTCDay() === 1;
  await sendDueWeeklyReports({ db, mailer }, 0, false);
  assert.equal(sent.length, isMonday ? 1 : 0, "outside Mondays nothing goes out");
});

test("the weekly report lists the new findings the brief mentions and five top risks, not three", async () => {
  const a = await signup();
  await a.c.post("/scans", { config: Array.from({ length: 7 }, (_, i) => bucket(`pub${i}`)) });
  await a.c.put("/notifications", { weeklyReport: true });
  sent.length = 0;
  await sendDueWeeklyReports({ db, mailer }, 0, true);
  const mine = sent.filter((m) => m.to === a.email); // other organizations in this database may have a report due too
  assert.equal(mine.length, 1);
  const text: string = mine[0].text;
  assert.match(text, /7 new findings in the last week, the 5 highest are listed/);
  assert.equal((text.match(/^New: /gm) ?? []).length, 5);                                       // what the sentence promises
  assert.equal((text.match(/^\d\. /gm) ?? []).length, 5);                                        // five top risks
  assert.equal((await a.c.get("/brief")).json.topRisks.length, 3);                             // the dashboard brief keeps three
});

test("the background tick (suppression expiry, daily summary, weekly report) does not depend on AWS being configured", () => {
  assert.equal(schedulerEnabled({}), true);                                                     // no CSPM_AWS_ACCOUNT_ID
  assert.equal(schedulerEnabled({ CSPM_AWS_ACCOUNT_ID: "123456789012" }), true);
  assert.equal(schedulerEnabled({ SCHEDULER: "0" }), false);                                    // and it can still be switched off
  assert.equal(schedulerEnabled({ SCHEDULER: "1" }), true);
});

test("report delivery: an organization that has not scanned is not claimed, and a first scan the same day still gets its report", async () => {
  const x = await signup();
  await x.c.put("/notifications", { weeklyReport: true, dailyDigest: true });
  await sendDueWeeklyReports({ db, mailer }, 0, true); await sendDueDigests({ db, mailer }, 0);
  const row = async () => (await db.query("select last_weekly_at, last_digest_at from notification_settings where org_id = $1", [x.me.org.id])).rows[0];
  assert.deepEqual(await row(), { last_weekly_at: null, last_digest_at: null });                // not claimed, so not used up
  await x.c.post("/scans", { config: [bucket("late")] });
  sent.length = 0;
  await sendDueWeeklyReports({ db, mailer }, 0, true); await sendDueDigests({ db, mailer }, 0);
  assert.equal(sent.filter((m) => m.to === x.email).length, 2);                                 // the weekly report and the daily summary
});

test("report delivery: organizations are claimed one at a time inside a time budget, so a stop loses at most the one in hand", async () => {
  const orgs = [await signup(), await signup(), await signup()];
  for (const o of orgs) { await o.c.post("/scans", { config: [bucket("p")] }); await o.c.put("/notifications", { weeklyReport: true }); }
  await db.query("update notification_settings set weekly_report = false where org_id <> all($1::uuid[])", [orgs.map((o) => o.me.org.id)]); // only these three are due
  const slow = { enabled: true, send: async (m: any) => { await new Promise((r) => setTimeout(r, 120)); sent.push(m); return true; } };
  sent.length = 0;
  await sendDueWeeklyReports({ db, mailer: slow }, 0, true, 100);                              // budget 100 ms, one send takes 120 ms
  const claimed = (await db.query("select count(*)::int as n from notification_settings where last_weekly_at is not null and org_id = any($1::uuid[])", [orgs.map((o) => o.me.org.id)])).rows[0].n;
  assert.equal(claimed, 1); assert.equal(sent.length, 1);                                       // one claimed and delivered; the others wait for the next tick, unclaimed
  await sendDueWeeklyReports({ db, mailer }, 0, true);                                          // the next tick finishes the rest
  assert.deepEqual(new Set(sent.map((m) => m.to)), new Set(orgs.map((o) => o.email)));
  assert.equal(sent.length, 3);
});

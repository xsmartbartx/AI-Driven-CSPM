import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

process.env["APP_ORIGINS"] = "http://localhost:5174";
process.env["NODE_ENV"] = "test";

const { openDb } = await import("@workspace/db");
const { createApp } = await import("../src/app.ts");
const { resetRateLimits } = await import("../src/lib/ratelimit.ts");
const { sendDueDigests, sendDueWeeklyReports } = await import("../src/services/notifications.ts");

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
  assert.match(sent[0].text, /No new findings this week/); assert.match(sent[0].text, /Highest risks right now:/); assert.match(sent[0].text, /1\. \w+ .+ on pub/);
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

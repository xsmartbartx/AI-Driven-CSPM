// Dev seed: one demo org with a scan of the sample config. Fake data only. Run: pnpm --filter @workspace/api-server seed
import { SAMPLE_CONFIG } from "@workspace/cspm-engine";
import { openDb } from "@workspace/db";
import { config } from "./config";
import { hashPassword } from "./lib/crypto";
import { runScan } from "./services/scans";

const db = await openDb({ url: config.databaseUrl, dataDir: config.dataDir });
const email = "demo@example.com";
if ((await db.query("select 1 from users where email = $1", [email])).rows.length) { console.log("seed: demo user exists"); await db.close(); process.exit(0); }
const pw = process.env["SEED_PASSWORD"] ?? "demo-password-change-me";
const ids = await db.tx(async (q) => {
  const u = (await q.query("insert into users (email, name, password_hash) values ($1,'Demo',$2) returning id", [email, await hashPassword(pw)])).rows[0];
  const o = (await q.query("insert into organizations (name) values ('Demo organization') returning id")).rows[0];
  await q.query("insert into members (org_id, user_id, role) values ($1,$2,'owner')", [o.id, u.id]);
  return { userId: u.id as string, orgId: o.id as string };
});
await runScan(db, { ...ids, role: "owner", email, via: "session" }, SAMPLE_CONFIG);
console.log(`seed: created ${email}`);
await db.close();

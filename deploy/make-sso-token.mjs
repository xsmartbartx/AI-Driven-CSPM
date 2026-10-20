#!/usr/bin/env node
// Shows what onenexora.com must do to send a signed-in Nexora user to CSPM.
// Usage: SSO_SECRET=... node deploy/make-sso-token.mjs user@example.com "Pat" nexora-user-id nexora-org-id "Acme Inc" [admin|analyst|viewer]
// The SAME logic goes into the Nexora console (server side only, never in the browser; the secret must stay secret).
import { createHmac, randomUUID } from "node:crypto";
const [email, name, sub, org, orgName, role = "viewer"] = process.argv.slice(2);
const secret = process.env.SSO_SECRET;
if (!secret || !email || !sub || !org) { console.error("need SSO_SECRET and email name sub org orgName [role]"); process.exit(1); }
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
const head = b64u({ alg: "HS256", typ: "JWT" });
const body = b64u({ sub, email, name, org, orgName, role, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 120 }); // valid 2 minutes, one use
const sig = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
console.log(`${process.env.API_URL ?? "https://api.cspm.onenexora.com"}/api/auth/sso?token=${head}.${body}.${sig}`);

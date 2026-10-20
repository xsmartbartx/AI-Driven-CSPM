import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createCspmSignInUrl, createCspmToken } from "../src/index.ts";

const secret = "a".repeat(40);
const user = { id: "u1", email: "pat@example.com", name: "Pat", orgId: "o1", orgName: "Acme" };
const claims = (t: string) => JSON.parse(Buffer.from(t.split(".")[1]!, "base64url").toString());

test("token is HS256-signed, short-lived, one-time and carries the user", () => {
  const t = createCspmToken({ secret, user, now: () => 1_000_000_000_000 });
  const [h, b, s] = t.split(".");
  assert.equal(JSON.parse(Buffer.from(h!, "base64url").toString()).alg, "HS256");
  assert.equal(s, createHmac("sha256", secret).update(`${h}.${b}`).digest("base64url"));
  const c = claims(t);
  assert.deepEqual([c.sub, c.email, c.org, c.orgName, c.role], ["u1", "pat@example.com", "o1", "Acme", "viewer"]);
  assert.equal(c.exp - c.iat, 120);
  assert.notEqual(claims(createCspmToken({ secret, user })).jti, claims(createCspmToken({ secret, user })).jti); // fresh jti every time
});

test("lifetime is clamped to 10 seconds..9 minutes, leaving a minute of clock skew below the API's 10-minute limit", () => {
  const long = claims(createCspmToken({ secret, user, ttlSeconds: 86400 })); // one token: comparing two could straddle a second boundary
  assert.equal(long.exp - long.iat, 540);
  const short = claims(createCspmToken({ secret, user, ttlSeconds: 1 })); assert.equal(short.exp - short.iat, 10);
});

test("refuses weak secrets and bad input", () => {
  assert.throws(() => createCspmToken({ secret: "short", user }), /32 characters/);
  assert.throws(() => createCspmToken({ secret, user: { ...user, email: "not-an-email" } }), /valid email/);
  assert.throws(() => createCspmToken({ secret, user: { ...user, orgId: "" } }), /orgId/);
});

test("sign-in URL points at the API and refuses plain http outside localhost", () => {
  assert.match(createCspmSignInUrl({ secret, apiUrl: "https://api.cspm.onenexora.com/", user }), /^https:\/\/api\.cspm\.onenexora\.com\/api\/auth\/sso\?token=[\w-]+\.[\w-]+\.[\w-]+$/);
  assert.ok(createCspmSignInUrl({ secret, apiUrl: "http://localhost:8080", user }).startsWith("http://localhost:8080/api/auth/sso?token="));
  assert.throws(() => createCspmSignInUrl({ secret, apiUrl: "http://api.example.com", user }), /https/);
});

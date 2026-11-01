import { test } from "node:test";
import assert from "node:assert/strict";
import { fixFor, RULES, RULES_WITH_FIXES, tfIdent } from "../src/index.ts";

test("every rule has a fix as code, and a new rule without one fails here", () => {
  assert.deepEqual(RULES.map((r) => r.id).filter((id) => !RULES_WITH_FIXES.includes(id)), []);
  assert.deepEqual(RULES_WITH_FIXES.filter((id) => !RULES.some((r) => r.id === id)), []);
  for (const r of RULES) { const f = fixFor(r.id, { resourceName: "my-asset", evidence: {} })!; assert.ok(((f.terraform ?? f.yaml ?? "").length > 20) && f.notes.length > 0, r.id); }
  assert.equal(fixFor("no-such-rule", { resourceName: "x", evidence: {} }), null);
});

test("snippets name the asset, use the AWS identifier from \"name (id)\", and read the ports from the evidence", () => {
  const s3 = fixFor("s3-public-read", { resourceName: "uploads-prod", evidence: {} })!;
  assert.match(s3.terraform!, /resource "aws_s3_bucket_public_access_block" "uploads_prod"/); assert.match(s3.awsCli!, /--bucket "uploads-prod"/);
  const sg = fixFor("sg-sensitive-port-open", { resourceName: "web (sg-0abc123)", evidence: { ports: ["22 (SSH)", "3306 (MySQL)"] } })!;
  assert.match(sg.terraform!, /aws_security_group\.web_sg_0abc123/); assert.match(sg.terraform!, /from_port   = 22/); assert.match(sg.terraform!, /from_port   = 3306/);
  const db = fixFor("db-public", { resourceName: "orders-db (db-7)", evidence: {} })!;
  assert.match(db.awsCli!, /--db-instance-identifier "db-7"/);
  assert.match(fixFor("db-no-encryption", { resourceName: "d", evidence: {} })!.notes.join(" "), /replaces it/); // the cost is stated
});

test("a hostile resource name cannot break out of the identifier, the string or the line", () => {
  const evil = ['x"; rm -rf / #', "a\nresource \"aws_iam_user\" \"pwn\" {}", "b${file(\"/etc/passwd\")}", "c`id`", "d$(whoami)", "e' || true '"];
  for (const name of evil) {
    for (const ruleId of ["s3-public-read", "s3-no-encryption", "sg-open-world", "iam-admin-access", "db-public"]) {
      const f = fixFor(ruleId, { resourceName: name, evidence: { ports: [name] } })!;
      const all = (f.terraform ?? "") + "\n" + (f.yaml ?? "") + "\n" + (f.awsCli ?? "");
      // the only places user text can land: identifiers made of [a-z0-9_], and a quoted CLI argument of plain characters
      for (const m of (f.terraform ?? "").matchAll(/^resource "[a-z_]+" "([^"]*)"/gm)) assert.match(m[1]!, /^[a-z][a-z0-9_]*$/, `${ruleId}: identifier`);
      for (const m of (f.terraform ?? "").matchAll(/\.([A-Za-z0-9_]+)(?=[.\s]|$)/g)) assert.match(m[1]!, /^[A-Za-z0-9_]+$/);
      for (const m of (f.awsCli ?? "").matchAll(/--(?:bucket|db-instance-identifier) "([^"]*)"/g)) assert.match(m[1]!, /^[\w .:/@+=-]*$/, `${ruleId}: CLI argument`);
      assert.ok(!/`|\$\(|\$\{file|\n\s*resource "aws_iam_user"/.test(all), `${ruleId}: ${JSON.stringify(name)}`);
      assert.ok(!/[\n\r]/.test(f.awsCli ?? ""), "the CLI command is one line");
    }
  }
  assert.equal(tfIdent('x"; rm -rf / #'), "x_rm_rf"); assert.equal(tfIdent("9lives"), "r_9lives"); assert.equal(tfIdent("***"), "r_resource"); assert.match(tfIdent("a".repeat(500)), /^a{60}$/);
});

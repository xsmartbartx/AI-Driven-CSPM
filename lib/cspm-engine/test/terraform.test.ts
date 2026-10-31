import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, fromTerraformPlan } from "../src/index.ts";

const rc = (address: string, type: string, after: object, extra: object = {}) => ({ address, mode: "managed", type, name: address.split(".").pop(), change: { actions: ["create"], after, after_unknown: {}, ...extra } });
const conf = (address: string, expressions: object) => ({ address, mode: "managed", type: address.split(".")[0], expressions });
const ref = (...r: string[]) => ({ references: r });

const PLAN = {
  format_version: "1.2",
  resource_changes: [
    rc("aws_s3_bucket.assets", "aws_s3_bucket", { bucket: "assets", acl: null, tags: { Environment: "production" } }),
    rc("aws_s3_bucket_acl.assets", "aws_s3_bucket_acl", { acl: "public-read" }),
    rc("aws_s3_bucket.logs", "aws_s3_bucket", { bucket: "logs" }),
    rc("aws_s3_bucket_acl.logs", "aws_s3_bucket_acl", { acl: "public-read" }),
    rc("aws_s3_bucket_public_access_block.logs", "aws_s3_bucket_public_access_block", { block_public_acls: true, ignore_public_acls: true }),
    rc("aws_s3_bucket.legacy", "aws_s3_bucket", { bucket: "legacy", acl: "public-read-write" }),
    rc("aws_security_group.web", "aws_security_group", { ingress: [{ cidr_blocks: ["0.0.0.0/0"], ipv6_cidr_blocks: [], from_port: 22, to_port: 22, protocol: "tcp" }, { cidr_blocks: ["10.0.0.0/8"], from_port: 443, to_port: 443, protocol: "tcp" }], tags: { Environment: "staging" } }),
    rc("aws_vpc_security_group_ingress_rule.db", "aws_vpc_security_group_ingress_rule", { cidr_ipv4: "0.0.0.0/0", from_port: 5432, to_port: 5432, ip_protocol: "tcp" }),
    rc("aws_iam_policy.admin", "aws_iam_policy", { policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }) }),
    rc("aws_iam_policy.later", "aws_iam_policy", {}, { after_unknown: { policy: true } }),
    rc("aws_db_instance.main", "aws_db_instance", { publicly_accessible: true, storage_encrypted: false }),
    rc("module.data.aws_db_instance.replica[0]", "aws_db_instance", { publicly_accessible: false, storage_encrypted: true }),
    rc("aws_s3_bucket.gone", "aws_s3_bucket", { acl: "public-read" }, { actions: ["delete"] }),
    rc("aws_lambda_function.fn", "aws_lambda_function", {}), rc("aws_lambda_function.fn2", "aws_lambda_function", {}),
  ],
  configuration: { root_module: { resources: [
    conf("aws_s3_bucket_acl.assets", { bucket: ref("aws_s3_bucket.assets.id", "aws_s3_bucket.assets") }),
    conf("aws_s3_bucket_acl.logs", { bucket: ref("aws_s3_bucket.logs.id", "aws_s3_bucket.logs") }),
    conf("aws_s3_bucket_public_access_block.logs", { bucket: ref("aws_s3_bucket.logs.id") }),
    conf("aws_vpc_security_group_ingress_rule.db", { security_group_id: ref("aws_security_group.web.id") }),
  ] } },
};

test("a plan becomes the resources the rules read: public ACLs (also through separate resources), open ingress, admin policies, public databases", () => {
  const r = fromTerraformPlan(PLAN);
  assert.deepEqual(r.errors, []);
  const byName = new Map(r.resources.map((x) => [x.name, x]));
  assert.equal(byName.get("aws_s3_bucket.assets")!["public_read"], true);         // acl lives in a separate resource, linked by reference
  assert.equal(byName.get("aws_s3_bucket.assets")!["environment"], "production");  // from the tag
  assert.equal(byName.get("aws_s3_bucket.logs")!["public_read"], undefined);       // the public access block cancels the ACL
  assert.equal(byName.get("aws_s3_bucket.legacy")!["public_read"], true);          // legacy inline acl
  assert.ok(!byName.has("aws_s3_bucket.gone"));                                     // deleted resources are not checked
  const sg = byName.get("aws_security_group.web")!;
  assert.deepEqual((sg["ingress"] as any[]).map((i) => `${i.cidr}:${i.fromPort ?? i.port}`), ["0.0.0.0/0:22", "10.0.0.0/8:443", "0.0.0.0/0:5432"]); // inline rules + the standalone one
  assert.equal(sg["environment"], "staging");
  assert.ok(byName.has("module.data.aws_db_instance.replica[0]"));
  assert.deepEqual(r.skipped, [{ type: "aws_lambda_function", count: 2 }]);
  assert.ok(r.notes.some((n) => /aws_iam_policy.later: the policy is not known until apply/.test(n)));
});

test("the rules find what is wrong in the plan, and only that", () => {
  const { findings } = evaluate(fromTerraformPlan(PLAN).resources);
  const got = findings.map((f) => `${f.ruleId} ${f.resourceName}`).sort();
  assert.deepEqual(got, [
    "db-no-encryption aws_db_instance.main", "db-public aws_db_instance.main", "iam-admin-access aws_iam_policy.admin",
    "s3-public-read aws_s3_bucket.assets", "s3-public-read aws_s3_bucket.legacy",
    "sg-sensitive-port-open aws_security_group.web",
  ].sort());
});

test("input that is not a plan is refused with the command that makes one; inline role policies and the size limit work", () => {
  assert.match(fromTerraformPlan({ resources: [] }).errors[0]!, /terraform show -json/);
  assert.match(fromTerraformPlan("nope").errors[0]!, /terraform show -json/);
  const r = fromTerraformPlan({ resource_changes: [rc("aws_iam_role.r", "aws_iam_role", { inline_policy: [{ name: "all", policy: JSON.stringify({ Statement: { Effect: "Allow", Action: "s3:*", Resource: "*" } }) }] })] });
  assert.equal(r.resources.length, 1);
  assert.deepEqual(evaluate(r.resources).findings.map((f) => f.ruleId).sort(), ["iam-wildcard-action", "iam-wildcard-resource"]);
  const many = { resource_changes: Array.from({ length: 501 }, (_, i) => rc(`aws_db_instance.d${i}`, "aws_db_instance", { storage_encrypted: true })) };
  assert.match(fromTerraformPlan(many).errors[0]!, /Too many resources/);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, parseInput } from "@workspace/cspm-engine";
import { collectWithClients, environmentFromTags, mapBucket, mapDbInstance, mapPolicy, mapSecurityGroup, type AwsClients } from "../src/services/aws/collect.ts";
import { cloudFormationTemplate, isAccountId, isRoleName, READ_ONLY_ACTIONS } from "../src/services/aws/setup.ts";
import { friendlyAwsError } from "../src/services/aws/connector.ts";
import { AwsError } from "../src/services/aws/types.ts";

const awsErr = (name: string, extra: object = {}) => Object.assign(new Error(`${name}: arn:aws:iam::999999999999:role/secret-detail`), { name, ...extra });

interface World {
  buckets?: Record<string, { policyPublic?: boolean | "none"; acl?: any[]; pab?: any | "none"; enc?: boolean; tags?: any[] | "none"; deny?: boolean }>;
  groups?: any[]; policies?: { name: string; arn: string; doc: any }[]; dbs?: any[];
  fail?: Partial<Record<"s3" | "ec2" | "iam" | "rds", Error>>;
  pageSize?: number;
}
/** Fake AWS clients: answer the exact commands the collector sends, with the same errors AWS uses for "not configured". */
function fake(w: World): AwsClients {
  const page = <T,>(all: T[], token: string | undefined, key: string) => { const n = w.pageSize ?? 1000; const i = Number(token ?? 0); return { items: all.slice(i, i + n), next: i + n < all.length ? String(i + n) : undefined, key }; };
  const make = (svc: "s3" | "ec2" | "iam" | "rds") => ({
    async send(cmd: any) {
      if (w.fail?.[svc]) throw w.fail[svc];
      const n = cmd.constructor.name, i = cmd.input ?? {};
      const b = w.buckets?.[i.Bucket];
      if (n === "ListBucketsCommand") { const p = page(Object.keys(w.buckets ?? {}), i.ContinuationToken, "b"); return { Buckets: p.items.map((Name) => ({ Name })), ContinuationToken: p.next }; }
      if (b?.deny) throw awsErr("AccessDenied", { $metadata: { httpStatusCode: 403 } });
      if (n === "GetPublicAccessBlockCommand") { if (b!.pab === "none" || b!.pab === undefined) throw awsErr("NoSuchPublicAccessBlockConfiguration"); return { PublicAccessBlockConfiguration: b!.pab }; }
      if (n === "GetBucketPolicyStatusCommand") { if (b!.policyPublic === "none" || b!.policyPublic === undefined) throw awsErr("NoSuchBucketPolicy"); return { PolicyStatus: { IsPublic: b!.policyPublic } }; }
      if (n === "GetBucketAclCommand") return { Grants: b!.acl ?? [] };
      if (n === "GetBucketEncryptionCommand") { if (b!.enc === false) throw awsErr("ServerSideEncryptionConfigurationNotFoundError"); return { ServerSideEncryptionConfiguration: { Rules: [] } }; }
      if (n === "GetBucketTaggingCommand") { if (b!.tags === "none" || b!.tags === undefined) throw awsErr("NoSuchTagSet"); return { TagSet: b!.tags }; }
      if (n === "DescribeSecurityGroupsCommand") { const p = page(w.groups ?? [], i.NextToken, "g"); return { SecurityGroups: p.items, NextToken: p.next }; }
      if (n === "ListPoliciesCommand") { const p = page(w.policies ?? [], i.Marker, "p"); return { Policies: p.items.map((x) => ({ PolicyName: x.name, Arn: x.arn, DefaultVersionId: "v1" })), IsTruncated: !!p.next, Marker: p.next }; }
      if (n === "GetPolicyVersionCommand") { const pol = w.policies!.find((x) => x.arn === i.PolicyArn)!; return { PolicyVersion: { Document: typeof pol.doc === "string" ? pol.doc : encodeURIComponent(JSON.stringify(pol.doc)) } }; }
      if (n === "DescribeDBInstancesCommand") { const p = page(w.dbs ?? [], i.Marker, "d"); return { DBInstances: p.items, Marker: p.next }; }
      throw new Error(`unexpected command ${n}`);
    },
  });
  return { s3: make("s3"), ec2: make("ec2"), iam: make("iam"), rds: make("rds") };
}
const ctx = { accountId: "111122223333", region: "eu-west-1" };
const PUBLIC_READ = { Grantee: { Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" };

test("bucket exposure: a public policy or ACL counts only if the public-access block does not neutralise it", () => {
  const b = (p: Partial<Parameters<typeof mapBucket>[1]>) => mapBucket("x", { policyPublic: false, aclPublic: false, pab: {}, encrypted: true, ...p }).public_read;
  assert.equal(b({}), false);
  assert.equal(b({ policyPublic: true }), true);
  assert.equal(b({ aclPublic: true }), true);
  assert.equal(b({ policyPublic: true, pab: { RestrictPublicBuckets: true } }), false);
  assert.equal(b({ aclPublic: true, pab: { IgnorePublicAcls: true } }), false);
  assert.equal(b({ policyPublic: true, pab: { IgnorePublicAcls: true } }), true); // ignoring ACLs does not hide a public policy
  assert.equal(b({ aclPublic: true, pab: { RestrictPublicBuckets: true } }), true); // restricting policies does not hide a public ACL
});

test("S3: policy, ACL, blocked, private, unencrypted, tagged; 'not configured' errors are answers, not failures", async () => {
  const r = await collectWithClients(fake({ buckets: {
    "pub-policy": { policyPublic: true, enc: true },
    "pub-acl": { acl: [PUBLIC_READ], enc: true },
    "blocked": { policyPublic: true, pab: { RestrictPublicBuckets: true, IgnorePublicAcls: true }, enc: true },
    "private": { enc: true, tags: [{ Key: "Environment", Value: "Production" }] },
    "plain": { enc: false },
    "write-only-acl": { acl: [{ ...PUBLIC_READ, Permission: "WRITE" }], enc: true },
  } }), ctx);
  const by = Object.fromEntries(r.resources.filter((x) => x.type === "s3_bucket").map((x) => [x.name, x]));
  assert.deepEqual([by["pub-policy"]!.public_read, by["pub-acl"]!.public_read, by["blocked"]!.public_read, by["private"]!.public_read, by["write-only-acl"]!.public_read], [true, true, false, false, false]);
  assert.equal(by["plain"]!["encrypted"], false); assert.equal(by["private"]!["encrypted"], true);
  assert.equal(by["private"]!.environment, "production");
  assert.equal(r.complete, true); assert.equal(r.notes.some((n) => n.startsWith("S3")), false);
});

test("S3: access denied on one bucket is reported and marks the result incomplete, others still return", async () => {
  const r = await collectWithClients(fake({ buckets: { ok: { enc: true }, locked: { deny: true } } }), ctx);
  assert.deepEqual(r.resources.filter((x) => x.type === "s3_bucket").map((x) => x.name), ["ok"]);
  assert.equal(r.complete, false); assert.ok(r.notes.some((n) => /S3: access denied on 1 bucket/.test(n)));
});

test("security groups: protocol -1 is all ports, tcp ranges, IPv6, icmp ignored, readable name", () => {
  const g = mapSecurityGroup({ GroupId: "sg-1", GroupName: "web", Tags: [{ Key: "env", Value: "prod" }], IpPermissions: [
    { IpProtocol: "-1", IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
    { IpProtocol: "tcp", FromPort: 22, ToPort: 22, Ipv6Ranges: [{ CidrIpv6: "::/0" }] },
    { IpProtocol: "tcp", FromPort: 8000, ToPort: 8100, IpRanges: [{ CidrIp: "10.0.0.0/8" }] },
    { IpProtocol: "icmp", FromPort: -1, ToPort: -1, IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
  ] });
  assert.equal(g.name, "web (sg-1)"); assert.equal(g.environment, "production");
  assert.deepEqual(g["ingress"], [{ cidr: "0.0.0.0/0", port: "all" }, { cidr: "::/0", port: 22 }, { cidr: "10.0.0.0/8", fromPort: 8000, toPort: 8100 }]);
});

test("IAM: URL-encoded documents, single statements, string actions, Deny, NotAction skipped with a note, account-prefixed names", async () => {
  assert.deepEqual(mapPolicy("1", "p", encodeURIComponent(JSON.stringify({ Statement: { Effect: "Allow", Action: "s3:*", Resource: "*" } }))).resource["statements"], [{ effect: "Allow", actions: ["s3:*"], resources: ["*"] }]);
  const r = await collectWithClients(fake({ policies: [
    { name: "Admin", arn: "arn:p/1", doc: { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] } },
    { name: "Denier", arn: "arn:p/2", doc: { Statement: [{ Effect: "Deny", Action: ["*"], Resource: "*" }] } },
    { name: "Odd", arn: "arn:p/3", doc: { Statement: [{ Effect: "Allow", NotAction: "iam:*", Resource: "*" }, { Effect: "Allow", Action: ["s3:GetObject"], Resource: ["arn:aws:s3:::b/*"] }] } },
  ] }), ctx);
  const names = r.resources.filter((x) => x.type === "iam_policy").map((x) => x.name);
  assert.deepEqual(names, ["111122223333:Admin", "111122223333:Denier", "111122223333:Odd"]);
  assert.equal(r.complete, false); assert.ok(r.notes.some((n) => /NotAction or NotResource/.test(n))); assert.ok(r.notes.some((n) => /AWS-managed policies/.test(n)));
  const f = evaluate(r.resources).findings.map((x) => `${x.ruleId}@${x.resourceName}`);
  assert.deepEqual(f, ["iam-admin-access@111122223333:Admin"]); // the Deny and the benign statement raise nothing
});

test("RDS mapping and environment tags", () => {
  const d = mapDbInstance("111122223333", "eu-west-1", { DBInstanceIdentifier: "orders", PubliclyAccessible: true, StorageEncrypted: false, TagList: [{ Key: "env", Value: "dev" }] });
  assert.deepEqual([d.name, d["publicly_accessible"], d["encrypted"], d.environment], ["111122223333/eu-west-1/orders", true, false, "development"]);
  assert.equal(environmentFromTags([{ Key: "Environment", Value: "whatever" }]), undefined);
  assert.equal(environmentFromTags(undefined), undefined);
});

test("end to end through the rules engine: what the account looks like becomes the right findings", async () => {
  const r = await collectWithClients(fake({
    buckets: { "customer-data": { acl: [PUBLIC_READ], enc: false, tags: [{ Key: "environment", Value: "production" }] }, "logs": { enc: true } },
    groups: [{ GroupId: "sg-9", GroupName: "bastion", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }, { IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }] }],
    policies: [{ name: "Everything", arn: "arn:p/9", doc: { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] } }],
    dbs: [{ DBInstanceIdentifier: "orders", PubliclyAccessible: true, StorageEncrypted: true }],
  }), ctx);
  assert.deepEqual(parseInput(r.resources).errors, []); // the engine accepts what the collector produces
  const ids = evaluate(r.resources).findings.map((x) => x.ruleId).sort();
  assert.deepEqual(ids, ["db-public", "iam-admin-access", "s3-no-encryption", "s3-public-read", "sg-sensitive-port-open"]);
});

test("pagination across S3, EC2, IAM and RDS", async () => {
  const buckets = Object.fromEntries(Array.from({ length: 7 }, (_, i) => [`b${i}`, { enc: true }]));
  const groups = Array.from({ length: 7 }, (_, i) => ({ GroupId: `sg-${i}`, GroupName: "g", IpPermissions: [] }));
  const policies = Array.from({ length: 7 }, (_, i) => ({ name: `p${i}`, arn: `arn:p/${i}`, doc: { Statement: [] } }));
  const dbs = Array.from({ length: 7 }, (_, i) => ({ DBInstanceIdentifier: `d${i}` }));
  const r = await collectWithClients(fake({ buckets, groups, policies, dbs, pageSize: 3 }), ctx);
  const count = (t: string) => r.resources.filter((x) => x.type === t).length;
  assert.deepEqual([count("s3_bucket"), count("security_group"), count("iam_policy"), count("database")], [7, 7, 7, 7]);
});

test("one failing service does not stop the others; it is reported and the result is incomplete", async () => {
  const r = await collectWithClients(fake({ buckets: { a: { enc: true } }, dbs: [{ DBInstanceIdentifier: "d" }], fail: { ec2: awsErr("UnauthorizedOperation"), iam: awsErr("ThrottlingException") } }), ctx);
  assert.deepEqual(r.resources.map((x) => x.type).sort(), ["database", "s3_bucket"]);
  assert.equal(r.complete, false);
  assert.ok(r.notes.some((n) => /EC2 security groups: access denied/.test(n)));
  assert.ok(r.notes.some((n) => /IAM: could not be read \(ThrottlingException\)/.test(n)));
  assert.equal(r.notes.join(" ").includes("999999999999"), false); // raw AWS messages (ARNs, account ids) never leak into notes
});

test("the 500-resource scan limit is respected and reported", async () => {
  const groups = Array.from({ length: 700 }, (_, i) => ({ GroupId: `sg-${i}`, GroupName: "g", IpPermissions: [] }));
  const r = await collectWithClients(fake({ groups, dbs: [{ DBInstanceIdentifier: "never-reached" }] }), ctx);
  assert.equal(r.resources.length, 500); assert.equal(r.complete, false);
  assert.ok(r.notes.some((n) => /Stopped at 500/.test(n))); assert.ok(r.notes.some((n) => /RDS: skipped/.test(n)));
});

test("CloudFormation template: trusts only our account AND the ExternalId, read-only, no wildcards", () => {
  const t = cloudFormationTemplate({ principalAccountId: "123456789012", externalId: "nx-abcdefghijklmnopqrstuvwx", roleName: "NexoraCSPMReadOnly" });
  assert.match(t, /AWS: arn:aws:iam::123456789012:root/); assert.match(t, /sts:ExternalId: nx-abcdefghijklmnopqrstuvwx/);
  assert.match(t, /RoleName: NexoraCSPMReadOnly/);
  const actions = [...t.matchAll(/^\s+- ([a-z0-9]+:[A-Za-z]+)$/gm)].map((m) => m[1]);
  assert.deepEqual(actions, [...READ_ONLY_ACTIONS]);
  for (const a of actions) assert.match(a!, /^[a-z0-9]+:(List|Get|Describe)/, a); // read-only verbs only
  assert.equal(/\*/.test(actions.join("")), false);
  assert.equal(/s3:GetObject|secretsmanager|ssm:|logs:|kms:Decrypt|iam:Create|iam:Put|iam:Attach/.test(t), false); // no data, secrets, logs or writes
  for (const bad of [{ externalId: "x\nInjected: yes" }, { externalId: "short" }, { principalAccountId: "12345" }, { roleName: "bad name; rm" }])
    assert.throws(() => cloudFormationTemplate({ principalAccountId: "123456789012", externalId: "nx-abcdefghijklmnopqrstuvwx", roleName: "R", ...bad }), /invalid template input/);
});

test("account id and role name validation", () => {
  assert.ok(isAccountId("123456789012")); for (const x of ["12345678901", "1234567890123", "12345678901a", " 123456789012", ""]) assert.equal(isAccountId(x), false, x);
  assert.ok(isRoleName("My-Role_1+=,.@")); for (const x of ["", "a b", "a/b", "x".repeat(65), "a;b"]) assert.equal(isRoleName(x), false, x);
});

test("errors shown to users are friendly and never carry raw AWS text", () => {
  const e1 = friendlyAwsError(awsErr("AccessDenied"), "123456789012");
  assert.equal(e1.code, "assume_denied"); assert.match(e1.message, /123456789012/); assert.equal(e1.message.includes("secret-detail"), false);
  assert.equal(friendlyAwsError(awsErr("ExpiredToken"), "1").code, "platform_credentials");
  assert.equal(friendlyAwsError(awsErr("CredentialsProviderError"), "1").code, "platform_credentials");
  assert.equal(friendlyAwsError(awsErr("ThrottlingException"), "1").code, "throttled");
  assert.equal(friendlyAwsError(awsErr("TimeoutError"), "1").code, "network");
  const other = friendlyAwsError(awsErr("WeirdThing"), "1"); assert.equal(other.code, "aws_error"); assert.equal(other.message.includes("secret-detail"), false);
  const mine = new AwsError("account_mismatch", "x"); assert.equal(friendlyAwsError(mine, "1"), mine);
});

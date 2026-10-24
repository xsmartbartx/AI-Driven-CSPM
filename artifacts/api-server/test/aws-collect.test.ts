import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzePaths, evaluate, parseInput } from "@workspace/cspm-engine";
import { collectWithClients, environmentFromTags, mapBucket, mapDbInstance, mapPolicy, mapSecurityGroup, type AwsClients } from "../src/services/aws/collect.ts";
import { cloudFormationTemplate, isAccountId, isRoleName, READ_ONLY_ACTIONS } from "../src/services/aws/setup.ts";
import { friendlyAwsError } from "../src/services/aws/connector.ts";
import { AwsError } from "../src/services/aws/types.ts";

const awsErr = (name: string, extra: object = {}) => Object.assign(new Error(`${name}: arn:aws:iam::999999999999:role/secret-detail`), { name, ...extra });

interface World {
  buckets?: Record<string, { policyPublic?: boolean | "none"; acl?: any[]; pab?: any | "none"; enc?: boolean; tags?: any[] | "none"; deny?: boolean }>;
  groups?: any[]; policies?: { name: string; arn: string; doc: any }[]; dbs?: any[];
  instances?: any[]; profiles?: { Arn: string; Roles: { RoleName: string }[] }[];
  roles?: Record<string, { attached?: { PolicyName: string; PolicyArn: string }[]; inline?: Record<string, any>; fail?: boolean }>;
  failCommands?: Record<string, Error>;
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
      if (w.failCommands?.[n]) throw w.failCommands[n];
      if (n === "DescribeInstancesCommand") { const p = page(w.instances ?? [], i.NextToken, "i"); return { Reservations: p.items.map((x) => ({ Instances: [x] })), NextToken: p.next }; }
      if (n === "ListInstanceProfilesCommand") return { InstanceProfiles: w.profiles ?? [], IsTruncated: false };
      if (n === "ListAttachedRolePoliciesCommand") { const r = w.roles?.[i.RoleName]; if (r?.fail) throw awsErr("AccessDenied"); return { AttachedPolicies: r?.attached ?? [], IsTruncated: false }; }
      if (n === "ListRolePoliciesCommand") return { PolicyNames: Object.keys(w.roles?.[i.RoleName]?.inline ?? {}), IsTruncated: false };
      if (n === "GetRolePolicyCommand") return { PolicyDocument: encodeURIComponent(JSON.stringify(w.roles![i.RoleName]!.inline![i.PolicyName])) };
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

test("hitting the S3 or IAM cap exactly, with more pages still to read, is reported as incomplete", async () => {
  const buckets = Object.fromEntries(Array.from({ length: 301 }, (_, i) => [`b${i}`, { enc: true }]));
  const s3 = await collectWithClients(fake({ buckets, pageSize: 100 }), ctx);
  assert.equal(s3.complete, false); assert.ok(s3.notes.some((n) => /S3: more than 300 buckets/.test(n)));
  const policies = Array.from({ length: 301 }, (_, i) => ({ name: `p${i}`, arn: `arn:p/${i}`, doc: { Statement: [] } }));
  const iam = await collectWithClients(fake({ policies, pageSize: 100 }), ctx);
  assert.equal(iam.complete, false); assert.ok(iam.notes.some((n) => /IAM: more than 300 attached/.test(n)));
  assert.equal(iam.resources.filter((x) => x.type === "iam_policy").length, 300);
  // exactly 300 and nothing more is complete as far as the cap goes
  const exact = await collectWithClients(fake({ buckets: Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`e${i}`, { enc: true }])), pageSize: 100 }), ctx);
  assert.equal(exact.notes.some((n) => /S3: more than/.test(n)), false);
});

const INSTANCE = (id: string, o: any = {}) => ({ InstanceId: id, State: { Name: "running" }, PublicIpAddress: "203.0.113.10", SecurityGroups: [{ GroupId: "sg-web", GroupName: "web" }], IamInstanceProfile: { Arn: "arn:aws:iam::111122223333:instance-profile/app-profile" }, Tags: [{ Key: "Name", Value: "web-1" }, { Key: "env", Value: "prod" }], ...o });

test("instances: name, public IP, security groups, environment and the role behind the instance profile; stopped ones are ignored", async () => {
  const r = await collectWithClients(fake({
    instances: [INSTANCE("i-1"), INSTANCE("i-2", { State: { Name: "terminated" } }), INSTANCE("i-3", { PublicIpAddress: undefined, IamInstanceProfile: undefined, Tags: [] })],
    profiles: [{ Arn: "arn:aws:iam::111122223333:instance-profile/app-profile", Roles: [{ RoleName: "app-role" }] }],
    roles: { "app-role": {} },
  }), ctx);
  const ins = r.resources.filter((x) => x.type === "ec2_instance");
  assert.deepEqual(ins.map((x) => x.name), ["web-1 (i-1)", "i-3"]);
  assert.deepEqual([ins[0]!["public_ip"], ins[0]!["security_groups"], ins[0]!["role"], ins[0]!.environment], [true, ["sg-web"], "app-role", "production"]);
  assert.deepEqual([ins[1]!["public_ip"], ins[1]!["role"]], [false, undefined]);
});

test("roles: only roles that instances run as are read; customer-managed, AWS-managed and inline policies are told apart", async () => {
  const seen: string[] = [];
  const clients = fake({
    instances: [INSTANCE("i-1")],
    profiles: [{ Arn: "arn:aws:iam::111122223333:instance-profile/app-profile", Roles: [{ RoleName: "app-role" }] }, { Arn: "arn:aws:iam::111122223333:instance-profile/unused", Roles: [{ RoleName: "unused-role" }] }],
    roles: { "app-role": { attached: [{ PolicyName: "Custom", PolicyArn: "arn:aws:iam::111122223333:policy/Custom" }, { PolicyName: "AdministratorAccess", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }], inline: { scratch: { Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::data/*" }] } } }, "unused-role": {} },
  });
  const orig = clients.iam.send.bind(clients.iam); clients.iam.send = async (cmd: any) => { seen.push(`${cmd.constructor.name}:${cmd.input?.RoleName ?? ""}`); return orig(cmd); };
  const r = await collectWithClients(clients, ctx);
  const role = r.resources.find((x) => x.type === "iam_role")!;
  assert.deepEqual([role.name, role["policies"], role["managed_policies"]], ["app-role", ["111122223333:Custom"], ["arn:aws:iam::aws:policy/AdministratorAccess"]]);
  assert.deepEqual(role["inline_statements"], [{ effect: "Allow", actions: ["s3:GetObject"], resources: ["arn:aws:s3:::data/*"] }]);
  assert.equal(r.resources.filter((x) => x.type === "iam_role").length, 1);
  assert.equal(seen.some((s) => s.endsWith(":unused-role")), false); // a role no instance uses is never fetched
});

test("security groups carry their id and group-to-group rules; databases carry their security groups", () => {
  const g = mapSecurityGroup({ GroupId: "sg-db", GroupName: "db", IpPermissions: [
    { IpProtocol: "tcp", FromPort: 5432, ToPort: 5432, UserIdGroupPairs: [{ GroupId: "sg-web" }] },
    { IpProtocol: "-1", UserIdGroupPairs: [{ GroupId: "sg-admin" }] },
    { IpProtocol: "tcp", FromPort: 8000, ToPort: 8100, UserIdGroupPairs: [{ GroupId: "sg-web" }], IpRanges: [{ CidrIp: "10.0.0.0/8" }] },
  ] });
  assert.equal(g["id"], "sg-db");
  assert.deepEqual(g["ingress"], [{ sourceGroup: "sg-web", port: 5432 }, { sourceGroup: "sg-admin", port: "all" }, { sourceGroup: "sg-web", fromPort: 8000, toPort: 8100 }, { cidr: "10.0.0.0/8", fromPort: 8000, toPort: 8100 }]);
  assert.deepEqual(mapDbInstance("1", "r", { DBInstanceIdentifier: "o", VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-db" }] })["security_groups"], ["sg-db"]);
  // a group-to-group rule is not internet exposure
  assert.deepEqual(evaluate([g]).findings, []);
});

test("relationship data is optional: if it cannot be read the scan stays complete and says what to do", async () => {
  const denied = awsErr("UnauthorizedOperation");
  const r = await collectWithClients(fake({ buckets: { a: { enc: true } }, failCommands: { DescribeInstancesCommand: denied } }), ctx);
  assert.equal(r.complete, true); // an older role template must not turn every scan into an incomplete one
  assert.ok(r.notes.some((n) => /EC2 instances: access denied, so attack paths cannot be built\. Redeploy the setup template/.test(n)));
  assert.deepEqual(r.resources.map((x) => x.type), ["s3_bucket"]);
  const noProfiles = await collectWithClients(fake({ instances: [INSTANCE("i-1")], failCommands: { ListInstanceProfilesCommand: awsErr("AccessDenied") } }), ctx);
  assert.equal(noProfiles.complete, true); assert.ok(noProfiles.notes.some((n) => /iam:ListInstanceProfiles denied/.test(n)));
  assert.equal(noProfiles.resources.find((x) => x.type === "ec2_instance")!["role"], undefined);
  const roleFails = await collectWithClients(fake({ instances: [INSTANCE("i-1")], profiles: [{ Arn: "arn:aws:iam::111122223333:instance-profile/app-profile", Roles: [{ RoleName: "app-role" }] }], roles: { "app-role": { fail: true } } }), ctx);
  assert.equal(roleFails.complete, true); assert.ok(roleFails.notes.some((n) => /IAM roles: 1 role used by instances could not be read/.test(n)));
});

test("the whole chain: what the collector returns becomes the attack path the engine finds", async () => {
  const r = await collectWithClients(fake({
    groups: [
      { GroupId: "sg-web", GroupName: "web", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }] },
      { GroupId: "sg-db", GroupName: "db", IpPermissions: [{ IpProtocol: "tcp", FromPort: 5432, ToPort: 5432, UserIdGroupPairs: [{ GroupId: "sg-web" }] }] },
    ],
    instances: [INSTANCE("i-1")],
    profiles: [{ Arn: "arn:aws:iam::111122223333:instance-profile/app-profile", Roles: [{ RoleName: "app-role" }] }],
    roles: { "app-role": { attached: [{ PolicyName: "Everything", PolicyArn: "arn:aws:iam::111122223333:policy/Everything" }] } },
    policies: [{ name: "Everything", arn: "arn:aws:iam::111122223333:policy/Everything", doc: { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] } }],
    dbs: [{ DBInstanceIdentifier: "orders", PubliclyAccessible: false, StorageEncrypted: true, VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-db" }], TagList: [{ Key: "env", Value: "prod" }] }],
  }), ctx);
  assert.deepEqual(parseInput(r.resources).errors, []);
  const a = analyzePaths(r.resources);
  assert.deepEqual(a.paths.map((p) => [p.target, p.score]), [["AWS account (full control)", 100], ["111122223333/eu-west-1/orders", 77]]);
  assert.match(a.paths[0]!.edges[0]!.label, /web-1 \(i-1\) has a public IP and web \(sg-web\) lets the internet in on port 22/);
  assert.equal(a.chokePoints[0]!.asset, "web (sg-web)");
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
  for (const a of ["ec2:DescribeInstances", "iam:ListInstanceProfiles", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy"]) assert.ok((actions as string[]).includes(a), a); // the permissions attack paths need
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

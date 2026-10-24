import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzePaths, evaluate, parseInput, SAMPLE_PATHS_CONFIG, wildcardMatch, type Resource } from "../src/index.ts";

const sg = (name: string, ingress: object[], extra: object = {}): Resource => ({ type: "security_group", name, ingress, ...extra } as any);
const inst = (name: string, o: object = {}): Resource => ({ type: "ec2_instance", name, environment: "production", public_ip: true, security_groups: ["web-sg"], ...o } as any);
const role = (name: string, o: object = {}): Resource => ({ type: "iam_role", name, ...o } as any);
const policy = (name: string, statements: object[]): Resource => ({ type: "iam_policy", name, statements } as any);
const bucket = (name: string, o: object = {}): Resource => ({ type: "s3_bucket", name, environment: "production", ...o } as any);
const db = (name: string, o: object = {}): Resource => ({ type: "database", name, environment: "production", ...o } as any);
const WORLD_SSH = sg("web-sg", [{ cidr: "0.0.0.0/0", port: 22 }]);
const ADMIN = role("app-role", { managed_policies: ["arn:aws:iam::aws:policy/AdministratorAccess"] });

test("the classic chain: internet -> public instance with SSH open -> admin role -> the whole account", () => {
  const r = analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), ADMIN]);
  assert.equal(r.paths.length, 1);
  const p = r.paths[0]!;
  assert.deepEqual(p.nodes.map((n) => n.kind), ["internet", "instance", "role", "account"]);
  assert.deepEqual(p.edges.map((e) => e.kind), ["exposes", "assumes", "grants_admin"]);
  assert.equal(p.score, 100); assert.equal(p.severity, "critical");
  assert.match(p.title, /web-1 is reachable from the internet and leads to full control/);
  assert.match(p.edges[0]!.label, /public IP and web-sg lets the internet in on port 22/);
  assert.match(p.edges[2]!.label, /AdministratorAccess lets app-role do anything on everything/);
  assert.deepEqual(r.notes.filter((n) => /Not modelled/.test(n)).length, 1); // limits are always stated
});

test("every hop is needed: no public IP, a closed security group, or no world rule means no path", () => {
  const ok = [WORLD_SSH, inst("web-1", { role: "app-role" }), ADMIN];
  assert.equal(analyzePaths(ok).paths.length, 1);
  assert.equal(analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role", public_ip: false }), ADMIN]).paths.length, 0);
  assert.equal(analyzePaths([sg("web-sg", [{ cidr: "10.0.0.0/8", port: 22 }]), inst("web-1", { role: "app-role" }), ADMIN]).paths.length, 0);
  assert.equal(analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role", security_groups: ["other-sg"] }), ADMIN]).paths.length, 0); // an unknown group is not guessed
  assert.equal(analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" })]).paths.length, 0); // role not described: nothing assumed
  assert.equal(analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), role("app-role")]).paths.length, 0); // a role with no permissions leads nowhere
});

test("a web server open on 443 only is a weaker entry point than one with SSH open", () => {
  const web = analyzePaths([sg("web-sg", [{ cidr: "0.0.0.0/0", port: 443 }]), inst("web-1", { role: "app-role" }), ADMIN]).paths[0]!;
  assert.equal(web.score, 60); assert.equal(web.severity, "high");
  const odd = analyzePaths([sg("web-sg", [{ cidr: "::/0", port: 8080 }]), inst("web-1", { role: "app-role" }), ADMIN]).paths[0]!;
  assert.equal(odd.score, 80); assert.equal(odd.severity, "critical");
  const all = analyzePaths([sg("web-sg", [{ cidr: "0.0.0.0/0", port: "all" }]), inst("web-1", { role: "app-role" }), ADMIN]).paths[0]!;
  assert.equal(all.score, 100); assert.match(all.edges[0]!.label, /all ports/);
});

test("what a role can do decides where the path ends", () => {
  const base = (r: Resource, ...extra: Resource[]) => analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), r, bucket("data"), bucket("logs"), ...extra]);
  // customer policy, resolved by its (account-prefixed) name
  const all = base(role("app-role", { policies: ["Everything"] }), policy("111122223333:Everything", [{ effect: "Allow", actions: ["*"], resources: ["*"] }]));
  assert.deepEqual(all.paths.map((p) => p.target), ["AWS account (full control)"]); // admin covers every bucket: one path, not three
  // all of IAM is as good as admin: it can grant itself anything
  assert.deepEqual(base(role("app-role", { inline_statements: [{ effect: "Allow", actions: ["iam:*"], resources: ["*"] }] })).paths.map((p) => p.target), ["AWS account (full control)"]);
  // s3 only: reads buckets, not the account
  const s3 = base(role("app-role", { inline_statements: [{ effect: "Allow", actions: ["s3:*"], resources: ["*"] }] }));
  assert.deepEqual(s3.paths.map((p) => p.target).sort(), ["data", "logs"]);
  assert.ok(s3.paths.every((p) => p.edges[2]!.kind === "reads" && p.score < 100));
  // scoped to one bucket by ARN
  const one = base(role("app-role", { inline_statements: [{ effect: "Allow", actions: ["s3:GetObject"], resources: ["arn:aws:s3:::data/*"] }] }));
  assert.deepEqual(one.paths.map((p) => p.target), ["data"]);
  // a different action, or only Deny, reaches nothing
  assert.equal(base(role("app-role", { inline_statements: [{ effect: "Allow", actions: ["s3:PutObject"], resources: ["*"] }] })).paths.length, 0);
  assert.equal(base(role("app-role", { inline_statements: [{ effect: "Deny", actions: ["*"], resources: ["*"] }] })).paths.length, 0);
  // PowerUserAccess reads all data but is not control of the account
  assert.deepEqual(base(role("app-role", { managed_policies: ["arn:aws:iam::aws:policy/PowerUserAccess"] })).paths.map((p) => p.target).sort(), ["data", "logs"]);
  // S3 read-only managed policy
  assert.deepEqual(base(role("app-role", { managed_policies: ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"] })).paths.map((p) => p.target).sort(), ["data", "logs"]);
});

test("unknown or missing policies are reported, never guessed", () => {
  const r = analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), role("app-role", { managed_policies: ["arn:aws:iam::aws:policy/SomethingNew"], policies: ["ghost-policy"] }), bucket("data")]);
  assert.equal(r.paths.length, 0);
  assert.ok(r.notes.some((n) => /SomethingNew/.test(n))); assert.ok(r.notes.some((n) => /ghost-policy/.test(n)));
});

test("instance -> database only where the database's security group names the instance's group", () => {
  const dbs = (src: string) => [WORLD_SSH, sg("db-sg", [{ sourceGroup: src, port: 5432 }]), inst("web-1"), db("orders", { security_groups: ["db-sg"] })];
  const hit = analyzePaths(dbs("web-sg")).paths;
  assert.equal(hit.length, 1);
  assert.deepEqual(hit[0]!.nodes.map((n) => n.kind), ["internet", "instance", "database"]);
  assert.match(hit[0]!.edges[1]!.label, /db-sg accepts connections from web-sg on port 5432, and web-1 is in web-sg/);
  assert.equal(hit[0]!.score, 77); assert.equal(hit[0]!.severity, "critical"); // 1 x 0.85 x (0.5 + 0.5 x 0.8)
  assert.equal(analyzePaths(dbs("some-other-sg")).paths.length, 0);
  assert.equal(analyzePaths([WORLD_SSH, inst("web-1"), db("orders", { security_groups: ["missing-sg"] })]).paths.length, 0);
  // a development database matters less than a production one
  const dev = analyzePaths([WORLD_SSH, sg("db-sg", [{ sourceGroup: "web-sg", port: 5432 }]), inst("web-1"), db("orders", { security_groups: ["db-sg"], environment: "development" })]).paths[0]!;
  assert.ok(dev.score < hit[0]!.score);
});

test("security groups are matched by name, by id, and by the collector's 'name (sg-id)' form", () => {
  const web = sg("web (sg-0abc)", [{ cidr: "0.0.0.0/0", port: 22 }]);
  const base = [web, inst("i-1", { security_groups: ["sg-0abc"] }), db("orders", { security_groups: ["dbg (sg-0def)"] }), sg("dbg (sg-0def)", [{ sourceGroup: "sg-0abc", port: 5432 }])];
  assert.equal(analyzePaths(base).paths.length, 1);
  assert.equal(analyzePaths([sg("web", [{ cidr: "0.0.0.0/0", port: 22 }], { id: "sg-77" }), inst("i-1", { security_groups: ["sg-77"] }), ADMIN, ...[inst("i-1", { security_groups: ["sg-77"], role: "app-role" })].slice(0, 0)]).paths.length, 0); // no role: no path, but the id resolved without error
});

test("choke points: one fix that breaks several paths comes first", () => {
  const r = analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), inst("web-2", { role: "app-role" }), ADMIN, sg("db-sg", [{ sourceGroup: "web-sg", port: 5432 }]), db("orders", { security_groups: ["db-sg"] })]);
  assert.equal(r.paths.length, 4); // two instances x (account, database)
  const top = r.chokePoints[0]!;
  assert.equal(top.paths, 4); assert.equal(top.asset, "web-sg"); assert.match(top.action, /Remove the internet-wide rule \(port 22\) from web-sg/);
  assert.ok(r.chokePoints.some((c) => c.asset === "app-role" && c.paths === 2)); // narrowing the role breaks both account paths
  assert.ok(r.chokePoints.every((c) => c.pathIds.every((id) => r.paths.some((p) => p.id === id))));
});

test("coverage and notes explain what is missing", () => {
  const none = analyzePaths([WORLD_SSH, bucket("b")]);
  assert.equal(none.coverage.hasRelationshipData, false); assert.match(none.notes[0]!, /No instances were found/);
  const norole = analyzePaths([WORLD_SSH, inst("web-1")]);
  assert.equal(norole.coverage.instancesWithoutRole, 1); assert.ok(norole.notes.some((n) => /1 instance has no role information/.test(n)));
});

test("results are deterministic and ordered by risk; more than 50 paths are capped with a note", () => {
  const many: Resource[] = [WORLD_SSH, role("app-role", { inline_statements: [{ effect: "Allow", actions: ["s3:GetObject"], resources: ["*"] }] })];
  for (let i = 0; i < 30; i++) many.push(inst(`i-${i}`, { role: "app-role" }), bucket(`b${i}`));
  const a = analyzePaths(many), b = analyzePaths([...many].reverse());
  assert.equal(a.paths.length, 50); assert.ok(a.notes.some((n) => /Showing the 50 highest-risk of 900 paths/.test(n)));
  assert.deepEqual(a.paths.map((p) => p.id), b.paths.map((p) => p.id)); // same input in another order: same answer
  for (let i = 1; i < a.paths.length; i++) assert.ok(a.paths[i - 1]!.score >= a.paths[i]!.score);
});

test("instances and roles are accepted in a scan without being reported as unsupported, and raise no findings", () => {
  const { resources, errors } = parseInput([WORLD_SSH, inst("web-1", { role: "app-role" }), ADMIN]);
  assert.deepEqual(errors, []);
  const e = evaluate(resources);
  assert.deepEqual(e.unknownTypes, []);
  assert.deepEqual(e.findings.map((f) => f.resourceName), ["web-sg"]); // only the security group has rules
});

test("wildcard matching: * and ? behave like IAM, special characters are literal, and it never goes exponential", () => {
  const m = wildcardMatch;
  assert.ok(m("*", "anything")); assert.ok(m("", "")); assert.ok(!m("", "x")); assert.ok(m("s3:*", "s3:GetObject")); assert.ok(!m("s3:*", "ec2:Run"));
  assert.ok(m("arn:aws:s3:::b/*", "arn:aws:s3:::b/logs/2024/x.gz")); assert.ok(!m("arn:aws:s3:::b/*", "arn:aws:s3:::b"));
  assert.ok(m("a?c", "abc")); assert.ok(!m("a?c", "ac")); assert.ok(m("*a*b*", "xxaxxbxx")); assert.ok(!m("*b*a*", "xxaxxbxx"));
  assert.ok(m("a.c+(d)", "a.c+(d)")); assert.ok(!m("a.c", "abc")); // regex characters mean nothing here
  assert.ok(m("S3:getobject", "s3:GetObject", true)); assert.ok(!m("S3:getobject", "s3:GetObject")); // action names ignore case, ARNs do not
  assert.ok(!m("*".repeat(5000), "x")); assert.ok(!m("a", "a".repeat(5000))); // over-long input never matches
  // the pattern a regex would take forever on: many stars, a long value that almost matches
  const evil = "*a".repeat(40) + "*b", value = "a".repeat(4000);
  const t0 = Date.now(); assert.equal(m(evil, value), false); assert.ok(Date.now() - t0 < 200, `took ${Date.now() - t0} ms`);
});

test("a pasted policy full of pathological patterns cannot stall the analysis", () => {
  const evil = "*a".repeat(40) + "*b";
  const buckets = Array.from({ length: 50 }, (_, i) => bucket(`${"a".repeat(60)}${i}`));
  const t0 = Date.now();
  const r = analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), role("app-role", { inline_statements: [{ effect: "Allow", actions: [evil, "s3:GetObject"], resources: [evil, `arn:aws:s3:::${"a".repeat(60)}7/*`] }] }), ...buckets]);
  assert.ok(Date.now() - t0 < 500, `took ${Date.now() - t0} ms`);
  assert.deepEqual(r.paths.map((p) => p.target), [`${"a".repeat(60)}7`]); // the one honest match still found
});

test("a read permission scoped to a prefix still leads to the bucket, and says so; a similarly named bucket does not match", () => {
  const base = (resources: string[]) => analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), role("app-role", { inline_statements: [{ effect: "Allow", actions: ["s3:GetObject"], resources }] }), bucket("data"), bucket("data-archive")]);
  const prefix = base(["arn:aws:s3:::data/logs/*"]);
  assert.deepEqual(prefix.paths.map((p) => p.target), ["data"]);
  assert.match(prefix.paths[0]!.edges[2]!.label, /read some objects \(a prefix\) in data/);
  const whole = base(["arn:aws:s3:::data/*"]);
  assert.match(whole.paths[0]!.edges[2]!.label, /read objects in data$/);
  assert.deepEqual(base(["arn:aws:s3:::data*/*"]).paths.map((p) => p.target).sort(), ["data", "data-archive"]); // a wildcard in the name covers both
  assert.equal(base(["arn:aws:s3:::other/*"]).paths.length, 0);
});

test("two paths over the same nodes through different open security groups get different ids", () => {
  const r = analyzePaths([sg("web-sg", [{ cidr: "0.0.0.0/0", port: 22 }]), sg("extra-sg", [{ cidr: "0.0.0.0/0", port: 3389 }]), inst("web-1", { role: "app-role", security_groups: ["web-sg", "extra-sg"] }), ADMIN]);
  assert.equal(r.paths.length, 2);
  assert.notEqual(r.paths[0]!.id, r.paths[1]!.id);
  assert.equal(new Set(r.paths.map((p) => p.id)).size, 2);
  const fixes = r.chokePoints.filter((c) => c.paths === 1 && /web-sg|extra-sg/.test(c.asset)).length;
  assert.equal(fixes, 2); // each group's rule is its own fix: closing one leaves the other path
});

test("very large permission lists are truncated with a note, not silently", () => {
  const stmts = Array.from({ length: 250 }, (_, i) => ({ effect: "Allow", actions: ["ec2:Describe*"], resources: [`arn:aws:ec2:::thing${i}`] }));
  const r = analyzePaths([WORLD_SSH, inst("web-1", { role: "app-role" }), role("app-role", { inline_statements: stmts })]);
  assert.ok(r.notes.some((n) => /very large: only the first 200 statements/.test(n)));
});

test("the sample used in docs and demos produces the two headline paths", () => {
  const r = analyzePaths(SAMPLE_PATHS_CONFIG().resources as Resource[]);
  assert.deepEqual(r.paths.map((p) => [p.target, p.score]), [["AWS account (full control)", 100], ["orders-db", 77]]);
  assert.equal(r.chokePoints[0]!.asset, "web-sg");
});

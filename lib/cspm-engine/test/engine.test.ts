import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, parseInput, riskScore, severityOf, postureScore, complianceFrom, SAMPLE_CONFIG, LIMITS } from "../src/index.ts";

test("sample config yields expected findings", () => {
  const { resources, errors } = parseInput(SAMPLE_CONFIG);
  assert.deepEqual(errors, []);
  const { findings } = evaluate(resources);
  const ids = findings.map((f) => `${f.ruleId}@${f.resourceName}`).sort();
  assert.deepEqual(ids, [
    "db-no-encryption@orders-db", "db-public@orders-db",
    "iam-admin-access@payments-role", "iam-wildcard-resource@reports-reader",
    "s3-no-encryption@prod-customer-data", "s3-public-read@prod-customer-data",
    "sg-sensitive-port-open@web-sg",
  ].sort());
});

test("admin policy does not double-report as wildcard action/resource", () => {
  const { findings } = evaluate([{ type: "iam_policy", name: "p", statements: [{ effect: "Allow", actions: ["*"], resources: ["*"] }] }]);
  assert.deepEqual(findings.map((f) => f.ruleId), ["iam-admin-access"]);
});

test("Deny statements are ignored", () => {
  const { findings } = evaluate([{ type: "iam_policy", name: "p", statements: [{ effect: "Deny", actions: ["*"], resources: ["*"] }] }]);
  assert.equal(findings.length, 0);
});

test("security group: all-ports world rule is sensitive; 443 alone is fine; 8080 is generic", () => {
  const f = (ingress: unknown[]) => evaluate([{ type: "security_group", name: "g", ingress: ingress as any }]).findings.map((x) => x.ruleId);
  assert.deepEqual(f([{ cidr: "0.0.0.0/0", port: "all" }]).sort(), ["sg-open-world", "sg-sensitive-port-open"]);
  assert.deepEqual(f([{ cidr: "0.0.0.0/0", port: 8080 }]), ["sg-open-world"]);
  assert.deepEqual(f([{ cidr: "0.0.0.0/0", port: 443 }, { cidr: "0.0.0.0/0", port: 80 }]), []);
  assert.deepEqual(f([{ cidr: "10.0.0.0/8", port: 22 }]), []);
  assert.deepEqual(f([{ cidr: "::/0", port: 3389 }]), ["sg-sensitive-port-open"]);
  assert.deepEqual(f([{ cidr: "0.0.0.0/0", fromPort: 20, toPort: 25 }]).sort(), ["sg-open-world", "sg-sensitive-port-open"]);
});

test("evidence reports the CIDR that actually matched, IPv6 included", () => {
  const f = evaluate([{ type: "security_group", name: "g", ingress: [{ cidr: "::/0", port: 22 }, { cidr: "0.0.0.0/0", port: 8080 }] }]).findings;
  assert.equal(f.find((x) => x.ruleId === "sg-sensitive-port-open")!.evidence["cidr"], "::/0");
  assert.equal(f.find((x) => x.ruleId === "sg-open-world")!.evidence["cidr"], "0.0.0.0/0");
});

test("non-numeric criticality never produces NaN", () => {
  const f = evaluate([{ type: "s3_bucket", name: "b", public_read: true, criticality: "high", environment: "production" } as any]).findings[0]!;
  assert.ok(Number.isInteger(f.riskScore) && f.riskScore >= 0 && f.riskScore <= 100);
  assert.equal(f.riskScore, riskScore(85, 8));
  assert.equal(riskScore(50, NaN), 50);
});

test("risk scale and severity thresholds", () => {
  assert.equal(riskScore(85, 5), 85);
  assert.equal(riskScore(100, 10), 100);
  assert.equal(riskScore(10, 1), 9);
  assert.equal(riskScore(85, 8), 93);
  assert.equal(severityOf(76), "critical"); assert.equal(severityOf(75), "high");
  assert.equal(severityOf(51), "high"); assert.equal(severityOf(50), "medium");
  assert.equal(severityOf(21), "medium"); assert.equal(severityOf(20), "low");
});

test("posture is clamped 0-100", () => {
  assert.equal(postureScore({ critical: 0, high: 0, medium: 0, low: 0 }), 100);
  assert.equal(postureScore({ critical: 20, high: 0, medium: 0, low: 0 }), 0);
});

test("input validation", () => {
  assert.ok(parseInput("x").errors.length);
  assert.ok(parseInput([]).errors.length);
  assert.ok(parseInput([{ type: "s3_bucket" }]).errors[0].includes("name"));
  assert.ok(parseInput([{ type: "s3_bucket", name: "a" }, { type: "s3_bucket", name: "a" }]).errors[0].includes("duplicate"));
  assert.ok(parseInput(Array.from({ length: LIMITS.maxResources + 1 }, (_, i) => ({ type: "x", name: String(i) }))).errors[0].includes("Too many"));
});

test("unknown types are reported, not silently dropped", () => {
  assert.deepEqual(evaluate([{ type: "lambda", name: "f" }]).unknownTypes, ["lambda"]);
});

test("compliance: failing rule fails its controls only", () => {
  const all = complianceFrom([]);
  assert.ok(all.every((f) => f.coverage === 100));
  const some = complianceFrom(["s3-public-read"]);
  assert.ok(some.find((f) => f.framework === "CIS-AWS")!.failed >= 1);
  assert.ok(some.every((f) => f.coverage < 100 || f.failed === 0));
});

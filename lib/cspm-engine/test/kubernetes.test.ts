import { test } from "node:test";
import assert from "node:assert/strict";
import { complianceFrom, evaluate, fromKubernetesManifests } from "../src/index.ts";

const container = (o: object = {}) => ({ name: "app", image: "registry.example.com/team/app:1.4.2", securityContext: { allowPrivilegeEscalation: false, runAsNonRoot: true }, resources: { limits: { memory: "256Mi" } }, ...o });
const deploy = (name: string, spec: object, extra: object = {}) => ({ kind: "Deployment", apiVersion: "apps/v1", metadata: { name, namespace: "shop", ...extra }, spec: { template: { spec } } });
const rulesOf = (m: unknown) => evaluate(fromKubernetesManifests(m).resources).findings.map((f) => `${f.ruleId} ${f.resourceName}`).sort();

test("a well-configured workload has no findings; every setting that matters is found when it is wrong", () => {
  assert.deepEqual(rulesOf([deploy("good", { containers: [container()] })]), []);
  assert.deepEqual(rulesOf([deploy("priv", { containers: [container({ securityContext: { privileged: true, allowPrivilegeEscalation: false, runAsNonRoot: true } })] })]), ["k8s-privileged Deployment/shop/priv"]);
  assert.deepEqual(rulesOf([deploy("host", { hostNetwork: true, containers: [container()] })]), ["k8s-privileged Deployment/shop/host"]);
  assert.deepEqual(rulesOf([deploy("caps", { containers: [container({ securityContext: { allowPrivilegeEscalation: false, runAsNonRoot: true, capabilities: { add: ["SYS_ADMIN"] } } })] })]), ["k8s-privileged Deployment/shop/caps"]);
  assert.deepEqual(rulesOf([deploy("hp", { volumes: [{ name: "d", hostPath: { path: "/var/run/docker.sock" } }], containers: [container()] })]), ["k8s-host-path Deployment/shop/hp"]);
  assert.deepEqual(rulesOf([deploy("root", { containers: [container({ securityContext: { allowPrivilegeEscalation: false } })] })]), ["k8s-run-as-root Deployment/shop/root"]);
  assert.deepEqual(rulesOf([deploy("esc", { containers: [container({ securityContext: { runAsNonRoot: true } })] })]), ["k8s-privilege-escalation Deployment/shop/esc"]);
  assert.deepEqual(rulesOf([deploy("img", { containers: [container({ image: "nginx" })] })]), ["k8s-latest-image Deployment/shop/img"]);
  assert.deepEqual(rulesOf([deploy("img2", { containers: [container({ image: "registry:5000/app:latest" })] })]), ["k8s-latest-image Deployment/shop/img2"]);
  assert.deepEqual(rulesOf([deploy("pinned", { containers: [container({ image: "registry:5000/app@sha256:" + "a".repeat(64) })] })]), []); // a digest is pinned; a port in the registry is not a tag
  assert.deepEqual(rulesOf([deploy("lim", { containers: [container({ resources: {} })] })]), ["k8s-no-limits Deployment/shop/lim"]);
});

test("defaults follow Kubernetes: the pod's security context applies, unspecified means unsafe, init containers count", () => {
  const podLevel = deploy("podsc", { securityContext: { runAsNonRoot: true }, containers: [container({ securityContext: { allowPrivilegeEscalation: false } })] });
  assert.deepEqual(rulesOf([podLevel]), []);                                                      // runAsNonRoot inherited from the pod
  assert.deepEqual(rulesOf([deploy("uid", { securityContext: { runAsUser: 1000 }, containers: [container({ securityContext: { allowPrivilegeEscalation: false } })] })]), []);
  assert.deepEqual(rulesOf([deploy("uid0", { securityContext: { runAsUser: 0 }, containers: [container({ securityContext: { allowPrivilegeEscalation: false } })] })]), ["k8s-run-as-root Deployment/shop/uid0"]);
  assert.deepEqual(rulesOf([deploy("bare", { containers: [{ name: "app", image: "app:1" }] })]), ["k8s-no-limits Deployment/shop/bare", "k8s-privilege-escalation Deployment/shop/bare", "k8s-run-as-root Deployment/shop/bare"]);
  assert.deepEqual(rulesOf([deploy("init", { initContainers: [container({ name: "setup", securityContext: { privileged: true, allowPrivilegeEscalation: false, runAsNonRoot: true } })], containers: [container()] })]), ["k8s-privileged Deployment/shop/init"]);
});

test("every kind that makes pods is read, lists and single documents work, other kinds are counted, bad input is refused", () => {
  const bad = { kind: "Pod", metadata: { name: "p" }, spec: { containers: [{ name: "a", image: "x" }] } };
  const cron = { kind: "CronJob", metadata: { name: "c" }, spec: { jobTemplate: { spec: { template: { spec: { containers: [{ name: "a", image: "x" }] } } } } } };
  const r = fromKubernetesManifests({ kind: "List", items: [bad, cron, { kind: "Service", metadata: { name: "s" } }, { kind: "Service", metadata: { name: "t" } }, { kind: "DaemonSet", metadata: { name: "d" }, spec: { template: { spec: { containers: [] } } } }] });
  assert.deepEqual(r.resources.map((x) => x.name), ["Pod/default/p", "CronJob/default/c", "DaemonSet/default/d"]);
  assert.deepEqual(r.skipped, [{ type: "Service", count: 2 }]);
  assert.equal(fromKubernetesManifests(bad).resources.length, 1);
  assert.match(fromKubernetesManifests({ hello: 1 }).errors[0]!, /yq -o=json/); assert.match(fromKubernetesManifests("nope").errors[0]!, /Kubernetes manifests/);
  assert.equal(fromKubernetesManifests([bad, bad]).resources.length, 1);                          // the same workload twice is one
  assert.equal(fromKubernetesManifests(Array.from({ length: 501 }, (_, i) => ({ ...bad, metadata: { name: `p${i}` } }))).errors.length, 1);
  assert.equal(fromKubernetesManifests({ ...bad, metadata: { name: "p", namespace: "prod-eu" } }).resources[0]!.environment, "production"); // from the namespace or an environment label
});

test("compliance counts the Kubernetes controls only for organizations that have Kubernetes assets", () => {
  const without = complianceFrom([]), withK8s = complianceFrom([], ["k8s_workload"]);
  assert.ok(!without.some((f) => f.framework === "CIS-K8s"));
  assert.ok(withK8s.some((f) => f.framework === "CIS-K8s"));
  const nist = (l: typeof without) => l.find((f) => f.framework === "NIST-800-53")!.controls;
  assert.ok(nist(withK8s) > nist(without), "the shared frameworks gain controls only with Kubernetes in scope");
  assert.deepEqual(complianceFrom(["k8s-privileged"], ["k8s_workload"]).find((f) => f.framework === "CIS-K8s")!.failedControls.map((c) => c.control), ["5.2.2"]);
});

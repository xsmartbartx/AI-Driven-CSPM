#!/usr/bin/env node
// Checks Kubernetes manifests against NEXORA CSPM's rules before they are deployed. No dependencies, Node 18+.
//   kubectl kustomize . | yq -o=json '.' > manifests.json     (or: kubectl get deploy,sts,ds,cronjob,job,pod -A -o json > manifests.json)
//   CSPM_API_KEY=cspm_... node deploy/k8s-check.mjs manifests.json [--fail-on high] [--show-fixes] [--api https://api.cspm.onenexora.com]
// Exit code: 0 = passed, 1 = findings at or above --fail-on (default high), 2 = the check could not run.
// A read-only API key is enough. Only the settings the rules read are sent: no environment variables, commands, secrets or config.
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(name); if (i === -1) return dflt;
  const v = args[i + 1];
  // a flag without a value (an unset shell variable, for example) must not quietly fall back to a default that could let a failing plan pass
  if (v === undefined || v === "" || v.startsWith("--")) { console.error(`${name} needs a value.`); process.exit(2); }
  args.splice(i, 2); return v;
};
const showFixes = args.includes("--show-fixes") && !!args.splice(args.indexOf("--show-fixes"), 1);
const failOn = flag("--fail-on", "high");
const api = (flag("--api", process.env.CSPM_API_URL ?? "https://api.cspm.onenexora.com")).replace(/\/$/, "");
if (!["critical", "high", "medium", "low"].includes(failOn)) { console.error(`--fail-on must be critical, high, medium or low (got "${failOn}").`); process.exit(2); }
const file = args[0];
const key = process.env.CSPM_API_KEY;
if (!file || !key) { console.error("Usage: CSPM_API_KEY=cspm_... node k8s-check.mjs manifests.json [--fail-on critical|high|medium|low] [--show-fixes] [--api URL]"); process.exit(2); }

const KINDS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"]);
let input;
try { input = JSON.parse(readFileSync(file, "utf8")); } catch (e) { console.error(`Cannot read ${file}: ${e.message}`); process.exit(2); }
// Only the settings the rules read are sent. Manifests hold secrets (environment variables, commands, mounted secret names); none of them leave your machine.
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o && k in o).map((k) => [k, o[k]]));
const slimSc = (sc) => sc && { ...pick(sc, ["privileged", "allowPrivilegeEscalation", "runAsNonRoot", "runAsUser"]), ...(sc.capabilities?.add ? { capabilities: { add: sc.capabilities.add } } : {}) };
const slimSpec = (spec) => spec && {
  ...pick(spec, ["hostNetwork", "hostPID", "hostIPC"]), securityContext: slimSc(spec.securityContext),
  volumes: (spec.volumes ?? []).filter((v) => v?.hostPath).map((v) => ({ name: v.name, hostPath: { path: v.hostPath.path } })),
  containers: [...(spec.containers ?? []), ...(spec.initContainers ?? [])].map((c) => ({ name: c.name, image: c.image, securityContext: slimSc(c.securityContext), resources: { limits: c.resources?.limits?.memory ? { memory: "set" } : {} } })),
};
const docs = Array.isArray(input) ? input : Array.isArray(input?.items) ? input.items : [input];
const other = {};
const slim = [];
for (const m of docs) {
  if (!m || typeof m.kind !== "string") continue;
  if (!KINDS.has(m.kind)) { other[m.kind] = (other[m.kind] ?? 0) + 1; continue; }
  const meta = { name: m.metadata?.name, generateName: m.metadata?.generateName, namespace: m.metadata?.namespace, labels: pick(m.metadata?.labels ?? {}, ["environment", "env", "Environment"]) };
  const spec = m.kind === "Pod" ? { spec: slimSpec(m.spec) } : m.kind === "CronJob" ? { spec: { jobTemplate: { spec: { template: { spec: slimSpec(m.spec?.jobTemplate?.spec?.template?.spec) } } } } } : { spec: { template: { spec: slimSpec(m.spec?.template?.spec) } } };
  slim.push({ kind: m.kind, metadata: meta, ...spec });
}
if (!slim.length && !Object.keys(other).length) { console.error("No Kubernetes manifests found in that file."); process.exit(2); }

let res;
try {
  res = await fetch(`${api}/api/kubernetes/check`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${key}` }, body: JSON.stringify({ manifests: slim, failOn }), redirect: "error" }); // a redirect must never carry the plan to another address
} catch (e) { console.error(`Could not reach ${api}${e.cause ? ` (${e.cause.code ?? e.cause.message})` : ""}: ${e.message}`); process.exit(2); }
const out = await res.json().catch(() => null);
if (!res.ok) { console.error(`NEXORA CSPM answered ${res.status}: ${out?.error?.message ?? "unexpected response"}`); process.exit(2); }
// a proxy can answer 200 with a page of its own: that is a check that did not run, not a pass
if (!out || !Array.isArray(out.findings) || !Array.isArray(out.notes) || typeof out.fail !== "boolean" || !out.counts) { console.error("NEXORA CSPM sent an unexpected response; the check did not run."); process.exit(2); }

for (const f of out.findings) {
  console.log(`${f.severity.toUpperCase().padEnd(8)} ${f.address}  ${f.title}\n         fix: ${f.remediation}`);
  if (showFixes && f.fix?.yaml) console.log(f.fix.yaml.split("\n").map((l) => `           | ${l}`).join("\n"));
}
const c = out.counts;
console.log(`\n${out.resourceCount} workloads checked: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${out.suppressed ? `, ${out.suppressed} suppressed` : ""}.`);
for (const n of out.notes) console.log(`note: ${n}`);
const unread = Object.entries(other).map(([t, n]) => `${t} x${n}`).join(", ");
if (unread) console.log(`not checked (no rules for these kinds): ${unread}`);
console.log(out.fail ? `FAILED: findings at or above "${failOn}".` : `Passed (fail threshold: ${failOn}).`);
process.exit(out.fail ? 1 : 0);

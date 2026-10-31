#!/usr/bin/env node
// Checks a Terraform plan against NEXORA CSPM's rules before it is applied. No dependencies, Node 18+.
//   terraform plan -out=tfplan && terraform show -json tfplan > plan.json
//   CSPM_API_KEY=cspm_... node deploy/tf-check.mjs plan.json [--fail-on high] [--api https://api.cspm.onenexora.com]
// Exit code: 0 = passed, 1 = findings at or above --fail-on (default high), 2 = the check could not run.
// A read-only API key is enough. Only the resource types the rules read are sent, not the whole plan.
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(name); if (i === -1) return dflt;
  const v = args[i + 1];
  // a flag without a value (an unset shell variable, for example) must not quietly fall back to a default that could let a failing plan pass
  if (v === undefined || v === "" || v.startsWith("--")) { console.error(`${name} needs a value.`); process.exit(2); }
  args.splice(i, 2); return v;
};
const failOn = flag("--fail-on", "high");
const api = (flag("--api", process.env.CSPM_API_URL ?? "https://api.cspm.onenexora.com")).replace(/\/$/, "");
if (!["critical", "high", "medium", "low"].includes(failOn)) { console.error(`--fail-on must be critical, high, medium or low (got "${failOn}").`); process.exit(2); }
const file = args[0];
const key = process.env.CSPM_API_KEY;
if (!file || !key) { console.error("Usage: CSPM_API_KEY=cspm_... node tf-check.mjs plan.json [--fail-on critical|high|medium|low] [--api URL]"); process.exit(2); }

const TYPES = new Set(["aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block", "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_role", "aws_db_instance", "aws_rds_cluster"]);
let plan;
try { plan = JSON.parse(readFileSync(file, "utf8")); } catch (e) { console.error(`Cannot read ${file}: ${e.message}`); process.exit(2); }
const slimModule = (m) => m && {
  resources: (m.resources ?? []).filter((r) => TYPES.has(r.type)).map((r) => ({ address: r.address, type: r.type, expressions: Object.fromEntries(["bucket", "security_group_id"].filter((k) => r.expressions?.[k]).map((k) => [k, { references: r.expressions[k].references ?? [] }])) })),
  module_calls: Object.fromEntries(Object.entries(m.module_calls ?? {}).map(([k, c]) => [k, { module: slimModule(c.module) }])),
};
// Only the attributes the rules read are sent. A plan can hold secrets (a database password, tokens in user data); none of them leave your machine.
const tagsOf = (t) => (t && typeof t === "object" ? Object.fromEntries(["Environment", "environment", "env", "Env"].filter((k) => k in t).map((k) => [k, t[k]])) : undefined);
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o && k in o).map((k) => [k, o[k]]));
const KEEP = {
  aws_s3_bucket: ["acl"], aws_s3_bucket_acl: ["acl"], aws_s3_bucket_public_access_block: ["block_public_acls", "ignore_public_acls"],
  aws_security_group: ["ingress"], aws_security_group_rule: ["type", "cidr_blocks", "ipv6_cidr_blocks", "from_port", "to_port", "protocol"],
  aws_vpc_security_group_ingress_rule: ["cidr_ipv4", "cidr_ipv6", "from_port", "to_port", "ip_protocol"],
  aws_iam_policy: ["policy"], aws_iam_role_policy: ["policy"], aws_iam_user_policy: ["policy"], aws_iam_group_policy: ["policy"], aws_iam_role: ["inline_policy"],
  aws_db_instance: ["publicly_accessible", "storage_encrypted"], aws_rds_cluster: ["storage_encrypted"],
};
const after = (type, a) => {
  if (!a) return a;
  const out = pick(a, KEEP[type]);
  const tags = tagsOf(a.tags ?? a.tags_all); if (tags) out.tags = tags;
  if (type === "aws_security_group") out.ingress = (a.ingress ?? []).map((i) => pick(i, ["cidr_blocks", "ipv6_cidr_blocks", "from_port", "to_port", "protocol"]));
  if (type === "aws_iam_role") out.inline_policy = (a.inline_policy ?? []).map((p) => pick(p, ["name", "policy"]));
  if (type === "aws_db_instance" || type === "aws_rds_cluster") out.kms_key_id = a.kms_key_id ? "set" : a.kms_key_id; // whether one is set, not which key
  return out;
};
const unknownKeys = (type, u) => (u && typeof u === "object" ? pick(u, [...KEEP[type], "kms_key_id"]) : {});
const slim = {
  resource_changes: (plan.resource_changes ?? []).filter((c) => c.mode === "managed" && TYPES.has(c.type)).map((c) => ({ address: c.address, mode: c.mode, type: c.type, change: { actions: c.change?.actions, after: after(c.type, c.change?.after), after_unknown: unknownKeys(c.type, c.change?.after_unknown) } })),
  configuration: { root_module: slimModule(plan.configuration?.root_module) },
};
// the checker also reports types it does not read; count them here so the totals still add up
const other = {}; for (const c of plan.resource_changes ?? []) if (c.mode === "managed" && !TYPES.has(c.type)) other[c.type] = (other[c.type] ?? 0) + 1;

let res;
try {
  res = await fetch(`${api}/api/terraform/check`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${key}` }, body: JSON.stringify({ plan: slim, failOn }), redirect: "error" }); // a redirect must never carry the plan to another address
} catch (e) { console.error(`Could not reach ${api}${e.cause ? ` (${e.cause.code ?? e.cause.message})` : ""}: ${e.message}`); process.exit(2); }
const out = await res.json().catch(() => null);
if (!res.ok) { console.error(`NEXORA CSPM answered ${res.status}: ${out?.error?.message ?? "unexpected response"}`); process.exit(2); }
// a proxy can answer 200 with a page of its own: that is a check that did not run, not a pass
if (!out || !Array.isArray(out.findings) || !Array.isArray(out.notes) || typeof out.fail !== "boolean" || !out.counts) { console.error("NEXORA CSPM sent an unexpected response; the check did not run."); process.exit(2); }

for (const f of out.findings) console.log(`${f.severity.toUpperCase().padEnd(8)} ${f.address}  ${f.title}\n         fix: ${f.remediation}`);
const c = out.counts;
console.log(`\n${out.resourceCount} resources checked: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${out.suppressed ? `, ${out.suppressed} suppressed` : ""}.`);
for (const n of out.notes) console.log(`note: ${n}`);
const unread = Object.entries(other).map(([t, n]) => `${t} x${n}`).join(", ");
if (unread) console.log(`not checked (no rules for these): ${unread}`);
console.log(out.fail ? `FAILED: findings at or above "${failOn}".` : `Passed (fail threshold: ${failOn}).`);
process.exit(out.fail ? 1 : 0);

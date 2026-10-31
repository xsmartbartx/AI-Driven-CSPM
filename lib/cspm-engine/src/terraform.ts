import type { Resource } from "./index";
import { LIMITS } from "./index";

/**
 * Turns `terraform show -json <planfile>` into the resources the rules understand, so a change can be checked before it
 * is applied. It reads the plan's final state (everything that will exist after apply), never the cloud account.
 * Only what the rules need is read; everything else is counted as skipped. Values the plan cannot know yet (computed
 * at apply time) are left out rather than guessed, and are reported in `notes`.
 */
export interface TerraformResult { resources: Resource[]; skipped: { type: string; count: number }[]; notes: string[]; errors: string[] }

export const TERRAFORM_TYPES = [
  "aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block",
  "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
  "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_role",
  "aws_db_instance", "aws_rds_cluster",
] as const;

type Json = Record<string, any>;
const obj = (v: unknown): Json | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : null);
const list = (v: unknown): any[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const base = (address: string) => address.replace(/\[[^\]]*\]/g, "");

/** address (without index) -> addresses of what it points at, for every resource in the configuration, with the attribute that points */
function referenceMap(plan: Json): Map<string, Map<string, string[]>> {
  const out = new Map<string, Map<string, string[]>>();
  const walk = (mod: Json | null, prefix: string) => {
    if (!mod) return;
    for (const r of list(mod["resources"])) {
      const attrs = new Map<string, string[]>();
      for (const [k, v] of Object.entries(obj(r.expressions) ?? {})) {
        const refs = list(obj(v)?.["references"]).filter((x): x is string => typeof x === "string").map((x) => prefix + x.split(".").slice(0, 2).join(".")).map(base);
        if (refs.length) attrs.set(k, [...new Set(refs)]);
      }
      out.set(prefix + base(String(r.address)), attrs);
    }
    for (const [name, call] of Object.entries(obj(mod["module_calls"]) ?? {})) walk(obj(obj(call)?.["module"]), `${prefix}module.${name}.`);
  };
  walk(obj(obj(plan["configuration"])?.["root_module"]), "");
  return out;
}

const envOf = (tags: unknown): Resource["environment"] => {
  const t = obj(tags); if (!t) return undefined;
  const v = String(t["Environment"] ?? t["environment"] ?? t["env"] ?? t["Env"] ?? "").toLowerCase();
  return /^prod/.test(v) ? "production" : /^(stag|stg|test|qa)/.test(v) ? "staging" : /^dev/.test(v) ? "development" : undefined;
};

function statementsOf(policy: unknown): Json[] | null {
  let doc: unknown = policy;
  if (typeof doc === "string") { try { doc = JSON.parse(doc); } catch { return null; } }
  const st = obj(doc)?.["Statement"];
  if (st === undefined) return null; // unknown until apply, or not a policy document
  return list(st).map(obj).filter((x): x is Json => !!x).map((s) => ({ effect: s["Effect"] ?? "Allow", actions: s["Action"], resources: s["Resource"] }));
}

function ingressRule(cidr: unknown, from: unknown, to: unknown, protocol: unknown): Json | null {
  if (typeof cidr !== "string" || !cidr) return null;
  const p = String(protocol ?? "");
  if (p === "icmp" || p === "icmpv6" || p === "1") return null;
  if (p === "-1" || p === "all") return { cidr, port: "all" };
  const lo = Number(from), hi = Number(to);
  return Number.isFinite(lo) && Number.isFinite(hi) ? { cidr, fromPort: lo, toPort: hi } : { cidr, port: "all" };
}

export function fromTerraformPlan(input: unknown): TerraformResult {
  const empty = (errors: string[]): TerraformResult => ({ resources: [], skipped: [], notes: [], errors });
  const plan = obj(input);
  if (!plan || !Array.isArray(plan["resource_changes"]))
    return empty(["This does not look like a Terraform plan in JSON. Create it with: terraform plan -out=tfplan && terraform show -json tfplan > plan.json"]);
  const refs = referenceMap(plan);
  const notes: string[] = [];
  let unknownValues = 0;
  const skipped = new Map<string, number>();

  // the final state of everything that will exist: not deleted, and a managed resource
  const live = (plan["resource_changes"] as any[]).filter((c) => obj(c) && c.mode === "managed" && !list(c.change?.actions).every((a) => a === "delete") && obj(c.change?.after));
  const unknownAt = (c: Json, key: string) => obj(c.change.after_unknown)?.[key] === true;
  const get = (c: Json, key: string) => { if (unknownAt(c, key)) { unknownValues++; return undefined; } return c.change.after[key]; };

  /** resources of a type whose attribute points at the given resource */
  const pointingAt = (type: string, attr: string, target: string): Json[] =>
    live.filter((c) => c.type === type && (refs.get(base(String(c.address)))?.get(attr) ?? []).includes(base(target)));

  const out: Resource[] = [];
  for (const c of live) {
    const address = String(c.address);
    const after = c.change.after as Json;
    switch (c.type) {
      case "aws_s3_bucket": {
        const r: Resource = { type: "s3_bucket", name: address };
        const env = envOf(after["tags"] ?? after["tags_all"]); if (env) r["environment"] = env;
        const pab = pointingAt("aws_s3_bucket_public_access_block", "bucket", address).map((x) => x.change.after as Json);
        const blocked = pab.some((p) => p["block_public_acls"] === true && p["ignore_public_acls"] === true);
        const acls = [get(c, "acl"), ...pointingAt("aws_s3_bucket_acl", "bucket", address).map((x) => x.change.after["acl"])];
        if (acls.some((a) => a === "public-read" || a === "public-read-write") && !blocked) r["public_read"] = true;
        out.push(r); break;
      }
      case "aws_security_group": {
        const ingress: Json[] = [];
        for (const i of list(get(c, "ingress"))) for (const key of ["cidr_blocks", "ipv6_cidr_blocks"])
          for (const cidr of list(obj(i)?.[key])) { const rule = ingressRule(cidr, i.from_port, i.to_port, i.protocol); if (rule) ingress.push(rule); }
        for (const x of pointingAt("aws_security_group_rule", "security_group_id", address)) {
          const a = x.change.after as Json; if (a["type"] !== "ingress") continue;
          for (const key of ["cidr_blocks", "ipv6_cidr_blocks"]) for (const cidr of list(a[key])) { const rule = ingressRule(cidr, a["from_port"], a["to_port"], a["protocol"]); if (rule) ingress.push(rule); }
        }
        for (const x of pointingAt("aws_vpc_security_group_ingress_rule", "security_group_id", address)) {
          const a = x.change.after as Json;
          for (const key of ["cidr_ipv4", "cidr_ipv6"]) { const rule = ingressRule(a[key], a["from_port"], a["to_port"], a["ip_protocol"]); if (rule) ingress.push(rule); }
        }
        const r: Resource = { type: "security_group", name: address, ingress }; const env = envOf(after["tags"] ?? after["tags_all"]); if (env) r["environment"] = env;
        out.push(r); break;
      }
      case "aws_iam_policy": case "aws_iam_role_policy": case "aws_iam_user_policy": case "aws_iam_group_policy": {
        const statements = statementsOf(get(c, "policy"));
        if (statements) out.push({ type: "iam_policy", name: address, statements }); else notes.push(`${address}: the policy is not known until apply, so it was not checked.`);
        break;
      }
      case "aws_iam_role": {
        for (const p of list(get(c, "inline_policy"))) {
          const statements = statementsOf(obj(p)?.["policy"]);
          if (statements) out.push({ type: "iam_policy", name: `${address}#inline:${obj(p)?.["name"] ?? out.length}`, statements });
        }
        break;
      }
      case "aws_db_instance": case "aws_rds_cluster": {
        const enc = get(c, "storage_encrypted"), kms = get(c, "kms_key_id");
        const r: Resource = { type: "database", name: address };
        if (enc === true || kms) r["encrypted"] = true;
        else if (!unknownAt(c, "storage_encrypted") && !unknownAt(c, "kms_key_id")) r["encrypted"] = false; // never guessed from a value the plan cannot know yet
        if (c.type === "aws_db_instance") { const pub = get(c, "publicly_accessible"); if (pub !== undefined) r["publicly_accessible"] = pub === true; }
        const env = envOf(after["tags"] ?? after["tags_all"]); if (env) r["environment"] = env;
        out.push(r); break;
      }
      case "aws_s3_bucket_acl": case "aws_s3_bucket_public_access_block": case "aws_security_group_rule": case "aws_vpc_security_group_ingress_rule": break; // read through their parent
      default: skipped.set(c.type, (skipped.get(c.type) ?? 0) + 1);
    }
  }
  if (unknownValues) notes.push(`${unknownValues} value${unknownValues === 1 ? " is" : "s are"} only known after apply and could not be checked.`);
  notes.push("Checked: S3 public ACLs, security group ingress, IAM policy documents, and RDS public access and storage encryption. S3 default encryption is on in AWS, so a missing encryption block is not reported.");
  if (out.length > LIMITS.maxResources) return empty([`Too many resources (${out.length}). The limit is ${LIMITS.maxResources} per check.`]);
  return { resources: out, skipped: [...skipped].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count), notes, errors: [] };
}

// Attack paths: chains an attacker could follow from the internet to something valuable, built from the relationships
// between resources (which security group is on which instance, which role an instance runs as, what the role may do).
// Pure functions, no I/O. Honest by construction: a hop exists only if the data says so. Nothing is assumed, so a path is
// a real possibility given the configuration, not a prediction. What it cannot see (subnets, route tables, NACLs, VPC
// peering, SCPs, permission boundaries, resource policies other than bucket names, instance-level firewalls) is listed in
// `notes`, and missing data produces NO path rather than a guessed one.
import { defaultCriticality, severityOf, type Resource, type Severity } from "./index";

export type NodeKind = "internet" | "instance" | "role" | "database" | "bucket" | "account";
export interface PathNode { id: string; kind: NodeKind; name: string; environment?: string }
export interface PathEdge {
  from: string; to: string;
  kind: "exposes" | "assumes" | "grants_admin" | "reads" | "connects";
  /** one plain sentence: why this hop is possible */
  label: string;
  /** names of the resources this hop depends on (security group, policy, ...), so their findings can be linked */
  assets: string[];
  /** the fix that closes THIS hop; the same fix on several paths is a choke point */
  fix: { id: string; action: string; asset: string };
}
export interface AttackPath { id: string; score: number; severity: Severity; title: string; target: string; nodes: PathNode[]; edges: PathEdge[] }
export interface ChokePoint { fixId: string; action: string; asset: string; paths: number; pathIds: string[] }
export interface PathAnalysis {
  paths: AttackPath[];
  chokePoints: ChokePoint[];
  coverage: { instances: number; roles: number; instancesWithoutRole: number; hasRelationshipData: boolean };
  notes: string[];
}

export const NOT_MODELLED = "Not modelled: subnets and route tables, network ACLs, VPC peering, service control policies, permission boundaries, resource policies other than the bucket name, and firewalls on the instance itself. A path means the configuration allows each hop; it does not prove an attacker can succeed.";

// ---- small helpers ------------------------------------------------------------------------------------------------

const list = (v: unknown): string[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]).filter((x): x is string => typeof x === "string");
const isWorld = (c: unknown) => c === "0.0.0.0/0" || c === "::/0";
const SENSITIVE = new Set([22, 3389, 1433, 3306, 5432, 6379, 9200, 27017]);
const glob = (pattern: string, value: string) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i").test(value);
const allows = (stmtActions: string[], action: string) => stmtActions.some((a) => glob(a, action));

interface Ingress { cidr?: string; port?: number | string; fromPort?: number; toPort?: number; sourceGroup?: string }
const rangeOf = (i: Ingress): [number, number] => {
  if (i.port === "all" || i.port === "*" || i.port === -1) return [0, 65535];
  if (typeof i.port === "number") return [i.port, i.port];
  if (typeof i.port === "string" && /^\d+$/.test(i.port)) return [Number(i.port), Number(i.port)];
  if (typeof i.fromPort === "number" && typeof i.toPort === "number") return [i.fromPort, i.toPort];
  return [0, 65535];
};
const portLabel = ([lo, hi]: [number, number]) => (lo === 0 && hi === 65535 ? "all ports" : lo === hi ? `port ${lo}` : `ports ${lo}-${hi}`);
const entryFactor = (ranges: [number, number][]) => {
  if (ranges.some(([lo, hi]) => (lo === 0 && hi === 65535) || [...SENSITIVE].some((p) => p >= lo && p <= hi))) return 1;
  if (ranges.every(([lo, hi]) => lo === hi && (lo === 80 || lo === 443))) return 0.6; // a web server open to the world is normal; it is only the first hop
  return 0.8;
};

/** Statements an AWS-managed policy is known to grant. Anything not listed is reported as unknown, never guessed. */
const MANAGED: Record<string, { effect: string; actions: string[]; resources: string[] }[]> = {
  AdministratorAccess: [{ effect: "Allow", actions: ["*"], resources: ["*"] }],
  AmazonS3FullAccess: [{ effect: "Allow", actions: ["s3:*"], resources: ["*"] }],
  AmazonS3ReadOnlyAccess: [{ effect: "Allow", actions: ["s3:Get*", "s3:List*"], resources: ["*"] }],
  IAMFullAccess: [{ effect: "Allow", actions: ["iam:*"], resources: ["*"] }],
  PowerUserAccess: [{ effect: "Allow", actions: ["*"], resources: ["*"] }], // everything except IAM management: reads all data, not admin
};
const managedName = (arn: string) => arn.split("/").pop() ?? arn;

// ---- the analysis -------------------------------------------------------------------------------------------------

export function analyzePaths(resources: Resource[]): PathAnalysis {
  const by = (t: string) => resources.filter((r) => r.type === t);
  const instances = by("ec2_instance"), roles = by("iam_role"), groups = by("security_group"), dbs = by("database"), buckets = by("s3_bucket"), policies = by("iam_policy");
  const notes: string[] = [NOT_MODELLED];
  const cov = { instances: instances.length, roles: roles.length, instancesWithoutRole: 0, hasRelationshipData: instances.length > 0 };

  // lookups: a security group is referenced by name, by id, or by the collector's "name (sg-id)" form
  const groupIndex = new Map<string, Resource>();
  for (const g of groups) {
    groupIndex.set(g.name, g);
    if (typeof g["id"] === "string") groupIndex.set(g["id"], g);
    const m = g.name.match(/\((sg-[\w]+)\)\s*$/); if (m) groupIndex.set(m[1]!, g);
  }
  const groupsOf = (r: Resource) => list(r["security_groups"]).map((ref) => groupIndex.get(ref)).filter((g): g is Resource => !!g);
  const refIds = (g: Resource) => new Set([g.name, ...(typeof g["id"] === "string" ? [g["id"] as string] : []), ...(g.name.match(/\((sg-[\w]+)\)\s*$/) ? [g.name.match(/\((sg-[\w]+)\)\s*$/)![1]!] : [])]);
  const ingressOf = (g: Resource): Ingress[] => (Array.isArray(g["ingress"]) ? (g["ingress"] as Ingress[]) : []);
  const roleIndex = new Map(roles.map((r) => [r.name, r]));
  const policyIndex = new Map<string, Resource>();
  for (const p of policies) { policyIndex.set(p.name, p); const short = p.name.split(":").pop(); if (short) policyIndex.set(short, p); }

  const unknownManaged = new Set<string>(), unresolvedPolicies = new Set<string>();
  /** The statements a role is allowed by: attached customer policies, inline statements and known managed policies. */
  const statementsOf = (role: Resource) => {
    const out: { effect: string; actions: string[]; resources: string[]; from: string; asset?: string }[] = [];
    for (const name of list(role["policies"])) {
      const p = policyIndex.get(name);
      if (!p) { unresolvedPolicies.add(name); continue; }
      for (const s of (Array.isArray(p["statements"]) ? p["statements"] : []) as any[]) out.push({ effect: String(s.effect ?? "Allow"), actions: list(s.actions), resources: list(s.resources), from: `policy ${name.split(":").pop()}`, asset: p.name });
    }
    for (const s of (Array.isArray(role["inline_statements"]) ? role["inline_statements"] : []) as any[]) out.push({ effect: String(s.effect ?? "Allow"), actions: list(s.actions), resources: list(s.resources), from: "an inline policy" });
    for (const arn of list(role["managed_policies"])) {
      const stmts = MANAGED[managedName(arn)];
      if (!stmts) { unknownManaged.add(managedName(arn)); continue; }
      for (const s of stmts) out.push({ ...s, from: managedName(arn) });
    }
    return out.filter((s) => s.effect.toLowerCase() === "allow");
  };

  const nodes = new Map<string, PathNode>();
  const node = (kind: NodeKind, name: string, r?: Resource): PathNode => {
    const id = `${kind}:${name}`;
    if (!nodes.has(id)) nodes.set(id, { id, kind, name, ...(r?.environment ? { environment: r.environment } : {}) });
    return nodes.get(id)!;
  };
  const internet = node("internet", "Internet");
  const edges: (PathEdge & { factor: number })[] = [];
  const crit = (r: Resource) => 0.5 + 0.5 * Math.min(10, Math.max(1, Number(r.criticality) || defaultCriticality(r))) / 10;

  // 1. internet -> instance: a public IP and a security group that lets the whole internet in
  for (const inst of instances) {
    if (inst["public_ip"] !== true) continue;
    for (const g of groupsOf(inst)) {
      const open = ingressOf(g).filter((i) => isWorld(i.cidr));
      if (!open.length) continue;
      const ranges = open.map(rangeOf);
      edges.push({
        from: internet.id, to: node("instance", inst.name, inst).id, kind: "exposes", factor: entryFactor(ranges), assets: [g.name],
        label: `${inst.name} has a public IP and ${g.name} lets the internet in on ${[...new Set(ranges.map(portLabel))].join(", ")}`,
        fix: { id: `close:${g.name}:${ranges.map(portLabel).join(",")}`, action: `Remove the internet-wide rule (${[...new Set(ranges.map(portLabel))].join(", ")}) from ${g.name}`, asset: g.name },
      });
    }
  }

  // 2. instance -> role -> account / bucket
  for (const inst of instances) {
    const roleName = typeof inst["role"] === "string" ? (inst["role"] as string) : "";
    const role = roleName ? roleIndex.get(roleName) : undefined;
    if (!roleName || !role) { cov.instancesWithoutRole++; continue; }
    const stmts = statementsOf(role);
    const instNode = node("instance", inst.name, inst), roleNode = node("role", role.name);
    // full control of the account: every action on everything, or all of IAM on everything (it can grant itself anything).
    // PowerUserAccess is "everything except IAM", so it reads all data but is not full control.
    const grantsAll = stmts.find((s) => s.actions.includes("*") && s.resources.includes("*") && s.from !== "PowerUserAccess");
    const iamAll = stmts.find((s) => s.actions.includes("iam:*") && s.resources.includes("*"));
    const takeover = grantsAll ?? iamAll;
    edges.push({ from: instNode.id, to: roleNode.id, kind: "assumes", factor: 1, assets: [], label: `${inst.name} runs as role ${role.name}, so code on it can use the role's permissions`, fix: { id: `detach:${inst.name}:${role.name}`, action: `Run ${inst.name} without role ${role.name}, or with a narrower role`, asset: inst.name } });
    if (takeover) {
      const acct = node("account", "AWS account (full control)");
      edges.push({ from: roleNode.id, to: acct.id, kind: "grants_admin", factor: 1, assets: takeover.asset ? [takeover.asset] : [], label: `${takeover.from} lets ${role.name} ${takeover.actions.includes("*") ? "do anything" : "manage IAM"} on everything, which is full control of the account`, fix: { id: `narrow:${role.name}`, action: `Replace the broad permissions of ${role.name} with only what it needs`, asset: role.name } });
    }
    for (const b of takeover ? [] : buckets) { // full control already covers every bucket: no separate path per bucket
      const reader = stmts.find((s) => (allows(s.actions, "s3:GetObject") || s.actions.includes("*")) && s.resources.some((x) => x === "*" || glob(x, `arn:aws:s3:::${b.name}`) || glob(x, `arn:aws:s3:::${b.name}/x`)));
      if (!reader) continue;
      edges.push({ from: roleNode.id, to: node("bucket", b.name, b).id, kind: "reads", factor: 0.75 * crit(b), assets: reader.asset ? [reader.asset, b.name] : [b.name], label: `${reader.from} lets ${role.name} read objects in ${b.name}`, fix: { id: `narrow:${role.name}`, action: `Limit ${role.name} so it cannot read ${b.name}`, asset: role.name } });
    }
  }

  // 3. instance -> database: the database's security group names the instance's security group as an allowed source
  for (const db of dbs) {
    for (const dg of groupsOf(db)) {
      for (const rule of ingressOf(dg)) {
        if (!rule.sourceGroup) continue;
        for (const inst of instances) {
          const mine = groupsOf(inst).find((g) => refIds(g).has(rule.sourceGroup!));
          if (!mine) continue;
          edges.push({ from: node("instance", inst.name, inst).id, to: node("database", db.name, db).id, kind: "connects", factor: 0.85 * crit(db), assets: [dg.name, mine.name], label: `${dg.name} accepts connections from ${mine.name} on ${portLabel(rangeOf(rule))}, and ${inst.name} is in ${mine.name}`, fix: { id: `restrict:${dg.name}:${mine.name}`, action: `Stop ${dg.name} from accepting connections from ${mine.name}`, asset: dg.name } });
        }
      }
    }
  }

  // enumerate: internet -> ... -> a target (account, bucket or database), no cycles, at most 5 hops.
  // A role shared by several instances yields the same role -> target edge once per instance: keep one of each.
  const out = new Map<string, typeof edges>();
  const seenEdge = new Set<string>();
  for (const e of edges) {
    const key = `${e.from}|${e.to}|${e.kind}|${e.fix.id}`;
    if (seenEdge.has(key)) continue;
    seenEdge.add(key);
    out.set(e.from, [...(out.get(e.from) ?? []), e]);
  }
  const found: AttackPath[] = [];
  const walk = (at: string, trail: typeof edges, seen: Set<string>) => {
    for (const e of out.get(at) ?? []) {
      if (seen.has(e.to) || trail.length >= 5) continue;
      const t = [...trail, e];
      const n = nodes.get(e.to)!;
      if (["account", "bucket", "database"].includes(n.kind)) {
        const score = Math.max(1, Math.min(100, Math.round(100 * t.reduce((p, x) => p * x.factor, 1))));
        const first = nodes.get(t[0]!.to)!;
        found.push({
          id: t.map((x) => `${x.from}>${x.to}`).join("|"), score, severity: severityOf(score), target: n.name,
          title: `${first.name} is reachable from the internet and leads to ${n.kind === "account" ? "full control of the AWS account" : `${n.kind === "bucket" ? "bucket" : "database"} ${n.name}`}`,
          nodes: [internet, ...t.map((x) => nodes.get(x.to)!)], edges: t.map(({ factor: _f, ...x }) => x),
        });
      }
      walk(e.to, t, new Set([...seen, e.to]));
    }
  };
  walk(internet.id, [], new Set([internet.id]));
  found.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  const paths = found.slice(0, 50);
  if (found.length > paths.length) notes.push(`Showing the ${paths.length} highest-risk of ${found.length} paths.`);

  // choke points: one fix that appears on several paths
  const byFix = new Map<string, ChokePoint>();
  for (const p of paths) for (const e of p.edges) {
    const c = byFix.get(e.fix.id) ?? { fixId: e.fix.id, action: e.fix.action, asset: e.fix.asset, paths: 0, pathIds: [] };
    if (!c.pathIds.includes(p.id)) { c.pathIds.push(p.id); c.paths++; }
    byFix.set(e.fix.id, c);
  }
  const chokePoints = [...byFix.values()].sort((a, b) => b.paths - a.paths || a.asset.localeCompare(b.asset)).slice(0, 8);

  if (!instances.length) notes.unshift("No instances were found, so no attack paths can be built. Instances and their roles come from a connected AWS account (with the updated role template) or from ec2_instance and iam_role entries in a pasted configuration.");
  if (cov.instancesWithoutRole) notes.push(`${cov.instancesWithoutRole} instance${cov.instancesWithoutRole === 1 ? "" : "s"} ${cov.instancesWithoutRole === 1 ? "has" : "have"} no role information, so paths through ${cov.instancesWithoutRole === 1 ? "it" : "them"} to the account or to data are not shown.`);
  if (unknownManaged.size) notes.push(`These AWS-managed policies are attached to a role but their contents are not known here, so they were not evaluated: ${[...unknownManaged].sort().join(", ")}.`);
  if (unresolvedPolicies.size) notes.push(`These policies are attached to a role but were not part of the scan: ${[...unresolvedPolicies].sort().join(", ")}.`);
  return { paths, chokePoints, coverage: cov, notes };
}

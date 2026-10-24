// Rules engine: pure functions, no I/O, runs in Node and the browser.

export type Severity = "critical" | "high" | "medium" | "low";

export interface Resource {
  type: string;
  name: string;
  environment?: "production" | "staging" | "development";
  criticality?: number;
  owner?: string;
  [k: string]: unknown;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  riskScore: number;
  resourceType: string;
  resourceName: string;
  evidence: Record<string, unknown>;
  remediation: string;
  frameworks: string[];
}

export interface Rule {
  id: string;
  title: string;
  resourceType: string;
  /** 0-100 before asset criticality adjustment */
  base: number;
  remediation: string;
  /** Indicative control IDs only. Verify against the benchmark version you audit against. */
  frameworks: string[];
  check(r: Resource): Record<string, unknown> | null;
}

export const SENSITIVE_PORTS: Record<number, string> = {
  22: "SSH", 3389: "RDP", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
};

const isWorld = (c: unknown) => c === "0.0.0.0/0" || c === "::/0";
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
interface Ingress { cidr?: string; port?: number | string; fromPort?: number; toPort?: number }
const ingressOf = (r: Resource): Ingress[] => arr(r["ingress"]).filter((x): x is Ingress => typeof x === "object" && x !== null);
/** Port spec as an inclusive [lo, hi] range. A bare/unknown spec means all ports. */
const portsOf = (i: Ingress): [number, number] => {
  if (i.port === "all" || i.port === "*" || i.port === -1) return [0, 65535];
  if (typeof i.port === "number") return [i.port, i.port];
  if (typeof i.port === "string" && /^\d+$/.test(i.port)) return [Number(i.port), Number(i.port)];
  if (typeof i.fromPort === "number" && typeof i.toPort === "number") return [Math.max(0, i.fromPort), Math.min(65535, i.toPort)];
  return [0, 65535];
};
const WEB_PORTS = [80, 443];
const sensitiveIn = ([lo, hi]: [number, number]) => Object.keys(SENSITIVE_PORTS).map(Number).filter((s) => s >= lo && s <= hi);
/** Open to the world on something other than a single web port or a single already-reported sensitive port. */
const broadExposure = ([lo, hi]: [number, number]) => lo !== hi || !(WEB_PORTS.includes(lo) || lo in SENSITIVE_PORTS);

interface Statement { effect?: string; actions?: unknown; resources?: unknown }
const stmts = (r: Resource): Statement[] => arr(r["statements"]).filter((x): x is Statement => typeof x === "object" && x !== null);
const allowStmts = (r: Resource) => stmts(r).filter((s) => (s.effect ?? "Allow").toLowerCase() === "allow");
const wildAction = (s: Statement) => arr(s.actions).some((a) => a === "*");
const svcWildAction = (s: Statement) => arr(s.actions).some((a) => typeof a === "string" && a.endsWith(":*"));
const wildRes = (s: Statement) => arr(s.resources).some((a) => a === "*");

export const RULES: Rule[] = [
  {
    id: "s3-public-read", title: "Storage bucket is publicly readable", resourceType: "s3_bucket", base: 85,
    remediation: "Turn on 'block public access' for the bucket and account, remove public ACLs and policy statements that grant access to everyone, and serve public content through a CDN with origin access instead.",
    frameworks: ["CIS-AWS 2.1.5", "PCI-DSS 1.3.1", "NIST-800-53 AC-3", "ISO-27001 A.8.3", "GDPR Art.32"],
    check: (r) => (r["public_read"] === true || r["public"] === true || r["acl"] === "public-read" ? { public_read: true } : null),
  },
  {
    id: "s3-no-encryption", title: "Storage bucket has no encryption at rest", resourceType: "s3_bucket", base: 55,
    remediation: "Enable default server-side encryption (SSE-KMS preferred) on the bucket, and re-encrypt existing objects.",
    frameworks: ["CIS-AWS 2.1.1", "PCI-DSS 3.5.1", "NIST-800-53 SC-28", "ISO-27001 A.8.24", "GDPR Art.32"],
    check: (r) => (r["encrypted"] === false ? { encrypted: false } : null),
  },
  {
    id: "sg-sensitive-port-open", title: "Admin or database port open to the internet", resourceType: "security_group", base: 90,
    remediation: "Remove the 0.0.0.0/0 rule. Allow the port only from a bastion, VPN or specific office/CIDR range, or use a managed access service.",
    frameworks: ["CIS-AWS 5.2", "PCI-DSS 1.3.2", "NIST-800-53 SC-7", "ISO-27001 A.8.20"],
    check: (r) => {
      const hits = new Set<number>();
      const cidrs = new Set<string>();
      for (const i of ingressOf(r)) if (isWorld(i.cidr)) { const s = sensitiveIn(portsOf(i)); if (s.length) cidrs.add(String(i.cidr)); s.forEach((p) => hits.add(p)); }
      return hits.size ? { ports: [...hits].sort((a, b) => a - b).map((p) => `${p} (${SENSITIVE_PORTS[p]})`), cidr: [...cidrs].join(", ") } : null;
    },
  },
  {
    id: "sg-open-world", title: "Security group allows all internet traffic", resourceType: "security_group", base: 65,
    remediation: "Replace 0.0.0.0/0 with the narrowest CIDR ranges that need access, and limit the rule to specific ports.",
    frameworks: ["CIS-AWS 5.3", "PCI-DSS 1.3.1", "NIST-800-53 SC-7", "ISO-27001 A.8.20"],
    check: (r) => {
      const open = ingressOf(r).filter((i) => isWorld(i.cidr));
      const broad = open.filter((i) => broadExposure(portsOf(i)));
      return broad.length ? { open_rules: broad.length, cidr: [...new Set(broad.map((i) => String(i.cidr)))].join(", ") } : null;
    },
  },
  {
    id: "iam-admin-access", title: "Policy grants full administrator access", resourceType: "iam_policy", base: 95,
    remediation: "Replace Action:* on Resource:* with the specific actions and resource ARNs the role needs. Use permission boundaries and access analyzer to right-size.",
    frameworks: ["CIS-AWS 1.16", "PCI-DSS 7.2.1", "NIST-800-53 AC-6", "ISO-27001 A.8.2"],
    check: (r) => (allowStmts(r).some((s) => wildAction(s) && wildRes(s)) ? { actions: "*", resources: "*" } : null),
  },
  {
    id: "iam-wildcard-action", title: "Policy uses wildcard actions", resourceType: "iam_policy", base: 65,
    remediation: "List the exact actions required instead of '*' or 'service:*'.",
    frameworks: ["CIS-AWS 1.16", "NIST-800-53 AC-6", "ISO-27001 A.8.2"],
    check: (r) => {
      const a = allowStmts(r);
      if (a.some((s) => wildAction(s) && wildRes(s))) return null; // reported as admin access
      const hit = a.filter((s) => wildAction(s) || svcWildAction(s));
      return hit.length ? { actions: hit.flatMap((s) => arr(s.actions).filter((x) => x === "*" || (typeof x === "string" && x.endsWith(":*")))) } : null;
    },
  },
  {
    id: "iam-wildcard-resource", title: "Policy applies to all resources", resourceType: "iam_policy", base: 40,
    remediation: "Scope the statement to specific resource ARNs.",
    frameworks: ["CIS-AWS 1.16", "NIST-800-53 AC-6"],
    check: (r) => {
      const a = allowStmts(r);
      if (a.some((s) => wildAction(s) && wildRes(s))) return null;
      return a.some(wildRes) ? { resources: "*" } : null;
    },
  },
  {
    id: "db-public", title: "Database is publicly accessible", resourceType: "database", base: 88,
    remediation: "Disable public accessibility, place the database in private subnets, and connect through a bastion, VPN or private endpoint.",
    frameworks: ["CIS-AWS 2.3.3", "PCI-DSS 1.4.2", "NIST-800-53 SC-7", "ISO-27001 A.8.20", "GDPR Art.32"],
    check: (r) => (r["publicly_accessible"] === true ? { publicly_accessible: true } : null),
  },
  {
    id: "db-no-encryption", title: "Database has no encryption at rest", resourceType: "database", base: 60,
    remediation: "Enable storage encryption. For existing instances, snapshot, copy the snapshot with encryption on, and restore.",
    frameworks: ["CIS-AWS 2.3.1", "PCI-DSS 3.5.1", "NIST-800-53 SC-28", "ISO-27001 A.8.24", "GDPR Art.32"],
    check: (r) => (r["encrypted"] === false ? { encrypted: false } : null),
  },
];

export const RESOURCE_TYPES = [...new Set(RULES.map((r) => r.resourceType))];
/** Accepted in a scan and stored, but have no rules of their own: they only describe relationships for attack paths. */
export const RELATIONAL_TYPES = ["ec2_instance", "iam_role"];
export * from "./paths";

export function severityOf(score: number): Severity {
  return score >= 76 ? "critical" : score >= 51 ? "high" : score >= 21 ? "medium" : "low";
}

/** Asset-level risk. v1 inputs: rule base score and asset criticality (1-10, default 5 => x1.0). */
export function riskScore(base: number, criticality = 5): number {
  const c = Number.isFinite(criticality) ? Math.min(10, Math.max(1, criticality)) : 5; // never NaN
  return Math.max(0, Math.min(100, Math.round(base * (0.85 + 0.03 * c))));
}

export const LIMITS = { maxResources: 500, maxBytes: 1_000_000 };

export interface Parsed { resources: Resource[]; errors: string[] }

export function parseInput(input: unknown): Parsed {
  const errors: string[] = [];
  let list: unknown = input;
  if (input && typeof input === "object" && !Array.isArray(input) && "resources" in input) list = (input as any).resources;
  if (!Array.isArray(list)) return { resources: [], errors: ['Expected a JSON array of resources, or an object like {"resources": [...]}.'] };
  if (list.length === 0) return { resources: [], errors: ["No resources found. Add at least one resource."] };
  if (list.length > LIMITS.maxResources) return { resources: [], errors: [`Too many resources (${list.length}). The limit is ${LIMITS.maxResources} per scan.`] };
  const resources: Resource[] = [];
  const seen = new Set<string>();
  list.forEach((r, i) => {
    if (!r || typeof r !== "object" || Array.isArray(r)) return void errors.push(`Item ${i + 1}: must be an object.`);
    const o = r as Resource;
    if (typeof o.type !== "string" || !o.type) return void errors.push(`Item ${i + 1}: missing "type".`);
    if (typeof o.name !== "string" || !o.name.trim()) return void errors.push(`Item ${i + 1}: missing "name".`);
    if (o.name.length > 200) return void errors.push(`Item ${i + 1}: name is longer than 200 characters.`);
    const key = `${o.type}/${o.name}`;
    if (seen.has(key)) return void errors.push(`Item ${i + 1}: duplicate ${key}.`);
    seen.add(key);
    resources.push(o);
  });
  return { resources, errors };
}

export function evaluate(resources: Resource[]): { findings: Finding[]; unknownTypes: string[] } {
  const findings: Finding[] = [];
  const unknown = new Set<string>();
  for (const r of resources) {
    if (RELATIONAL_TYPES.includes(r.type)) continue;
    if (!RESOURCE_TYPES.includes(r.type)) { unknown.add(r.type); continue; }
    for (const rule of RULES) {
      if (rule.resourceType !== r.type) continue;
      const evidence = rule.check(r);
      if (!evidence) continue;
      const crit = Number(r.criticality); // a non-numeric criticality (e.g. "high") falls back to the environment default
      const score = riskScore(rule.base, Number.isFinite(crit) ? crit : defaultCriticality(r));
      findings.push({
        ruleId: rule.id, title: rule.title, severity: severityOf(score), riskScore: score,
        resourceType: r.type, resourceName: r.name, evidence, remediation: rule.remediation, frameworks: rule.frameworks,
      });
    }
  }
  findings.sort((a, b) => b.riskScore - a.riskScore || a.resourceName.localeCompare(b.resourceName));
  return { findings, unknownTypes: [...unknown] };
}

export function defaultCriticality(r: Resource): number {
  return r.environment === "production" ? 8 : r.environment === "staging" ? 5 : r.environment === "development" ? 3 : 5;
}

const WEIGHT: Record<Severity, number> = { critical: 15, high: 8, medium: 3, low: 1 };
/** Posture 0-100, higher is safer. Counts only open findings. */
export function postureScore(counts: Record<Severity, number>): number {
  const penalty = (Object.keys(WEIGHT) as Severity[]).reduce((s, k) => s + (counts[k] ?? 0) * WEIGHT[k], 0);
  return Math.max(0, Math.round(100 - penalty));
}

export function ruleById(id: string) { return RULES.find((r) => r.id === id); }

export interface FrameworkCoverage { framework: string; controls: number; failed: number; coverage: number; failedControls: { control: string; ruleIds: string[] }[] }
/** Controls are the control IDs the rule set maps to. A control fails if any open finding maps to it. */
export function complianceFrom(openRuleIds: Iterable<string>): FrameworkCoverage[] {
  const open = new Set(openRuleIds);
  const byFw = new Map<string, Map<string, Set<string>>>();
  for (const rule of RULES) for (const f of rule.frameworks) {
    const i = f.indexOf(" ");
    const fw = f.slice(0, i), control = f.slice(i + 1);
    if (!byFw.has(fw)) byFw.set(fw, new Map());
    const m = byFw.get(fw)!;
    if (!m.has(control)) m.set(control, new Set());
    m.get(control)!.add(rule.id);
  }
  return [...byFw.entries()].map(([framework, m]) => {
    const failedControls = [...m.entries()].filter(([, ids]) => [...ids].some((id) => open.has(id))).map(([control, ids]) => ({ control, ruleIds: [...ids].filter((id) => open.has(id)) }));
    const controls = m.size;
    return { framework, controls, failed: failedControls.length, coverage: Math.round(((controls - failedControls.length) / controls) * 100), failedControls };
  }).sort((a, b) => a.framework.localeCompare(b.framework));
}

/** Deterministic, evidence-only explanation. Used directly, and as the fallback when no AI key is set. */
export function explain(f: Pick<Finding, "ruleId" | "title" | "resourceName" | "resourceType" | "riskScore" | "evidence" | "remediation" | "frameworks">): string {
  const ev = Object.entries(f.evidence).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`).join("; ");
  return [
    `What we found: ${f.title.toLowerCase()} on ${f.resourceType.replace("_", " ")} "${f.resourceName}".`,
    `Evidence in your config: ${ev}.`,
    `Why it matters: this scores ${f.riskScore}/100 based on the rule's base severity and the asset's criticality. It maps to ${f.frameworks.length} compliance control${f.frameworks.length === 1 ? "" : "s"} (${f.frameworks.slice(0, 3).join(", ")}${f.frameworks.length > 3 ? ", ..." : ""}).`,
    `How to fix: ${f.remediation}`,
    `Not checked: this scan sees only the config you provided, not live traffic, data contents or other resources.`,
  ].join("\n\n");
}

/** SAMPLE_CONFIG plus the relationships attack paths need: an internet-facing instance with an admin role and a database that trusts it. */
export const SAMPLE_PATHS_CONFIG = () => ({
  resources: [
    ...SAMPLE_CONFIG.resources.map((r) => (r.name === "orders-db" ? { ...r, security_groups: ["db-sg"] } : r)),
    { type: "ec2_instance", name: "web-1", environment: "production", public_ip: true, security_groups: ["web-sg"], role: "app-role" },
    { type: "iam_role", name: "app-role", policies: ["payments-role"] },
    { type: "security_group", name: "db-sg", environment: "production", ingress: [{ sourceGroup: "web-sg", port: 5432 }] },
  ],
});

export const SAMPLE_CONFIG = {
  resources: [
    { type: "s3_bucket", name: "prod-customer-data", environment: "production", public_read: true, encrypted: false },
    { type: "s3_bucket", name: "marketing-assets", environment: "staging", public_read: false, encrypted: true },
    { type: "security_group", name: "web-sg", environment: "production", ingress: [{ cidr: "0.0.0.0/0", port: 443 }, { cidr: "0.0.0.0/0", port: 22 }] },
    { type: "security_group", name: "internal-sg", environment: "production", ingress: [{ cidr: "10.0.0.0/16", port: 5432 }] },
    { type: "iam_policy", name: "payments-role", environment: "production", statements: [{ effect: "Allow", actions: ["*"], resources: ["*"] }] },
    { type: "iam_policy", name: "reports-reader", environment: "staging", statements: [{ effect: "Allow", actions: ["s3:GetObject"], resources: ["*"] }] },
    { type: "database", name: "orders-db", environment: "production", publicly_accessible: true, encrypted: false },
  ],
};

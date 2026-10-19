import type { Resource } from "@workspace/cspm-engine";
import { LIMITS } from "@workspace/cspm-engine";
import { GetBucketAclCommand, GetBucketEncryptionCommand, GetBucketPolicyStatusCommand, GetBucketTaggingCommand, GetPublicAccessBlockCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { GetPolicyVersionCommand, ListPoliciesCommand } from "@aws-sdk/client-iam";
import { DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import type { CollectResult } from "./types";

/** The only thing the collector needs from an AWS client. Tests pass fakes. */
export interface Sendable { send(command: any): Promise<any> }
export interface AwsClients { s3: Sendable; ec2: Sendable; iam: Sendable; rds: Sendable }

const MAX_BUCKETS = 300, MAX_POLICIES = 300, MAX_INGRESS_PER_GROUP = 200, PARALLEL = 8;
const errName = (e: any): string => String(e?.name ?? e?.Code ?? e?.code ?? "Error");
const denied = (e: any) => /^(AccessDenied|AccessDeniedException|UnauthorizedOperation|UnauthorizedAccess|AuthFailure)$/.test(errName(e)) || e?.$metadata?.httpStatusCode === 403;

/** Run fn over items with a small fixed concurrency. */
async function pool<T, R>(items: T[], fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(PARALLEL, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]!); } }));
  return out;
}

type Tag = { Key?: string; Value?: string };
/** Tag "environment" (or env) with a recognisable value sets the environment, which weights the risk score. */
export function environmentFromTags(tags?: Tag[]): Resource["environment"] | undefined {
  const t = (tags ?? []).find((x) => /^(environment|env)$/i.test(x.Key ?? ""));
  const v = (t?.Value ?? "").toLowerCase();
  if (/^(prod|production|prd|live)$/.test(v)) return "production";
  if (/^(stage|staging|stg|test|qa|uat)$/.test(v)) return "staging";
  if (/^(dev|development|sandbox)$/.test(v)) return "development";
  return undefined;
}

// ---- S3 ----------------------------------------------------------------------------------------------------------

export function mapBucket(name: string, p: { policyPublic: boolean; aclPublic: boolean; pab: { IgnorePublicAcls?: boolean; RestrictPublicBuckets?: boolean }; encrypted: boolean; tags?: Tag[] }): Resource {
  // A public policy only counts if RestrictPublicBuckets is off, a public ACL only if IgnorePublicAcls is off.
  const publicRead = (p.policyPublic && !p.pab.RestrictPublicBuckets) || (p.aclPublic && !p.pab.IgnorePublicAcls);
  const r: Resource = { type: "s3_bucket", name, public_read: publicRead, encrypted: p.encrypted };
  const env = environmentFromTags(p.tags); if (env) r.environment = env;
  return r;
}

const isPublicGrant = (g: any) => /\/global\/(AllUsers|AuthenticatedUsers)$/.test(g?.Grantee?.URI ?? "") && /^(READ|FULL_CONTROL)$/.test(g?.Permission ?? "");

async function collectS3(c: AwsClients, notes: string[], room: () => number): Promise<{ resources: Resource[]; ok: boolean }> {
  let ok = true;
  const names: string[] = [];
  let token: string | undefined;
  do {
    const r = await c.s3.send(new ListBucketsCommand(token ? { ContinuationToken: token } : {}));
    for (const b of r.Buckets ?? []) if (b.Name) names.push(b.Name);
    token = r.ContinuationToken;
  } while (token && names.length < MAX_BUCKETS);
  let list = names;
  if (list.length > Math.min(MAX_BUCKETS, room())) { list = list.slice(0, Math.min(MAX_BUCKETS, room())); notes.push(`S3: only the first ${list.length} of ${names.length} buckets were checked.`); ok = false; }
  let failed = 0, deniedCount = 0;
  const resources = (await pool(list, async (Bucket) => {
    // each probe answers "not configured" with a specific error: that is a normal answer, not a failure
    const probe = async <T>(cmd: any, notFound: string[], dflt: T): Promise<T> => { try { return await c.s3.send(cmd); } catch (e) { if (notFound.includes(errName(e))) return dflt; throw e; } };
    try {
      const pab = (await probe(new GetPublicAccessBlockCommand({ Bucket }), ["NoSuchPublicAccessBlockConfiguration"], {} as any)).PublicAccessBlockConfiguration ?? {};
      const ps = await probe(new GetBucketPolicyStatusCommand({ Bucket }), ["NoSuchBucketPolicy"], {} as any);
      const acl = await probe(new GetBucketAclCommand({ Bucket }), [], { Grants: [] } as any);
      const enc = await probe(new GetBucketEncryptionCommand({ Bucket }), ["ServerSideEncryptionConfigurationNotFoundError"], null as any);
      const tags = (await probe(new GetBucketTaggingCommand({ Bucket }), ["NoSuchTagSet"], {} as any)).TagSet as Tag[] | undefined;
      return mapBucket(Bucket, { policyPublic: !!ps.PolicyStatus?.IsPublic, aclPublic: (acl.Grants ?? []).some(isPublicGrant), pab, encrypted: !!enc?.ServerSideEncryptionConfiguration, tags });
    } catch (e) { if (denied(e)) deniedCount++; else failed++; return null; }
  })).filter((x): x is Resource => !!x);
  if (deniedCount) { notes.push(`S3: access denied on ${deniedCount} bucket${deniedCount === 1 ? "" : "s"}. Check the role's S3 permissions or bucket policies.`); ok = false; }
  if (failed) { notes.push(`S3: ${failed} bucket${failed === 1 ? "" : "s"} could not be read.`); ok = false; }
  return { resources, ok };
}

// ---- EC2 security groups -----------------------------------------------------------------------------------------

export function mapSecurityGroup(g: any): Resource {
  const ingress: { cidr: string; port?: number | "all"; fromPort?: number; toPort?: number }[] = [];
  for (const p of g.IpPermissions ?? []) {
    const cidrs: string[] = [...(p.IpRanges ?? []).map((x: any) => x.CidrIp), ...(p.Ipv6Ranges ?? []).map((x: any) => x.CidrIpv6)].filter(Boolean);
    for (const cidr of cidrs) {
      if (p.IpProtocol === "-1") ingress.push({ cidr, port: "all" });
      else if ((p.IpProtocol === "tcp" || p.IpProtocol === "udp") && typeof p.FromPort === "number" && typeof p.ToPort === "number") ingress.push(p.FromPort === p.ToPort ? { cidr, port: p.FromPort } : { cidr, fromPort: p.FromPort, toPort: p.ToPort });
      // icmp and other protocols have no ports: not port exposure
    }
  }
  const r: Resource = { type: "security_group", name: `${g.GroupName} (${g.GroupId})`, ingress: ingress.slice(0, MAX_INGRESS_PER_GROUP) };
  const env = environmentFromTags(g.Tags); if (env) r.environment = env;
  return r;
}

async function collectEc2(c: AwsClients, room: () => number): Promise<Resource[]> {
  const out: Resource[] = [];
  let token: string | undefined;
  do {
    const r = await c.ec2.send(new DescribeSecurityGroupsCommand(token ? { NextToken: token } : {}));
    for (const g of r.SecurityGroups ?? []) if (out.length < room()) out.push(mapSecurityGroup(g));
    token = r.NextToken;
  } while (token && out.length < room());
  return out;
}

// ---- IAM policies ------------------------------------------------------------------------------------------------

const asList = (v: unknown): string[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]).filter((x): x is string => typeof x === "string");

/** Returns the resource and how many statements could not be evaluated (NotAction / NotResource). */
export function mapPolicy(accountId: string, name: string, document: unknown): { resource: Resource; skipped: number } {
  const doc = typeof document === "string" ? JSON.parse(decodeURIComponent(document)) : (document as any);
  const raw = Array.isArray(doc?.Statement) ? doc.Statement : doc?.Statement ? [doc.Statement] : [];
  let skipped = 0;
  const statements: { effect: string; actions: string[]; resources: string[] }[] = [];
  for (const s of raw) {
    if (s.NotAction !== undefined || s.NotResource !== undefined) { skipped++; continue; }
    statements.push({ effect: s.Effect === "Deny" ? "Deny" : "Allow", actions: asList(s.Action), resources: asList(s.Resource) });
  }
  return { resource: { type: "iam_policy", name: `${accountId}:${name}`, statements }, skipped };
}

async function collectIam(c: AwsClients, accountId: string, notes: string[], room: () => number): Promise<{ resources: Resource[]; ok: boolean }> {
  let ok = true;
  const policies: { PolicyName?: string; Arn?: string; DefaultVersionId?: string }[] = [];
  let marker: string | undefined;
  do {
    const r = await c.iam.send(new ListPoliciesCommand({ Scope: "Local", OnlyAttached: true, ...(marker ? { Marker: marker } : {}) }));
    policies.push(...(r.Policies ?? []));
    marker = r.IsTruncated ? r.Marker : undefined;
  } while (marker && policies.length < MAX_POLICIES);
  let list = policies;
  const cap = Math.min(MAX_POLICIES, room());
  if (list.length > cap) { notes.push(`IAM: only the first ${cap} of ${policies.length} attached customer-managed policies were checked.`); list = list.slice(0, cap); ok = false; }
  let skipped = 0, failed = 0;
  const resources = (await pool(list, async (p) => {
    try {
      const v = await c.iam.send(new GetPolicyVersionCommand({ PolicyArn: p.Arn, VersionId: p.DefaultVersionId }));
      const m = mapPolicy(accountId, p.PolicyName ?? "unnamed", v.PolicyVersion?.Document);
      skipped += m.skipped;
      return m.resource;
    } catch { failed++; return null; }
  })).filter((x): x is Resource => !!x);
  if (skipped) { notes.push(`IAM: ${skipped} statement${skipped === 1 ? " uses" : "s use"} NotAction or NotResource and ${skipped === 1 ? "was" : "were"} not evaluated.`); ok = false; }
  if (failed) { notes.push(`IAM: ${failed} polic${failed === 1 ? "y" : "ies"} could not be read.`); ok = false; }
  notes.push("IAM: only customer-managed policies attached to something are checked; AWS-managed policies (such as AdministratorAccess) and inline policies are not.");
  return { resources, ok };
}

// ---- RDS ---------------------------------------------------------------------------------------------------------

export function mapDbInstance(accountId: string, region: string, d: any): Resource {
  const r: Resource = { type: "database", name: `${accountId}/${region}/${d.DBInstanceIdentifier}`, publicly_accessible: !!d.PubliclyAccessible, encrypted: !!d.StorageEncrypted };
  const env = environmentFromTags(d.TagList); if (env) r.environment = env;
  return r;
}

async function collectRds(c: AwsClients, accountId: string, region: string, room: () => number): Promise<Resource[]> {
  const out: Resource[] = [];
  let marker: string | undefined;
  do {
    const r = await c.rds.send(new DescribeDBInstancesCommand(marker ? { Marker: marker } : {}));
    for (const d of r.DBInstances ?? []) if (out.length < room()) out.push(mapDbInstance(accountId, region, d));
    marker = r.Marker;
  } while (marker && out.length < room());
  return out;
}

// ---- all together ------------------------------------------------------------------------------------------------

/**
 * Reads the four supported services with the given clients and returns engine resources.
 * One failing service does not stop the others: it becomes a note and marks the result incomplete.
 */
export async function collectWithClients(c: AwsClients, ctx: { accountId: string; region: string }): Promise<CollectResult> {
  const resources: Resource[] = [];
  const notes: string[] = [];
  let complete = true;
  const room = () => Math.max(0, LIMITS.maxResources - resources.length);
  const step = async (label: string, fn: () => Promise<{ resources: Resource[]; ok?: boolean }>) => {
    if (room() === 0) { notes.push(`${label}: skipped, the ${LIMITS.maxResources}-resource limit per scan was reached.`); complete = false; return; }
    try {
      const r = await fn();
      if (r.resources.length > room()) complete = false; // more than fits: the rest is dropped below
      resources.push(...r.resources.slice(0, room()));
      if (r.ok === false) complete = false;
    } catch (e) {
      complete = false;
      notes.push(denied(e) ? `${label}: access denied. The role is missing permissions for this service (see the setup template).` : `${label}: could not be read (${errName(e)}).`);
    }
  };
  await step("S3", () => collectS3(c, notes, room));
  await step("EC2 security groups", async () => ({ resources: await collectEc2(c, room) }));
  await step("IAM", () => collectIam(c, ctx.accountId, notes, room));
  await step("RDS", async () => ({ resources: await collectRds(c, ctx.accountId, ctx.region, room) }));
  if (resources.length >= LIMITS.maxResources) { notes.push(`Stopped at ${LIMITS.maxResources} resources per scan; some resources were not checked.`); complete = false; }
  return { resources, notes, complete };
}

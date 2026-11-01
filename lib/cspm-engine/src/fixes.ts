import type { Finding } from "./index";

/**
 * Remediation as code, per rule: a Terraform snippet and, where one command does it, an AWS CLI command. They are
 * starting points written from the rule and the finding's evidence, to be adapted and reviewed, never applied blindly.
 * The resource name comes from the user's own configuration, so it is only ever used as a sanitised identifier or inside
 * an escaped string.
 */
export interface FixSnippet { terraform: string; awsCli?: string; notes: string[] }

/** A Terraform identifier: lowercase letters, digits and underscores, starting with a letter. */
export const tfIdent = (name: string): string => {
  const s = name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60);
  return /^[a-z]/.test(s) ? s : `r_${s || "resource"}`;
};
/** Inside a double-quoted HCL or shell string: no way to close it, interpolate, or start a new line. */
const q = (v: string): string => v.replace(/[^\w .:/@+=-]/g, "").slice(0, 200);
/** The bucket / group / database name as AWS knows it, when the display name is "name (id)". */
const awsName = (display: string): string => { const m = /\(([^)]+)\)\s*$/.exec(display); return q(m ? m[1]! : display); };

type Maker = (f: Pick<Finding, "resourceName" | "evidence">) => FixSnippet;

const MAKERS: Record<string, Maker> = {
  "s3-public-read": (f) => {
    const id = tfIdent(f.resourceName), b = awsName(f.resourceName);
    return {
      terraform: `resource "aws_s3_bucket_public_access_block" "${id}" {\n  bucket                  = aws_s3_bucket.${id}.id   # adjust to your bucket resource\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`,
      awsCli: `aws s3api put-public-access-block --bucket "${b}" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
      notes: ["Serve public content through CloudFront with origin access control instead of a public bucket.", "Remove any public ACL or bucket policy statement that grants access to everyone."],
    };
  },
  "s3-no-encryption": (f) => {
    const id = tfIdent(f.resourceName), b = awsName(f.resourceName);
    return {
      terraform: `resource "aws_s3_bucket_server_side_encryption_configuration" "${id}" {\n  bucket = aws_s3_bucket.${id}.id   # adjust to your bucket resource\n\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm     = "aws:kms"\n      kms_master_key_id = aws_kms_key.${id}.arn   # your KMS key\n    }\n    bucket_key_enabled = true\n  }\n}`,
      awsCli: `aws s3api put-bucket-encryption --bucket "${b}" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'`,
      notes: ["New objects are encrypted from now on; existing objects stay as they were until they are copied over themselves."],
    };
  },
  "sg-sensitive-port-open": (f) => {
    const id = tfIdent(f.resourceName), ports = Array.isArray(f.evidence["ports"]) ? (f.evidence["ports"] as unknown[]).map((p) => Number(String(p).split(" ")[0])).filter((p) => Number.isInteger(p)) : [];
    const rules = (ports.length ? ports : [22]).map((p) => `  ingress {\n    from_port   = ${p}\n    to_port     = ${p}\n    protocol    = "tcp"\n    cidr_blocks = var.admin_cidrs   # your office or VPN ranges, never 0.0.0.0/0\n  }`).join("\n");
    return { terraform: `# in aws_security_group.${id}: replace the open rule(s) with\n${rules}\n\nvariable "admin_cidrs" {\n  type = list(string)\n}`, notes: ["Better still: remove the rule and use AWS Systems Manager Session Manager or a bastion host."] };
  },
  "sg-open-world": (f) => {
    const id = tfIdent(f.resourceName);
    return { terraform: `# in aws_security_group.${id}: narrow each 0.0.0.0/0 rule to the ranges and ports that need it\n  ingress {\n    from_port   = 443   # the one port this service needs\n    to_port     = 443\n    protocol    = "tcp"\n    cidr_blocks = var.allowed_cidrs\n  }\n\nvariable "allowed_cidrs" {\n  type = list(string)\n}`, notes: ["Rules that allow all ports or all protocols should become one rule per port."] };
  },
  "iam-admin-access": (f) => {
    const id = tfIdent(f.resourceName);
    return { terraform: `# replace the "Action": "*" / "Resource": "*" statement in aws_iam_policy.${id} with what the role does\ndata "aws_iam_policy_document" "${id}" {\n  statement {\n    effect    = "Allow"\n    actions   = ["s3:GetObject", "s3:PutObject"]   # the exact actions needed\n    resources = ["\${aws_s3_bucket.example.arn}/*"]   # the exact resources\n  }\n}`, notes: ["Find what the role really uses with IAM Access Analyzer's policy generation, then write that down.", "Add a permissions boundary so a future mistake cannot grant administrator access."] };
  },
  "iam-wildcard-action": (f) => {
    const id = tfIdent(f.resourceName);
    return { terraform: `# in aws_iam_policy.${id}: list the exact actions instead of "*" or "service:*"\n  actions = ["s3:GetObject", "s3:ListBucket"]`, notes: ["IAM Access Analyzer can generate a policy from the access the role actually used."] };
  },
  "iam-wildcard-resource": (f) => {
    const id = tfIdent(f.resourceName);
    return { terraform: `# in aws_iam_policy.${id}: scope the statement to the resources it needs\n  resources = [\n    aws_s3_bucket.example.arn,\n    "\${aws_s3_bucket.example.arn}/*",\n  ]`, notes: ["Some actions only support \"*\" as a resource; check the service's IAM reference before narrowing."] };
  },
  "db-public": (f) => {
    const id = tfIdent(f.resourceName), d = awsName(f.resourceName);
    return {
      terraform: `resource "aws_db_instance" "${id}" {\n  # ...existing settings...\n  publicly_accessible = false\n  db_subnet_group_name = aws_db_subnet_group.private.name   # private subnets only\n}`,
      awsCli: `aws rds modify-db-instance --db-instance-identifier "${d}" --no-publicly-accessible --apply-immediately`,
      notes: ["Connections from outside the VPC stop working: reach the database through a bastion, VPN or private endpoint first."],
    };
  },
  "db-no-encryption": (f) => {
    const id = tfIdent(f.resourceName);
    return {
      terraform: `resource "aws_db_instance" "${id}" {\n  # ...existing settings...\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.${id}.arn\n}`,
      notes: ["Changing this on an existing instance replaces it. Take a snapshot, copy the snapshot with encryption on, and restore from the copy; plan the cutover."],
    };
  },
};

/** The fix as code for a finding, or null for a rule without one. */
export function fixFor(ruleId: string, f: Pick<Finding, "resourceName" | "evidence">): FixSnippet | null {
  return MAKERS[ruleId]?.(f) ?? null;
}
export const RULES_WITH_FIXES = Object.keys(MAKERS);

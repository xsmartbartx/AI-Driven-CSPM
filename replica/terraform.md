# Checking a Terraform plan before you apply it

NEXORA reads the **plan**, never your cloud account, and applies the same rules it runs on scans. Nothing is stored and no scan is used from your quota.

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
CSPM_API_KEY=cspm_... node deploy/tf-check.mjs plan.json            # fails on high or critical
CSPM_API_KEY=cspm_... node deploy/tf-check.mjs plan.json --fail-on medium --api https://api.cspm.onenexora.com
```

Exit code **0** passed, **1** findings at or above `--fail-on` (default `high`), **2** the check could not run (bad key, unreachable, unreadable plan). A **read-only** API key (Settings → API keys → Read only) is enough. The script has no dependencies (Node 18+) and sends only the resource types the rules read.

GitHub Actions:

```yaml
- run: terraform plan -out=tfplan && terraform show -json tfplan > plan.json
- run: node deploy/tf-check.mjs plan.json
  env: { CSPM_API_KEY: "${{ secrets.CSPM_API_KEY }}" }
```

## What it checks
| Terraform | rules applied |
| --- | --- |
| `aws_s3_bucket` (+ `aws_s3_bucket_acl`, `aws_s3_bucket_public_access_block`) | public read through an ACL, unless a public access block cancels it |
| `aws_security_group` (+ `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`) | sensitive ports and all traffic open to the internet |
| `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy`, inline policies on `aws_iam_role` | administrator access, wildcard actions, wildcard resources |
| `aws_db_instance`, `aws_rds_cluster` | publicly accessible, storage not encrypted |

- Resources that will be **deleted** are ignored; everything else is read as it will be after apply.
- Values Terraform only knows after apply (for example a policy built from another resource's output) cannot be checked; the output says how many.
- S3 buckets are encrypted by default in AWS, so a missing encryption block is **not** reported.
- Attack paths are not computed from plans.
- Rule suppressions that apply everywhere, or to an environment (read from the resource's `Environment` tag), are honoured; suppressions for one asset are not, because plan addresses are not account assets.
- API: `POST /api/terraform/check` with `{ "plan": <json>, "failOn": "high" }` (viewer role or a read-only key); request bodies up to 8 MB, 60 checks an hour per organization.

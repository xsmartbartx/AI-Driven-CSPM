# AWS connector: setup, security model, limits

Built and tested with a fake AWS and a mock STS server (real SDK request path), **never run against a real AWS account**. Treat the first real run as a test (steps at the end). The connector is **off by default**: it is enabled by setting `CSPM_AWS_ACCOUNT_ID`.

## How it works
1. An org admin opens **Cloud accounts → Connect AWS account** and enters the 12-digit account id and a region.
2. NEXORA creates a connection with a **per-connection External ID** and shows a CloudFormation template. The customer deploys it in their account. It creates one role that trusts **only NEXORA's AWS account and that External ID**, and allows only List/Get/Describe on S3, EC2 security groups, IAM policies and RDS (see the permission list in `services/aws/setup.ts`; tests fail if anything else, a wildcard or a write verb appears).
3. **Verify connection** makes NEXORA call `sts:AssumeRole` (15-minute session) and checks the role really belongs to the entered account.
4. **Scan now** assumes the role, reads the resources, runs them through the same rules as a pasted scan and stores assets and findings. It counts as one scan on the plan. Credentials are never stored.

## Operator setup (NEXORA's side)
1. Use a dedicated AWS account for NEXORA ("principal account"). Put its 12-digit id in `CSPM_AWS_ACCOUNT_ID` on the API.
2. The API process needs AWS credentials that may call `sts:AssumeRole`, from the standard AWS credential chain. Best: run the API on AWS with an **instance/task role**. Otherwise an IAM user's access key in the host's secret store, or IAM Roles Anywhere / OIDC federation. Attach only this policy to that identity:
   ```json
   { "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/*" } ] }
   ```
   It is broad on purpose (customers choose their role names) but harmless on its own: a customer role must explicitly trust your account **and** present the right External ID.
3. Nothing else. No S3, no database, no write access to anything in your own account.
4. Confirm: the Cloud accounts page now shows "Connect AWS account". If the server has no usable credentials, Verify answers "NEXORA's own AWS credentials are not working on the server" (tested through the production bundle).

## What it reads
| service | read | notes |
| --- | --- | --- |
| S3 | bucket list; public access block, policy status, ACL, encryption, tags per bucket | up to 300 buckets; bucket contents are never read |
| EC2 | security groups in the chosen region (rules and tags) | |
| IAM | **customer-managed** policies that are attached to something | AWS-managed policies (e.g. AdministratorAccess) and inline policies are **not** checked; `NotAction`/`NotResource` statements are skipped and reported |
| RDS | DB instances in the chosen region | |
Environment: a tag `environment` (or `env`) with prod/staging/dev values sets the asset's environment, which weights the risk score. One connection per account **and region**; S3 and IAM are global but are read on each connection, so use one connection per account unless you need other regions.

## Attack paths (relationship data)
The role template now also allows `ec2:DescribeInstances`, `iam:ListInstanceProfiles`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies` and `iam:GetRolePolicy` (all read-only; still no data, secrets or logs). They read which servers exist, which role each runs as, and what that role is allowed to do, and only for roles servers actually use. **Customers who deployed the earlier template must redeploy it to get attack paths.** Without the new permissions nothing breaks: the scan stays complete for everything it checks, says "EC2 instances: access denied ... Redeploy the setup template" in its notes, and the Attack paths page explains what is missing. See `replica/attack-paths.md`.

## Safety rules enforced in code (and tested)
- External ID per connection, random, never reused; the setup template and the permission list come from one source.
- The role's account must match the account entered; the role ARN is built from the account id and a validated role name (no free-form ARNs).
- Raw AWS error text (which can contain ARNs and account ids) is never shown or stored; users see a short mapped sentence.
- A partial scan (a denied service, a failing call, the 500-resource cap) is **incomplete**: it reports what was missed and **never** marks findings on unseen resources as fixed. A complete scan marks findings on resources that disappeared as fixed.
- Per-org limits: 10 connections, 30 verifications and 12 scans per hour; one scan per connection at a time (per process); plan quota checked **before** reading AWS.
- Viewers see connections but not the External ID, nor any action buttons; analysts can scan; admins connect, verify and disconnect. Everything is audited without ARNs or External IDs.
- Row level security applies (tenant role), and the AWS calls run with no database connection held.

## Scheduled rescans
An admin can switch a verified connection to **Daily** or **Weekly** on the Cloud accounts page. The API process checks every minute (`SCHEDULER_TICK_SECONDS`, default 60; `SCHEDULER=0` turns it off on an instance) and scans the accounts that are due, three at a time, one after another.
- **Same pipeline as a manual scan** (one shared service): same rules, same complete/incomplete handling, same quota. A scheduled scan counts against the plan's monthly scans, so **Daily needs a plan with at least 31 scans** (Free has 10: it will run until the allowance is used, then pause and say so; it resumes when the month resets). Scheduled scans have no user: they appear in scan history as account scans with no author, and in the audit log as `cloud.scan.scheduled`.
- **Several instances are safe**: due accounts are claimed with `FOR UPDATE SKIP LOCKED`, and every scan takes a per-account lease in the database (`scan_started_at`, abandoned after 20 minutes if a process dies), so an account is never scanned twice at once, by the scheduler or by a person.
- **Start times**: turning a schedule on starts the first scan within 1–10 minutes, or one full interval after the last scan if there was one; every run adds up to 10 minutes of random jitter so accounts do not all fire together.
- **Failures**: a scan that fails for a reason that may fix itself (NEXORA's own AWS credentials, network, throttling, an empty account) is retried after 1 h, 2 h, 4 h, 8 h, ... (never longer than the interval); a success resets the count. After **5 failures in a row** the schedule switches off, the owners and admins get one email, and the audit log records `cloud.schedule_disabled`. If the customer's role stops working (assume-role denied, wrong account) the schedule stops **at once**, the connection is marked "Needs attention" and the admins are emailed. Quota exhaustion and "a scan is already running" are not failures: they retry in 6 hours and 15 minutes.
- Everything a scheduled scan does runs under the organization's row level security.
- **Not built:** per-connection times of day, notifications about new findings (only the stop emails exist), a schedule per region group, and a scan history filter for scheduled vs manual.

## Not built
Other regions in one connection, Azure/GCP/Kubernetes, inline and AWS-managed IAM policies, trust-policy checks for roles, S3 object-level checks, resource-count pagination beyond 500, and a webhook for EventBridge changes.

## First real run (you, with a sandbox AWS account, about 30 minutes)
1. Operator setup above; set `CSPM_AWS_ACCOUNT_ID`; restart the API.
2. In a **separate sandbox AWS account**, create: one public-read bucket (or a public ACL), one security group open to `0.0.0.0/0` on port 22, one customer-managed policy with `Action: *` / `Resource: *` attached to a test role, one public RDS instance if you want (costs money; skip it otherwise).
3. Connect that account, deploy the template, Verify, Scan. Expect: S3 public-read, SG sensitive-port, IAM admin access findings; Notes listing the IAM scope limits.
4. Negative checks: change the role's ExternalId condition → Verify must fail with the trust-policy message; remove `ec2:DescribeSecurityGroups` from the role → the scan must report "EC2 security groups: access denied", finish as incomplete and **not** close any findings; delete the bucket and rescan completely → its finding becomes fixed.
5. Scheduled scans: set the connection to Daily, then in the database set `next_run_at = now()` for it (or wait) and watch `docker compose logs api` for "scheduled scan finished"; check scan history shows an account scan with no author. Break the role (change the External ID condition) and confirm the schedule stops with the admin email.
6. Delete the stack in the sandbox account and press Disconnect.
Report anything that differs; the most likely surprises are AWS API shapes for S3 region redirects and the number of API calls on accounts with hundreds of buckets.

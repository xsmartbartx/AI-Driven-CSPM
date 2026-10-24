# Attack paths

A list of the ways an attacker could get from the **internet** to **full control of your AWS account** or to **your data**, one step at a time, so ten alerts that belong together show up as one fix. It is built from the configuration NEXORA scanned. It is a map of what the configuration *allows*, not a prediction and not a penetration test.

## What counts as a path
```
Internet -> server (public IP + a security group open to the whole internet)
         -> role the server runs as
         -> AWS account   (the role can do everything, or all of IAM, on everything)
         -> bucket        (the role can read that bucket's objects)
Internet -> server -> database   (the database's security group accepts connections from the server's group)
```
Every hop must be **explicit in the data**. Nothing is guessed: an unknown security group, a role that was not described, a policy that was not part of the scan, or a managed policy whose contents are not known produces **no path** and a note saying so.

| hop | needs |
| --- | --- |
| internet -> server | `public_ip: true` **and** a security group on the server with an ingress rule for `0.0.0.0/0` or `::/0` |
| server -> role | the server's `role`, and that role described in the scan |
| role -> account | an allowing statement of `*` on `*`, or `iam:*` on `*` (a role that can change IAM can grant itself anything) |
| role -> bucket | an allowing statement covering `s3:GetObject` (or `s3:*`, `*`) on the bucket's ARN or `*`, unless the role already has full control (then one path to the account, not one per bucket) |
| server -> database | the database's security group has a rule whose `sourceGroup` is one of the server's groups |
Deny statements are ignored when reading permissions. `NotAction` and `NotResource` statements are not evaluated (the AWS collector skips and reports them).

AWS-managed policies the engine knows: AdministratorAccess (everything), PowerUserAccess (reads all data, not the account), AmazonS3FullAccess, AmazonS3ReadOnlyAccess, IAMFullAccess. Any other managed policy on a role is listed as "not evaluated".

## Score (0 to 100) and ranking
`entry x pivot x target`, then the same bands as findings (76+ critical, 51-75 high, 21-50 medium).
- **entry**: 1.0 if the open rule covers a sensitive port (SSH, RDP, database ports) or all ports; 0.8 for other ports; 0.6 if only 80/443 are open (a web server is normal, it is just the first step).
- **pivot / target**: the account = 1.0; a database = 0.85 x (0.5 + 0.5 x criticality/10); a bucket = 0.75 x (0.5 + 0.5 x criticality/10). Criticality comes from the asset (tag or default by environment: production 8, staging 5, development 3).
It is a heuristic for ordering, not a probability. The page shows the plain-language reason for every hop.

## Fix first
Each hop names the change that closes it (remove the internet-wide rule from a group, narrow a role, stop a database group accepting another group, run a server without the role). The same change on several paths is a **choke point**; the page lists those first with how many paths each breaks.

## Where the data comes from
- **Connected AWS account**: the collector reads servers, instance profiles, the roles servers run as (attached customer-managed and AWS-managed policies, inline policies) and security-group-to-group rules. Needs the updated role template (`replica/aws-setup.md`). Only what the **latest scan** found counts: an instance that vanished or could not be read drops out of the paths immediately (`assets.last_scan_id`).
- **Pasted configuration**: add `ec2_instance`, `iam_role` entries (and `security_groups` on databases, `sourceGroup` on rules). "Load sample with attack paths" on the New scan page shows the format. Pasted assets count for 30 days.
Computed when the page is opened (nothing stored, so nothing stale), from at most 2,000 assets, showing the 50 highest-risk paths.

## What it cannot see (also shown on the page)
Subnets and route tables (a public IP in a private subnet may not be reachable), network ACLs, VPC peering, service control policies, permission boundaries, resource policies other than the bucket name, firewalls on the instance, application-level vulnerabilities (it does not know the server is exploitable, only that it is reachable), and anything in an account that is not connected. Reachability is therefore an upper bound: a listed path may be blocked by something not modelled, and a missing path does not prove safety.

## Not built
Lateral movement between servers, roles assuming other roles (`sts:AssumeRole` chains), Lambda and container workloads, Kubernetes, storing path history and alerting when a new path appears, and exporting paths.

## Tested
23 engine tests (each hop's positive and negative cases, scoring bands, managed policies, security group name/id/"name (sg-id)" matching, choke points, determinism, 50-path cap, duplicate-edge regression), 5 collector tests with fake AWS clients (instances, profiles, roles, group rules, optional-data behaviour, a full chain through the engine), 5 API tests (including "only the latest scan counts", organization isolation and viewer access), 4 browser tests with accessibility scans, one on a phone. Never run against a real AWS account.

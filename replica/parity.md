## Parity: 68.5 / 100

features 68.5  (13 counted, must-haves 5 of 6 done)

Not shippable yet: 1 must-have features are not done.

## By area, weakest first
- integrations                   0.0  (1 features)
- skip                           0.0  (5 features)
- billing                       75.0  (2 features)
- scan                         100.0  (1 features)
- findings                     100.0  (2 features)
- site                         100.0  (1 features)
- api                          100.0  (1 features)

## Missing, in build order
- [must] billing: Usage and plan page + Stripe upgrade, partial  (checkout+webhook coded and unit-tested; not run against real Stripe (needs keys))
- [should] integrations: AWS read-only account connection (role + external ID), partial  (built; never run on real AWS; replica/aws-setup.md)
- [could] skip: Agentless disk snapshot scanning, no  (out of scale)
- [could] skip: Licensed compliance benchmark text, no  (map IDs only)
- [could] skip: Microsoft Secure Score algorithm, no  (proprietary; own score instead)
- [could] skip: Microsoft/Apple logos icons fonts, no  (use own tokens)
- [could] skip: Threat-intelligence feeds, no  (licensed data)

## Yours, not in the original (not scored)
- Finding status (open fixed accepted false positive)
- Overview dashboard (score KPIs trend top actions)
- Risk score 0-100 per finding
- Scan history and new/fixed diff
- SSO redirect from Nexora console
- Multi-tenant orgs with RLS isolation (RLS enabled by migration 0003)
- RBAC owner admin analyst viewer
- Audit log
- Locked CORS + rate limit + security headers
- Onboarding with sample config
- Risk trend snapshots 30d/3m/6m
- Asset inventory
- Compliance frameworks (CIS NIST ISO PCI GDPR) mapped by control ID
- AI explanation per finding
- AI daily security brief
- AI Q&A over own findings
- Azure and GCP connectors
- Kubernetes checks
- Attack path analysis
- Executive PDF/CSV reports
- Notifications (email Slack)
- Terraform fix generation and PR
- Internal admin portal
- Light and dark theme
- Nexora SOC2/ISO certification

## Fix in the matrix
- line 34: priority 'skip' is not must/should/could, counted as could
- line 35: priority 'skip' is not must/should/could, counted as could
- line 36: priority 'skip' is not must/should/could, counted as could
- line 37: priority 'skip' is not must/should/could, counted as could
- line 38: priority 'skip' is not must/should/could, counted as could

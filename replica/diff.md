# Diff report (2026-10-14)

**No screenshot diff.** There is no original to compare layouts against: this is Nexora's own product with Defender for Cloud used only for UX patterns. Layout parity with Microsoft would be the wrong goal (trade dress). `imgdiff.py` is not used.

## Scores
- **Plan coverage 78/100** over the 34 feature rows (must 3, should 2, could 1; partial counts half; 6 `skip` rows excluded). The skill's own `parity.py` prints 84, but it only counts rows where the original has the feature, which is 8 of them, so it is not meaningful here.
- **Must-haves: 10 done, 3 partial, 0 missing.** Verdict under the skill's rule: **not shippable yet**, because three must-haves are partial and every one is blocked on something outside the code:
  1. Stripe upgrade: coded and tested with signed fake events, needs your Stripe test keys to run for real.
  2. SSO from Nexora: endpoint built and tested, needs onenexora.com to sign tokens with `SSO_SECRET` and link here.
  3. Postgres RLS: **unfinished implementation work in this repo**, not an external blocker. Isolation is enforced and tested at query level only; RLS needs policies in `schema.sql` plus a per-request tenant setting in a transaction, neither written yet.
- **Should-haves: 10 of 12.** Missing: AWS account connection (Phase 1b), email (needs provider).
- **Could-haves: 1 of 9.** Not built: AI brief, AI Q&A, Azure/GCP, Kubernetes, attack paths, notifications, Terraform fixes, admin portal; reports = CSV only.
- Tests: 9 engine + 27 API + 33 e2e (Chrome, axe AA on ~20 screens) all green. Open bugs: none S1; O1 (no email) is S2.

## Behaviour vs today's Beta (cspm.onenexora.com, from its public page)
| flow | Beta does | new product does | keep? |
| --- | --- | --- | --- |
| scan | paste JSON, get findings, usage logged in console | same, plus stored history, diff (new/fixed), trend, status workflow | keep |
| quota | Free 10/mo, Starter 75/mo | identical, enforced atomically (concurrent test) | keep |
| clicks to first finding | not measured | signup -> sample -> run: 2 clicks after signup (tested) | beat target met |
| rules | 4 areas: buckets, SGs, IAM, DBs | same 4 areas, 9 rules, 80/443 not flagged | verify rule parity with the Beta's source (not in this repo) |

## Top five to build next
1. Email provider: verification, reset, invite mail (you create the account).
2. Stripe test-mode end-to-end run and the real Starter price.
3. Nexora token issuer on onenexora.com + redirect from console (the SSO handoff).
4. AWS read-only connector (cross-account role + external ID).
5. Enable Postgres RLS and run the isolation tests against it.

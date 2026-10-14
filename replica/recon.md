# Recon map: NEXORA CSPM standalone product + customer console

Date: 2026-10-13. Scope decided with the user's brief: CSPM becomes its **own product site with its own client dashboard**, not a module of the onenexora.com marketing site. Nexora redirects signed-in clients into it. Design inspiration (patterns only, no assets): Microsoft Defender for Cloud / Azure portal, Apple.

## 0. Scope (proposed, change if wrong)

| question | answer |
| --- | --- |
| Which app | Not a third-party clone. Own product (this repo) + reference patterns from Defender for Cloud |
| Platform | Web (desktop first, responsive) |
| Slice (core loop) | Connect/describe cloud config -> scan -> prioritized findings -> AI explanation + fix -> track posture over time |
| Who | Nexora's own SaaS customers: CISO, security team, DevSecOps. Sold as Free / Starter / higher |
| Terms | Only public docs + user's own repos/sites used. No third-party accounts logged into |

## 1. Sources

| source | URL | gives |
| --- | --- | --- |
| Own repo README | github.com/xsmartbartx/AI-Driven-CSPM | target vision: assets, rules, compliance, risk formula, AI, attack paths, API list |
| Own repo code | this folder | actual state: Express+pino health only, OpenAPI health only, Drizzle lib empty, mockup-sandbox (shadcn/ui kit) |
| Nexora home | onenexora.com | positioning "Build. Secure. Operate.", 5 Beta products, shared core (identity, orgs, API, billing, telemetry), console.onenexora.com |
| Nexora CSPM page | onenexora.com/products/cspm | live Beta: paste JSON config -> findings. Free $0 / 10 scans/mo, Starter from $19 / 75 scans/mo. Live account connect "on the roadmap" |
| CSPM landing | cspm.onenexora.com | 3 steps Describe/Scan/Fix; app at /app; checks: S3 public+encryption, SG 0.0.0.0/0 + sensitive ports, IAM wildcards, DB public+encryption; usage in Console -> Usage |
| ChatGPT share (Polish) | chatgpt.com/share/6acdf73a-... | prior analysis: repo scores (concept 9/10, backend 2/10), proposed console IA, tenant isolation, CORS warning, priority order |
| Defender for Cloud overview | learn.microsoft.com/azure/defender-for-cloud/overview-page | UX patterns below |

Key ChatGPT-chat conclusions kept: priority = multi-tenant + real API + customer dashboard + AWS collector, before attack paths / autonomous remediation. Customer console and internal admin are separate. Lock CORS to exact origins. Tenant isolation is the top security requirement.

Conflict to resolve: the chat proposed the console under `onenexora.com/console`. The user now wants CSPM on its **own site**. Decision: `cspm.onenexora.com` (marketing) + `app.cspm.onenexora.com` or `cspm.onenexora.com/app` (dashboard), SSO from Nexora identity. See OPEN QUESTIONS.

## 2. Current state (honest)

- Done: monorepo (pnpm, TS), Express API skeleton, OpenAPI+orval+zod codegen pipeline, Drizzle package (no schema), shadcn/ui component kit in `artifacts/mockup-sandbox`.
- Not done: every endpoint besides `/api/healthz`, DB schema, auth, tenancy, rule engine, UI app, collectors, AI, billing.
- Live elsewhere (not in this repo): Nexora CSPM Beta paste-scan at cspm.onenexora.com/app. Its code is not in this repo; the new app must match or replace its behaviour (rules, quotas).
- Bug/risk in repo: `app.use(cors())` open to all origins. `lib/api-zod/tsconfig.json` has uncommitted content that is TypeScript source (`export * from ...`), not a tsconfig; it looks like an index.ts saved under the wrong name. Fix before build.

## 3. Reference UX patterns (Defender for Cloud overview, public docs)

Top filters: Scope, Environment (AWS/Azure/GCP), Time range (30d/3m/6m).
Sections: Security at a glance (Secure Score + trend, alerts by severity, asset coverage full/partial/none) -> Top Actions (critical recommendations, attack paths) -> Trends over time (posture, recommendations by severity) -> Workload insights tiles (mini dashboards with link-through). Plus Regulatory compliance and Inventory tiles, and an Insights pane (tips, what's new).
Apple-style layer: generous whitespace, one idea per card, large numeric type, restrained colour, system font stack, subtle motion, light+dark. Build own tokens in `/replica-design`; no Microsoft/Apple logos, icons or fonts.

## 4. Screen inventory

Marketing site (cspm.onenexora.com):

| ID | screen | route | purpose | key components | states |
| --- | --- | --- | --- | --- | --- |
| S01 | Landing | / | pitch + CTA | hero, 3-step, rule list, live demo scan, pricing teaser | default, mobile |
| S02 | Pricing | /pricing | plans | plan cards, quota table, FAQ | default |
| S03 | Docs/quickstart | /docs | JSON format, rules | doc nav, code blocks | default |
| S04 | Sign in / redirect | /signin | SSO from Nexora | button, loading redirect | loading, error, denied |

Customer console (app):

| ID | screen | route | purpose | key components | states |
| --- | --- | --- | --- | --- | --- |
| S05 | Onboarding | /app/onboarding | first scan or connect | stepper, paste box, sample config | empty, validating, error |
| S06 | Overview | /app | posture at a glance | filter bar, score tile, KPI tiles, trend chart, top actions, provider tiles | empty, loading, filled, error |
| S07 | Findings list | /app/findings | triage | table, filters, severity chips, bulk actions | empty, loading, filled, none-match |
| S08 | Finding detail | /app/findings/:id | why + fix | risk breakdown, affected resource, AI summary, fix snippet, status menu | loading, accepted-risk, resolved |
| S09 | New scan | /app/scans/new | paste JSON, run | code editor, validate, run button, quota meter | invalid JSON, quota exceeded |
| S10 | Scan history / result | /app/scans, /app/scans/:id | past runs and diff | list, diff badge new/fixed | empty, running, failed |
| S11 | Assets | /app/assets | inventory | grouped counts, table, criticality | empty, filled |
| S12 | Compliance | /app/compliance | framework coverage | framework cards, control table, failed->findings link | empty, filled |
| S13 | Attack paths | /app/attack-paths | chains | node graph, path list | locked (plan), empty (Phase 2) |
| S14 | AI Security Center | /app/ai | brief + Q&A | daily brief card, chat, suggested questions | quota, error |
| S15 | Remediation | /app/remediation | fixes and PRs | fix queue, Terraform diff | Phase 3 |
| S16 | Reports | /app/reports | exports | exec report, PDF/CSV | empty |
| S17 | Integrations | /app/integrations | connect cloud accounts | provider cards, connect wizard, status | not connected, connecting, error |
| S18 | Team & RBAC | /app/team | members, roles | invite, role select | empty |
| S19 | Usage & billing | /app/usage | quotas, plan | meter, upgrade, invoices | free, at-limit |
| S20 | Audit log | /app/audit | who did what | filterable table | empty |
| S21 | Settings | /app/settings | org, API keys, notifications | forms, key table | default |
| S22 | Admin (internal) | admin app | tenants, support | table | separate surface, Phase 3 |

Global states: 403 wrong tenant, 404, offline, session expired, maintenance.

## 5. Flows

- F01 Visitor tries a scan: S01 -> S09 (anonymous sample) -> result -> S04 signup prompt. edge: invalid JSON, rate limit.
- F02 Nexora client enters CSPM: onenexora.com console -> redirect -> S04 (SSO) -> S06 (or S05 if no data). edge: no CSPM entitlement, expired session, multiple orgs. Happy path target: 1 click from Nexora console.
- F03 First scan: S05 -> S09 -> S10 -> S06. target: under 4 clicks from login to first findings.
- F04 Triage: S06 top action -> S07 -> S08 -> mark status. edge: accepted-risk needs reason + expiry.
- F05 Fix with AI: S08 -> AI explanation -> copy fix / (later) PR -> rescan -> finding marked fixed.
- F06 Compliance gap: S12 failed control -> S07 filtered -> S08.
- F07 Connect AWS (Phase 1b): S17 -> role-ARN + external-ID wizard -> validate -> first discovery -> S11.
- F08 Upgrade: S19 at limit -> Stripe checkout -> back, quota raised.
- F09 Invite teammate: S18 -> email -> accept -> role scoped.
- F10 Executive report: S16 -> generate -> download/share.

## 6. Components

Shell: top bar (org switcher, scope, search, user), left nav (collapsible), breadcrumbs. Data: KPI tile, score ring, sparkline, trend chart, severity chip, status badge, data table (sort, filter, bulk), tabs, filter bar. Input: JSON editor, file drop, select, date range, toggle. Feedback: toast, empty state, skeleton, banner (quota, beta), confirm dialog, side drawer. Domain: risk breakdown bar, attack-path graph, framework card, AI brief card, code diff. Existing base: shadcn/ui set in mockup-sandbox (reuse allowed, it is the user's own).

## 7. Data model (inferred; confidence in brackets)

```
Organization  id, name, plan, nexora_org_id                  [high]
Member        id, org_id, user_id (nexora identity), role     [high]  roles: owner admin analyst viewer
CloudAccount  id, org_id, provider, external_id, role_arn, status, last_sync   [high]
Asset         id, org_id, account_id, provider, type, name, env, criticality 1-10, owner, raw jsonb   [high; README]
Scan          id, org_id, source (paste|account), status, started_at, counts, created_by   [high]
Finding       id, org_id, scan_id, asset_id, rule_id, severity, risk_score 0-100, status (open|fixed|accepted|false_positive),
              first_seen, last_seen, accepted_until, evidence jsonb   [high]
Rule          id, resource_type, title, severity, remediation, framework_map   [high]
ComplianceControl id, framework, control_id, rule_ids   [med]
ComplianceResult  org_id, scan_id, control_id, status   [med]
RiskSnapshot  org_id, date, score, counts by severity   [high; trend chart]
AiBrief       id, org_id, finding_id?, kind, content, model, tokens   [med]
UsageEvent    org_id, kind, count, at   [high; quotas]
AuditEvent    org_id, actor, action, target, at, ip   [high]
ApiKey        id, org_id, hash, scopes, last_used   [med]
```
Every table carries org_id; tenant isolation via Postgres RLS + server-side scoping (top security requirement).
Risk formula from README (Impact x Likelihood x Exposure x BusinessFactor / 2250 x 100) is kept, but its inputs (threat intel, data sensitivity) are not available from pasted JSON. v1 uses severity x exposure x criticality and says so in the UI.

## 8. Cannot be cloned / out of scope

skip rows are in features.csv. Summary: Microsoft's Secure Score algorithm, threat-intel feeds, Defender plans, Apple/Microsoft fonts and icons, compliance framework text (CIS/PCI texts are licensed; map to control IDs only), real-time agentless snapshots, SOC2/ISO certification of Nexora itself, cloud-provider partner programs.

## 9. Size and hard parts

Size: **L** (a quarter) for Phases 1 to 2; Phase 1 alone (paste scan + console + auth + billing + AWS read-only) is **M**.
Hardest parts:
1. Multi-tenant auth + SSO handoff from Nexora identity (Nexora Core "does not exist yet" per its own site, so identity may have to be built or stubbed with Clerk/own JWT).
2. Safe AWS connector (cross-account role + external ID, read-only, no stored long-lived keys).
3. Risk scoring + AI explanations that are accurate and not hallucinated (rule-grounded prompts, cached per finding, cost-capped).
Also: attack-path graph (Phase 2), Terraform/PR remediation (Phase 3).

## 10. Open questions (need the user)

1. Hostnames: `cspm.onenexora.com` (site) + `app.cspm.onenexora.com` (dashboard) acceptable? Currently /app lives under the same host.
2. Identity: does Nexora have a working login at console.onenexora.com today, and can I see how it issues sessions? Otherwise choose Clerk (skills available) or own JWT.
3. Does the existing Beta paste-scan app have source somewhere? Reuse its rules for parity.
4. Hosting target (Replit artifacts are in the repo; Cloudflare was mentioned in the chat).
5. Keep pricing Free $0 / Starter $19 or redo in `/replica-launch`?

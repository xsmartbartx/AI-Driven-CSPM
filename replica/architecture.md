# Architecture: NEXORA CSPM

Inputs: recon.md, features.csv. Decisions on the recon's open questions (defaults, change any time):

| question | decision |
| --- | --- |
| hosts | site `cspm.onenexora.com`, dashboard `app.cspm.onenexora.com`, API `api.cspm.onenexora.com` |
| identity | own email+password JWT now; Nexora SSO handoff via HS256-signed short token (`/auth/sso?token=`) signed with a shared secret; swappable later |
| hosting | Docker images, host-agnostic |
| pricing | Free $0 (10 scans/mo), Starter $19 (75), Team $79 (500), Enterprise contact |

## Stack (reuses the existing monorepo)

| layer | choice | why |
| --- | --- | --- |
| site | Vite + React + TS, static (`artifacts/cspm-site`) | already the repo's frontend tooling; static host, fast |
| dashboard | Vite + React + TS + Tailwind + shadcn/ui + Recharts + wouter (`artifacts/cspm-app`) | shadcn kit already in repo; SPA behind login |
| API | Express 5 + zod (`artifacts/api-server`) | exists; OpenAPI -> orval clients already wired |
| DB | Postgres + Drizzle (`lib/db`); PGlite for dev/tests | zero-setup tests, same SQL |
| auth | JWT in httpOnly SameSite cookie + CSRF header; scrypt password hash | no extra service |
| rules engine | pure TS package `lib/cspm-engine` | testable, shared by API and docs |
| AI | provider interface; Anthropic if `ANTHROPIC_API_KEY` set, else deterministic rule-grounded text | works offline, never invents facts |
| payments | Stripe Checkout + webhook (test mode only until you go live) | |
| design | tokens in `lib/ui-tokens` shared by both apps | one brand |

One database, no microservices. Collectors (AWS) are a Phase 1b module inside the API process, run by a job.

## Schema
`replica/schema.sql`: 14 tables. Access: **one authorisation check per query** (every data-layer function takes `orgId` from the session, never from the request body) **plus** RLS policies as defense in depth in prod. Hard constraints: `unique(org_id, asset_id, rule_id)` so rescans update rather than duplicate; accepted-risk requires reason and expiry (check constraint); `stripe_events` PK for webhook idempotency.

## API (base `/api`, JSON, cookie auth unless noted)

| route | what | who | flow |
| --- | --- | --- | --- |
| GET /healthz | health | public | |
| POST /auth/signup | create user+org | public, rate-limited | F01 |
| POST /auth/login, POST /auth/logout, GET /auth/me | session | public / any | F02 |
| GET /auth/sso?token= | Nexora handoff, upserts user+org by nexora ids | signed token | F02 |
| POST /demo/scan | anonymous scan, not stored, 5/hour/IP | public | F01 |
| POST /scans | run paste scan, stores assets/findings/snapshot, counts quota | analyst+ | F03 |
| GET /scans, GET /scans/:id | history, result + diff | member | F03 |
| GET /overview?range=30d | score, KPIs, trend, top actions, provider tiles | member | F03 |
| GET /findings (q, severity, status, provider, sort, page) | list | member | F04 |
| GET /findings/:id, PATCH /findings/:id | detail, status change | member / analyst+ | F04 |
| POST /findings/:id/explain | AI explanation (cached, counts `ai` usage) | analyst+ | F05 |
| GET /assets | inventory with counts | member | |
| GET /compliance | framework coverage from findings | member | F06 |
| GET /usage | plan, quota used | member | F08 |
| POST /billing/checkout, POST /billing/webhook | Stripe | owner / Stripe sig | F08 |
| GET/POST /team, DELETE /team/:id, POST /team/invite, POST /invites/accept | members | admin+ | F09 |
| GET /audit | audit log | admin+ | |
| GET/POST/DELETE /api-keys | keys | admin+ | |
| POST /cloud-accounts, POST /cloud-accounts/:id/verify | AWS connect wizard | admin+ | F07 (1b) |
| GET /reports/summary.csv | export | member | F10 |

Jobs: nightly `risk_snapshots` rollup; monthly nothing needed (usage is by `period` key); daily brief (could).

## Parts that bite
- **Tenant isolation:** only scope from session; test with two orgs that A never sees B (automated test).
- **Idempotency:** Stripe events deduped; rescans upsert on the unique key.
- **Quotas:** check-and-insert in one transaction; period key `YYYY-MM` UTC.
- **Abuse:** rate limit auth, demo scan; body size cap 1 MB; max 500 resources per scan.
- **CORS:** exact origins from env, credentials on; CSRF token header; helmet headers.
- **Secrets:** AWS uses cross-account role + external ID, never access keys. API keys hashed.
- **AI:** prompt contains only rule text + evidence; output stored; never claims facts outside evidence.
- **GDPR:** org delete cascades; user delete route in Phase 2.

## Build order
1. **Slice:** engine + POST /demo/scan + signup/login + POST /scans + overview + findings list + detail. Screens S01 S04 S06 S07 S08 S09.
2. **Must-haves:** quotas/usage S19, RBAC S18, hardening, Stripe test, site S02 S03, onboarding S05.
3. **Should:** history S10, assets S11, compliance S12, audit S20, API keys, AI explain, settings S21, trend ranges.
4. **Could:** AWS connect, attack paths, reports, AI Q&A.
5. Fixes from entrepreneur.

Riskiest: (1) tenant isolation and SSO handoff, (2) risk score honesty with limited inputs, (3) AWS connector (deferred to 1b).

## As built (deviations from the plan above)
- Styling is plain CSS on shared tokens (`lib/ui-tokens/tokens.css`), not Tailwind/shadcn; the repo's shadcn kit had no package.json and was not reused.
- Data layer is raw SQL (`lib/db/src/schema.sql`, embedded via `gen-schema.mjs`) behind a tiny adapter: `pg` in production, embedded PGlite for dev/tests. Drizzle was dropped. 15 tables (adds `sso_tokens`, `token_version` on users).
- API: 31 routes. JWT is hand-rolled HS256 (no library). Orval/OpenAPI codegen is not used for the new routes; `lib/api-spec/openapi.yaml` still only describes health.
- Roles read from the DB on every request; no RLS yet.
- Phase 1b (AWS connector), attack paths, remediation, AI Q&A are not built.

# Deploy checklist: NEXORA CSPM

Status 2026-10-14: **ready to deploy to staging, not ready for public launch.** Nothing was deployed, bought, registered or paid for. No accounts were created and no live keys were used. Everything below marked "you" needs your accounts.

## Preflight (run today)
| check | result |
| --- | --- |
| engine unit tests | 9 / 9 pass |
| API tests, embedded Postgres | 27 / 27 pass |
| API tests, **real Postgres 16** (Docker) | 27 / 27 pass, incl. concurrent-quota race |
| Playwright e2e (real Chrome, axe WCAG AA, no console errors, no 5xx) | 33 / 33 pass |
| typecheck (api, app, site, engine) | clean |
| `pnpm audit --prod` | no known vulnerabilities |
| production builds (site 69 KB gzip JS, app 78 KB, API bundle) | pass |
| API production mode (NODE_ENV=production) | refuses to start without JWT_SECRET; HSTS on; cookie HttpOnly+Secure+SameSite=Lax |
| Docker image (`deploy/api.Dockerfile`, 244 MB) run against Postgres | healthz 200, demo scan 200, healthcheck wired |
| brand sweep | clean, after narrowing the avoid list to competitor names (see `replica/brand.json` note) |
| must-haves | 10 of 13 done, 3 partial: Stripe, SSO, RLS (see below) |
| open S1 bugs | none. Open S2: no email (verification, reset, invites) |
| privacy + terms pages | **drafts live on the site, not lawyer-reviewed, brackets to fill** |
| account deletion | works (tested) |
| favicon / titles | own, inline SVG; no OG image yet |

## Blocks launch (public), in order
1. **Email**: needs a provider account (Resend or Postmark) and a verified sending domain. Until then no password reset, no verification, invites are copy-paste links. Do not launch to the public without at least reset.
2. **Stripe end to end** in test mode, then live (steps below).
3. **Nexora SSO handoff**: onenexora.com must mint the token and redirect (below).
4. **Postgres RLS** switched on (defense in depth). Tenant isolation is already enforced in every query and tested, so this is hardening, not a hole.
5. **Lawyer review** of Privacy and Terms; fill the bracketed details; add a cookie notice only if you add non-essential cookies or analytics (today there are none, only the session cookie).
6. Rate limiter is per process: fine for one instance, move to Redis before running several.

## Target layout
| what | host name | served by |
| --- | --- | --- |
| marketing site | `cspm.onenexora.com` | static host: build `artifacts/cspm-site` (`pnpm --filter @workspace/cspm-site build`, publish `dist`) |
| dashboard | `app.cspm.onenexora.com` | static host: `artifacts/cspm-app` `dist` |
| API | `api.cspm.onenexora.com` | container from `deploy/api.Dockerfile` (Fly.io, Render, Cloud Run, ECS, any Docker host), port 8080, health `/api/healthz` |
| database | private | managed Postgres 15+, backups on, a **separate production database** |

Both static sites need SPA fallback and the headers already in `public/_headers` and `public/_redirects` (Cloudflare Pages and Netlify read them as is; on other hosts copy the same rules). The CSP there allows API calls to `https://api.cspm.onenexora.com`; change it if the API host differs.

Cookies: the session cookie is set by the API host and sent from the app host. They share the registrable domain `onenexora.com`, so `SameSite=Lax` works. If you ever put the API on a different domain, sessions break; keep them under onenexora.com.

## DNS (you set these at your DNS provider; exact targets come from the hosts you pick)
| type | name | value |
| --- | --- | --- |
| CNAME | `cspm` | the site host's target (e.g. `<project>.pages.dev`) |
| CNAME | `app.cspm` | the app host's target |
| CNAME or A | `api.cspm` | the API host's target or IP |
| TXT / CNAME | as the email provider shows | SPF, DKIM for the sending domain |
| TXT | `_dmarc` | `v=DMARC1; p=none; rua=mailto:<you>@onenexora.com`, tighten to `quarantine` after clean reports |

## Environment (API container; names in `.env.example`, no values were written anywhere)
`NODE_ENV=production`, `DATABASE_URL`, `JWT_SECRET` (32+ random bytes), `APP_ORIGINS=https://cspm.onenexora.com,https://app.cspm.onenexora.com`, `APP_URL=https://app.cspm.onenexora.com`, `TRUST_PROXY=1`, `SSO_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_STARTER`, optional `ANTHROPIC_API_KEY`.
Front-end build vars: `VITE_API_URL=https://api.cspm.onenexora.com` (both), `VITE_APP_URL=https://app.cspm.onenexora.com` (site).
The API creates tables on first start if they are missing (`lib/db/src/schema.sql`). There is no migration tool yet: for later schema changes add numbered SQL files and a runner first. Back up before changing anything.

## Stripe (you create; test mode first)
1. Product "NEXORA CSPM Starter", $19/month recurring → `STRIPE_PRICE_STARTER`.
2. Webhook `https://api.cspm.onenexora.com/api/billing/webhook` for: checkout.session.completed, customer.subscription.updated, customer.subscription.deleted, invoice.payment_failed → `STRIPE_WEBHOOK_SECRET`.
3. Enable the customer portal with cancellation.
4. In test mode: upgrade with `4242 4242 4242 4242`, check the plan flips and quota rises; cancel in the portal and check it drops to Free; try the decline card `4000 0000 0000 0002`.
5. Repeat in live mode with live keys, one real purchase and a refund.

## Nexora SSO handoff (needs a change on onenexora.com)
The console server signs a 2-minute, one-use token and redirects the browser to the URL it prints. Reference implementation: `deploy/make-sso-token.mjs` (HMAC-SHA256, claims sub, email, name, org, orgName, role, jti, exp). Rules: sign server-side only, share `SSO_SECRET` with the API only through your secret store, role claim is capped at `admin`, the first user of a new Nexora org becomes the CSPM owner. Add an "Open CSPM" button in the Nexora console that hits that route.

## Watch it (first week)
Not set up (needs your accounts): error tracking (Sentry or host), uptime checks on `https://api.cspm.onenexora.com/api/healthz` and the site, log retention, an alert to your email. Watch: signups, first scan within a day of signup, 402 quota errors, `billing.payment_failed` entries in the audit log, 5xx rate, DB size and connections. Do the core flow on the live site yourself (signup, sample scan, findings, accept a risk, sign out), then on your phone.

## CI
`.github/workflows/ci.yml`: install, schema-generated check, audit, typecheck, unit + API tests (embedded and real Postgres service), builds, Playwright. Never run against production.

## Known gaps to tell users honestly
Paste-config only (no live AWS yet), rule set is 9 rules over 4 resource types, compliance mapping is indicative, attack paths / generated fixes / AWS connect are roadmap, no Safari/Firefox testing, no screen-reader pass, no load testing.

## Go / no-go
**Staging: go**, once you pick hosts. **Public launch: no-go** until email, Stripe live test, SSO handoff, legal review. Say "go" for each account step you want me to prepare further, and tell me the host you choose so I can write exact deploy commands for it.

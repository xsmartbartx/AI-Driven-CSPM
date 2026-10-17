# Backend notes and security checklist

Test mode only. No live keys, no third-party accounts created. Variables: see `.env.example`.

## Checklist
- [x] secrets only in env vars; `.env*` and `.data` in `.gitignore`; no secrets in client bundles (front ends read only `VITE_*` URLs)
- [x] input validated on the server with zod on every route; body limit 1 MB; max 500 resources per scan
- [x] authorisation on every read and write; org id always from the session. Tested with a second org (read, patch, explain, scan, CSV, compliance) and a forged `orgId` in the body
- [x] rate limits: signup 10/h, login 10/15min, SSO 30/min, invite accept 20/h, anonymous demo 5/h. In memory, per process (move to Redis for several instances)
- [x] Stripe webhook verifies signature (5 min tolerance) and records the event id in the same transaction as the handler, so a failed handler is retried
- [x] no uploads in the product
- [x] no user data in URLs or logs (request logs strip the query string, which carries the SSO token)
- [x] `pnpm audit --prod`: no known vulnerabilities
- [ ] privacy policy lists every processor. Not written yet (launch step). Processors: hosting, Postgres host, Stripe, optional Anthropic (finding text only, no account data)

## Auth
- scrypt password hashes, constant-time compare, equal timing for unknown emails
- session: JWT in httpOnly, SameSite=Lax cookie (Secure in production), 7 days. Role re-read from the DB on every request, so removing a member or changing a role is immediate
- sign out everywhere: `token_version` bump invalidates all sessions (tested)
- account deletion: password-confirmed, real delete; blocked if sole owner of an org with other members; last member takes the org with them (tested)
- CSRF: cookie sessions need an allowed `Origin` plus `x-csrf: 1`; API keys (Bearer) are exempt
- CORS: exact origins from `APP_ORIGINS`, credentials on, nothing else
- API keys: sha256 stored, shown once, analyst-level
- Nexora SSO: HS256 token signed with `SSO_SECRET`, lifetime at most 10 minutes, one-time `jti`, role claim capped at admin, first user of a new Nexora org becomes owner

## Not done, and why
- **Email**: built on Resend (`services/mail.ts`): confirmation on signup, password reset, invite emails. Tokens are random, stored only as hashes, single use (atomic), reset 1 h, confirm 24 h, newest link wins, reset signs out everywhere and verifies the mailbox; forgot-password answers identically for unknown addresses and is rate limited per IP and per address; provider failures never fail the request. **Not tested against the real provider.** Unverified users are not blocked from anything yet (banner only).
- **Migrations**: numbered SQL files run at API start under an advisory lock (`lib/db/migrations`, tested: fresh, pre-migration database, idempotent overlap, rollback on failure, concurrent start on real Postgres). Forward-only.
- **Row level security**: done (migration 0003). Two layers: every query filters by `org_id`, and Postgres refuses cross-tenant rows regardless (`cspm_app` role + `app.org_id`, fails closed, plan and Stripe columns not writable by tenant requests, secrets and system tables not readable). Tested by attacking it directly: unfiltered queries, cross-tenant insert/update/delete, moving a row to another org, privilege escalation, SQL in the org id, pooled-connection reuse; on embedded Postgres, on real Postgres as a superuser and as a non-superuser owner, and through the production bundle on an upgraded legacy database. Limits: it does not guard the privileged paths (auth, webhooks), a database user with BYPASSRLS gains nothing for tenant requests only because they switch role, and transaction-mode poolers are unsupported.
- **Stripe**: checkout, portal and four webhook events are coded and unit-tested with signed payloads, never run against Stripe. Needs your test-mode keys and a Starter price id.
- **AWS connector, email, background jobs**: not built (Phase 1b). Nightly snapshot rollup is replaced by writing a snapshot on every scan.
- **Backups**: depend on the Postgres host. Turn them on and verify (deploy checklist).
- **Anthropic explanations**: coded with timeout and fallback, not run live.

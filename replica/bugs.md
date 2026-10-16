# Bugs

Found during build and test, all fixed, each with a test that now guards it.

| ID | sev | found by | what | fix |
| --- | --- | --- | --- | --- |
| B01 | S2 | engine unit test | A web server with 443 open to the world was flagged "allows all internet traffic" | 80/443 single-port rules are not flagged; ranges and all-ports are |
| B02 | S1 | API tests | Embedded DB could not run the multi-statement schema, so nothing started | use `exec` for migrations |
| B03 | S2 | audit vs checklist | Stripe event was marked seen before its handler ran; a failing handler would never be retried | record + apply in one transaction (test: failed handler leaves no event row) |
| B04 | S2 | audit | No "sign out everywhere", no account deletion | token_version, DELETE /auth/me (tested, e2e) |
| B05 | S2 | audit | SSO token could be replayed within its lifetime | one-time `jti` stored in sso_tokens (tested) |
| B06 | S3 | visual check in Chrome | "Compliance coverage 3%" implied full-framework compliance; scores saturated at 100 for every production-critical finding | KPI now "mapped controls passing" with a disclaimer; criticality multiplier softened |
| B07 | S3 | Chrome console | React key warning on finding evidence list | Fragment key |
| B08 | S3 | e2e | Site nav links had no spacing (shared CSS missing in site) | moved utilities into shared tokens.css |
| B09 | S2 | startup | `pnpm-workspace.yaml` removed macOS native binaries, so Vite could not start on a Mac; `lib/api-zod/tsconfig.json` was empty and `lib/db/package.json` was a copy of the root one | removed darwin overrides; rewrote both files |

## Open, to fix before launch
- **O1 (S2)** Email is built (Resend: confirmation, reset, invites) but untested against the real provider and needs your Resend account, verified domain and key. Until then production sends nothing; invites remain copy-paste links.
- **O2 (S3)** Rate limiter is in memory per process.
- ~~O3~~ Postgres RLS: done in migration 0003. Found while testing it: a connection-leak in my own tests, a test database that was not re-runnable, and a migration that failed hard when the role already existed under another owner (now tolerant, with a clear startup error instead).

## To check (not reproduced)
- Behaviour with a very large number of findings (thousands): list is paginated, overview queries are aggregate, untested at scale.
- Axe passes, but a manual screen-reader pass has not been done.
- The e2e guard tolerates HTTP 503 by design; a real outage would show as a different failure, not as a failed guard.

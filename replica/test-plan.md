# Test plan

Run: `pnpm --filter @workspace/cspm-engine test` (9), `pnpm --filter @workspace/api-server test` (27), `cd e2e && npx playwright test` (33, real Chrome, own ports and in-memory DB). Every e2e test fails on console errors, 5xx responses (503 allowed: billing not configured by design) and axe WCAG 2.1 AA violations.

| flow | cases | where |
| --- | --- | --- |
| F01 visitor demo scan | H1 demo shows findings + signup prompt; E1 bad JSON; E2 empty list; E3 unsupported type reported; H2 pricing/docs; H3 CTA links; API: demo rate limit 5/h | e2e, api |
| F02 account/session | H1 signup, sign out, sign in; N1 wrong password; N2 duplicate email, short password; E1 refresh keeps session, deep link when signed out; E2 sign out everywhere; E3 delete account; API: CSRF, CORS, expired/forged tokens | e2e, api |
| F03 first scan | H1 first scan in 3 clicks; E1 invalid JSON/config stores nothing; E2 double click = one scan; E3 rescan after fix; E4 refresh; E5 long/accented/emoji names, no overflow; API: 500-resource and 1 MB limits, concurrent scans vs quota | e2e, api |
| F04 triage | H1 filter/search/pagination; H2 detail; N1 accept risk needs reason + future date; E1 Escape closes dialog; API: expiry rules, search wildcard escaping, fixed findings cannot be edited | e2e, api |
| F05 AI explanation | H1 explain, cached, counted once; API: quota, fallback text | e2e, api |
| F06 compliance | H1 failing controls link to findings; disclaimer shown | e2e, api |
| F08 quota/upgrade | N1 10 scans then block; upgrade shows clear "not set up" message; API: Stripe signature, replay, idempotency, lifecycle events, retry after failure | e2e, api |
| F09 team/RBAC | H1 invite, accept, read-only viewer, promote, single-use invite; API: admin cannot touch owner, last owner protected, removal is immediate | e2e, api |
| F10 settings/usage/audit | theme persists, API key shown once, usage meter, audit entries, planned pages honest | e2e |
| isolation | org B cannot open org A finding/scan by URL; API: 12 endpoints incl. forged orgId | e2e, api |
| mobile | drawer nav, no horizontal scroll, axe | e2e (@mobile, 390px) |
| engine | rule semantics, Deny ignored, no double reporting, port ranges, score bounds, input validation, compliance mapping | unit |

Not automated, needs you or real keys: real Stripe checkout and portal with test card `4000 0000 0000 0002` (decline) and `4242 4242 4242 4242`; real Anthropic explanations; real Nexora SSO token from onenexora.com; invite/reset emails (not built); screen reader pass (axe only); Safari/Firefox (Chrome only).

Not covered: load/soak tests, multi-instance rate limiting, network offline/slow behaviour, DST/time zone display (all stored UTC, shown in browser locale).

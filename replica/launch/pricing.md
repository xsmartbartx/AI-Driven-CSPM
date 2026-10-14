# Pricing

## Public competitor pricing (read 2026-10-14, from the pages themselves)
| product | what the page says | source |
| --- | --- | --- |
| Wiz (AWS Marketplace listing) | Essential $24,000/year for 100 cloud workloads; Advanced $38,000/year for 100 workloads; add-ons priced separately; 12/24/36-month contracts; free trial; private offers | https://aws.amazon.com/marketplace/pp/prodview-ibgbkrqusncsm |
| Microsoft Defender for Cloud | "Foundational CSPM" listed as Free; Defender CSPM price field shows "$-", "Pricing is dependent on cloud size", billed per billable resource | https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/ |
| AWS Security Hub, Prowler, others | not read; no claims made | - |

Prices change; re-read before publishing any comparison. Do not put competitor names or prices on the product site without a lawyer's look.

## What reviewers said about price
From `replica/fixes.md`: 1 comment (Hacker News, second-hand) on Wiz "contact sales" pricing. Thin. No review-site data was reachable.

## The model (unchanged from the live Beta)
| plan | price | for | includes |
| --- | --- | --- | --- |
| Free | $0 | trying it, one engineer | 10 scans/month, 10 AI explanations |
| Starter | $19/month | a small team | 75 scans, 100 AI explanations, roles, audit log, API keys |
| Team | $79/month | a team scanning in CI | 500 scans, 1,000 AI explanations |
| Enterprise | contact | SSO, custom limits | |

Rationale: the Free and Starter prices match what is already published on onenexora.com, so no customer sees a price change. Team ($79) is new and an assumption with no market evidence; validate it with the first paying users. Annual billing (2 months free) is not built; add after the first month of real usage.

Billing promises already in the product: cancel in the Stripe portal (one click, `POST /billing/portal`), plan changes only via webhooks, no per-seat pricing so no surprise seat jumps, a clear "limit reached" message instead of silent failures.

## Stripe objects to create (you create them; test mode first)
- Product "NEXORA CSPM Starter", recurring price $19/month → put its id in `STRIPE_PRICE_STARTER`.
- Webhook endpoint `https://api.cspm.onenexora.com/api/billing/webhook` with events checkout.session.completed, customer.subscription.updated, customer.subscription.deleted, invoice.payment_failed → `STRIPE_WEBHOOK_SECRET`.
- Customer portal enabled with cancellation allowed.
- Team plan has no checkout yet (code supports only Starter); sell by contact until built.

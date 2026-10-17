# Stripe setup and test-mode run

The billing code is finished and unit-tested with signed fake events. It has never talked to Stripe. These steps need **your** Stripe account; nothing here was run against it.

## 1. Create the test-mode objects (one command)
In the Stripe dashboard switch to **Test mode**, create a **restricted or secret test key** (Developers → API keys). Then, on your machine:

```bash
STRIPE_SECRET_KEY=sk_test_... node deploy/stripe-test-setup.mjs --webhook-url https://api.cspm.onenexora.com/api/billing/webhook
```
It creates (or reuses on a second run): the product "NEXORA CSPM Starter", a **$19/month** price, a webhook endpoint with the four events the API handles (`checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_failed`), and a customer-portal configuration that allows cancelling at period end. It prints `STRIPE_PRICE_STARTER` and `STRIPE_WEBHOOK_SECRET`; set those and the key on the API host. It **refuses live keys** and plain-http webhook URLs, and never prints your key. The signing secret is shown only when the endpoint is created; if the endpoint already existed, copy the secret from the dashboard.

Scripts were tested against a mock Stripe API in CI (`deploy/test/scripts.test.mjs`), not the real one: if Stripe changed a field, the script prints Stripe's own error.

## 2. Try it locally first (optional, recommended)
With the Stripe CLI installed: `stripe listen --forward-to localhost:8080/api/billing/webhook`. It prints a `whsec_...` secret for that session; run the API with it as `STRIPE_WEBHOOK_SECRET`, `STRIPE_SECRET_KEY=sk_test_...`, `STRIPE_PRICE_STARTER=<price id>`.

## 3. The test-mode run (about 15 minutes)
Use a fresh account in the app on the Free plan.
| step | do | expect |
| --- | --- | --- |
| 1 | Usage & plan → Upgrade | redirect to Stripe Checkout for $19/month |
| 2 | pay with `4242 4242 4242 4242`, any future date, any CVC | back on the app; within seconds the plan shows **Starter** and the scan limit 75 |
| 3 | Stripe dashboard → webhook endpoint → recent deliveries | all 2xx; none retried |
| 4 | Usage & plan → Manage or cancel subscription | portal opens; cancel at period end offered |
| 5 | in the dashboard cancel the subscription immediately | plan returns to **Free** within seconds |
| 6 | upgrade again with the decline card `4000 0000 0000 0002` | checkout shows the decline; plan stays Free |
| 7 | resend one delivery from the dashboard | API answers `duplicate`; nothing changes |
| 8 | Upgrade while already on Starter | the app refuses (409) and points to the portal |
Also check the API log has no stack traces, and that `audit` shows `billing.checkout_started`.

## 4. Live mode (only after step 3 passes)
Do this in the dashboard, not with the script: recreate the product and the $19 price in live mode, add the live webhook endpoint with the same four events, enable the live portal configuration, then set the live key, price id and signing secret on the production API. Make one real purchase with your own card and refund it. Keep test and live secrets in different environments.

## Known limits
Only the Starter plan can be bought online (Team is "contact us"). No annual billing, no tax or invoice details, no proration handling beyond Stripe's defaults, no emails on payment failure (an audit entry is written).

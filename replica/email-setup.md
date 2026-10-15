# Email setup (Resend)

The code is finished. These steps need your account, so I did not do them. Nothing has been sent to a real address.

## What sends email
| email | when | link lifetime |
| --- | --- | --- |
| Confirm your email | on signup, and from the dashboard banner ("Resend email") | 24 hours |
| Reset your password | "Forgot your password?" on the sign-in page | 1 hour, single use, signs you out everywhere |
| You are invited to <org> | when an admin creates an invite (the link is also shown to the admin as a fallback) | 7 days, single use |

Not built: notification emails (finding digests, quota warnings), marketing mail. Unverified users are only shown a banner; nothing is blocked.

## Steps for you
1. Create a Resend account (resend.com).
2. **Domains → Add domain.** Use a sending subdomain such as `mail.cspm.onenexora.com` (Resend recommends a subdomain so mail reputation is separate from your main domain). Choose the region closest to your users.
3. Resend shows DNS records for that domain: SPF (TXT), DKIM (TXT or CNAME) and a return-path (MX). Add them exactly as shown at your DNS provider. Wait until Resend marks the domain **Verified**.
4. Add a DMARC record if you have none: `_dmarc.mail.cspm.onenexora.com TXT "v=DMARC1; p=none; rua=mailto:<you>@onenexora.com"`. Tighten `p=none` to `quarantine` once the reports are clean.
5. **API Keys → Create**, permission **Sending access**, restricted to that domain. Copy it once.
6. Set on the API host (never in the repo): `RESEND_API_KEY=<the key>` and `MAIL_FROM=NEXORA CSPM <no-reply@mail.cspm.onenexora.com>`. In production the API refuses to start with a key but no `MAIL_FROM`.
7. Test: sign up with an address you own, check the confirmation mail and that it is not in spam; use "Forgot your password?"; invite a second address of yours.
8. Check mail-tester.com or Gmail "Show original" for SPF/DKIM/DMARC = pass.

## Behaviour to know
- No key in development: emails are printed to the API console (including the links), so you can try every flow locally.
- No key in production: nothing is sent, the API logs a warning, the dashboard says it could not email the invitation and shows the link.
- A failed send never fails signup, invites or password-reset requests. The error is logged by status code only, never with the address or the link.
- Forgot-password always answers "if an account exists…" and has a per-address limit of 3 per hour (and 10 per IP), so it cannot be used to find registered addresses or to spam someone.
- Links contain the token in the URL path (`/reset-password/<token>`); they are single use and short-lived. Static-host access logs will contain them, so keep those logs private or short-lived.
- Resend is a data processor: it receives the recipient address and message. The draft privacy page already lists it.
- Existing database created before this change: see the `alter table` note in `replica/deploy.md`.

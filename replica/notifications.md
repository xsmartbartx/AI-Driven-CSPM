# Scan alerts (email and Slack)

Settings → Notifications (owners and admins). When a scan finds **new** findings, or findings that come back after being fixed or after an accepted risk expires, at or above the chosen severity, NEXORA tells you. The same findings in a later scan do not alert again.

| setting | values |
| --- | --- |
| Email | on or off; sent to the organization's owners and admins (first 10) |
| Alert on | critical and high (default), or critical only |
| Slack | an incoming webhook URL, `https://hooks.slack.com/services/…` (create one in Slack: Apps → Incoming Webhooks) |

- Applies to manual scans, connected-account scans and scheduled scans.
- "Send a test" tells you what worked for each channel. If the last alert failed (a revoked webhook, for example) the page shows the problem.
- The webhook URL is a secret: stored per organization under row level security, only accepted for `hooks.slack.com`, never returned by the API, and not written to the audit log (which records only "set" or "removed").
- A failed notification never fails the scan. Email needs the mail provider from `replica/email-setup.md`; without it, email alerts are not sent.
- API: `GET/PUT /api/notifications`, `POST /api/notifications/test` (admin).

# Daily summary

**Overview → Since yesterday** says in plain sentences what changed: how many findings are open, how many are new in the last day, how many were fixed, whether the posture score moved, and which accepted risks or rule suppressions come due within 14 days. The new findings are listed and link to their pages.

It is built from the stored findings with no model involved, so every line can be traced to findings. "New" means first seen in the window and still open: suppressed and fixed findings are not news.

- API: `GET /api/brief?hours=24` (any key; `hours` 1 to 720, so `168` gives a weekly view). Described in `/api/openapi.json`.
- **Email:** Settings → Notifications → "Daily summary email". Once a day after 07:00 UTC, to the organization's owners and admins (first 10), and only when there is something to say: a new or fixed finding, a critical finding still open, or a review coming due. A quiet day sends nothing. The scheduler sends it, so it needs the scheduler on (`SCHEDULER` is on by default) and the mail provider from `replica/email-setup.md`.
- The send is claimed in the database before mailing, so several API instances never send twice; if mailing fails that day's email is lost, not retried.

# Launch plan

Everything below that needs an account (Product Hunt, analytics, email) is yours to create. Nothing was posted or signed up for.

Before launch: finish the Phase-1 blockers in `replica/diff.md` (email, Stripe test run, SSO handoff, deploy), lawyer review of Privacy/Terms, turn on error tracking and basic privacy-friendly analytics, add a waitlist form or the signup link on onenexora.com.

Who to reach, in this order:
1. **Existing Nexora users and the Beta's usage log**: they already used the paste scanner. Ask 10 by hand: "what would make you connect a real account?" Their answers decide whether AWS connect (Phase 1b) or CI scan comes first.
2. **Small AWS teams** in communities where posture and cost come up (DevOps and AWS subreddits and Slack groups, Hacker News "Show HN"). Lead with the fix, not the feature list: a Show HN titled around "free paste-your-config AWS misconfiguration scanner". Read each community's self-promotion rules first.
3. **Product Hunt**: a launch only after email, billing and SSO work. Not before; a Beta with no password reset will leak users.

Messages: lead with "short ranked list, a fix for each, free to start". Never name competitors in ads. No fake reviews or "trusted by".

Metrics: signups, first scan within 24h (target: most signups), scans per week per org, Free→Starter conversion, finding status changes (shows real triage), and the support questions you get. Retention at day 7 matters more than signups.

Risks: unvalidated positioning (3 data points); paste-config limits value; Security Hub and Wiz are free/better for those who connect accounts. The honest pitch is "fastest first look, cheapest, simple", not "replaces CNAPP".

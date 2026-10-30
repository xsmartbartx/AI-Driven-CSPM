# Rule suppressions (noise control)

Admins and owners can stop a rule from counting. Open a finding and choose **Suppress this rule…**, or manage the list under **Settings → Suppressed rules**.

| scope | meaning |
| --- | --- |
| Only this asset | the rule is ignored for that one asset |
| All production / staging / development assets | the rule is ignored for every asset in that environment |
| Every asset | the rule is off for the organization |

A reason (at least 5 characters) is required. An expiry (30 days, 90 days, 1 year or never) is optional but recommended: when it passes, the findings reopen on their own at the next scan or when the list is viewed.

- Suppressed findings are stored as **false positive** with the reason `Suppressed: …`. They leave the open list, the posture score, the compliance view, attack paths, the printable security report and scan alerts. The **Findings CSV export still lists them** (status `false_positive`), so an audit trail keeps them. Filter findings by status "False positive" to review them in the app.
- New findings that match, including ones on assets added later, are born suppressed. A scan reports them as `suppressed` in its counts, not as new.
- Removing a suppression reopens its findings immediately. Reopening one finding by hand takes just that finding out of the suppression.
- Analysts can see the list (Settings shows it to them without the Remove button); only admins and owners create or remove. Both are written to the audit log. Limit: 100 per organization.
- API: `GET/POST /api/suppressions`, `DELETE /api/suppressions/:id`.
- Scope by tag is not built; the environment is the available grouping.

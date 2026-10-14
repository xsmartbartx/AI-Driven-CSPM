# Brand

Not a clone, so there is no original to hide from. The job here is to make sure the product does not borrow Microsoft's or Apple's identity while taking their UX lessons.

## Name
**NEXORA CSPM** (a product under the NEXORA platform, as already on onenexora.com). The name is the user's, so no 20-candidate exercise was run.
Checks, none run (they are yours to run, and a lawyer's job before spending on the brand):

| check | status |
| --- | --- |
| US trademark (USPTO, classes 9 and 42) | to run |
| EU trademark (EUIPO / TMview) | to run |
| WIPO global database | to run |
| "CSPM" is a generic industry term: expect no exclusive rights in that word, only in NEXORA | note |
| domain `onenexora.com` | already yours; `cspm.onenexora.com` is a subdomain, nothing to buy |
| `app.cspm.onenexora.com`, `api.cspm.onenexora.com` | subdomains, need DNS records only |
| App Store / handles | not applicable (web only) |

## Palette
Own teal, not in Microsoft's blue family or Apple's blue. Placeholder `accent #0b6a88` light, `#4cb8d8` dark; both checked: 17 pairs each, 0 WCAG AA failures (`replica/design/tokens*.json`, `python3 contrast.py`). Change values only in the tokens; role names stay.
Sweep colours added to `brand.json` (#0078d4, #0071e3 and neighbours): none present in the code.

## Logo brief
- Idea: a shield outline holding a single clear line, "protection that is easy to read". Current favicon is a placeholder shield drawn for this project, not traced from anything.
- Wordmark "NEXORA CSPM" in the system sans, weight 700; symbol plus wordmark for the header, symbol alone for favicon.
- Must hold at 16px (favicon) and 1024px.
- Deliverables: SVG, favicon set (16/32/180), social image 1200x630, no iOS icon needed yet.
- Must not resemble Microsoft's shield-and-check security marks or any other vendor's. Put a competitor's mark beside the drafts before approving; a plain shield is common, so a designer should make it ownable (a distinctive internal shape).

## Voice
Three words: **plain** (not casual: say what happened and what to do), **honest** (not negative: say what the product does not do yet), **brisk** (not curt: one sentence where one will do).

Do / don't:
- Do "Run your first scan". Don't "Embark on your security journey".
- Do "Planned, not built". Don't "Coming soon!" with no truth behind it.
- Do "Not a full CIS-AWS assessment". Don't imply compliance you did not check.
- Do "Email or password is incorrect". Don't say which one.
- Do "You have used all 10 scans on the Free plan this month". Don't "Oops!".

The 10 most-seen strings (already written fresh in this build): hero headline, "Run your first scan", "Run scan", empty findings state, quota message, accept-risk dialog, sign-in error, "Planned, not built", scan result headings, usage banner.

## Sweep
`sweep.py` with the avoid list: 4 hits, all reviewed and kept:
1. README.md (2 lines): Azure's own service names as supported sources, descriptive use.
2. pnpm-workspace.yaml: a comment inherited from the template, not shipped.
3. tokens.css: `-apple-system` is the CSS keyword for the system font, not an asset.
No third-party logos, icons, fonts, images or copy are in the code. The favicon and icons are inline SVG drawn here.

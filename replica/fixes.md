# Market research and fix plan

## Sample size, stated plainly
**3 usable public comments, 1 source (Hacker News).** I pulled 464 HN comments through the official Algolia API for 16 queries; after filtering for CSPM tools plus complaint words, 30 matched and only 3 were about the products and a real complaint. G2, Capterra and TrustRadius returned HTTP 403, Reddit was unreachable, and I did not try to get around those blocks. So the entrepreneur skill's bar (100+ reviews, 3+ sources) was **not met** and everything below is a hypothesis, not a finding. To do it properly: export reviews by hand from G2/Capterra/Gartner Peer Insights, or give me a CSV (`replica/reviews.csv`, columns source,url,date,rating,text) and I will rank it.

## The three quotes (verbatim, linked)
1. AWS Security Hub, 2021: "I enabled AWS Security Hub to have some sort of security score on my account and although it found a few interesting, it generates way too much noise to be usable." https://news.ycombinator.com/item?id=26437889 (the same commenter says Microsoft's Azure and Office 365 security score has "the same issues")
2. Wiz, 2025: "Wiz is "contact sales for pricing"." and, citing its AWS Marketplace listing, "the lowest cost they have is $24,000/year." https://news.ycombinator.com/item?id=43399932 (second-hand; I did not verify the listing)
3. Market shape, 2023: "It's not good enough for a tool to just be used for Cloud Security Posture Management (CSPM) - it also has to do CI/CD security stuff and workload protection." https://news.ycombinator.com/item?id=36623732

## Three lists (all thin)
**What they hate** (thin, 1 source each)
- Noisy, unprioritised findings (Security Hub): 1 comment.
- Opaque, enterprise-only pricing (Wiz): 1 comment.

**What is missing** (thin)
- Tools are expected to also cover CI/CD and workloads: 1 comment. Not a reason for a paste-config scanner to chase it.

**What is unsolved** (my hypothesis, no review evidence)
- Small teams with one or a few AWS accounts that cannot buy a five-figure platform and want a ranked, plain-language list this week. Supported only indirectly by the pricing comment and by the product being priced at $0/$19.

## Fix plan (what the evidence supports, so small)
| fix | size | who | evidence |
| --- | --- | --- | --- |
| Rank by risk and show only a short top list on the overview (built) | done | build | Security Hub noise comment |
| Accept-risk with reason and expiry, false-positive status (built) | done | build | same |
| Suppress a rule for one asset or tag | S | build | same, thin |
| Public self-serve pricing from $0 (built on site) | done | launch | Wiz pricing comment |
| Terraform plan JSON scan for CI | M | build | consolidation comment, thin |

Added to `features.csv` with `original = no`: suppress-rule, Terraform-plan scan.

## The angle (recommend one, validate before betting on it)
1. **Recommended.** For small teams who cannot justify enterprise CSPM pricing or sift through Security Hub noise, NEXORA CSPM gives a short ranked list with a fix for each, starting free. Evidence: pricing and noise, 2 comments, 1 source (thin).
2. For engineers who want checks before deploy: scan the Terraform plan in CI with the same rules. Evidence: 1 comment (thin).
3. For managers: a posture score and trend they can show without learning cloud. Evidence: none from reviews; comes from the project's README vision.

Do not name competitors in the product name, ads or store listing. A comparison page needs a lawyer.

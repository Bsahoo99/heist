# Template stats

Date run: 2026-11-02.
Script: `engine/scripts/scan_templates.py` (run with `cd engine && uv run python scripts/scan_templates.py`).
Every number is an aggregate over the scanned repos; no repo is named here.

## Method

Repos were collected on 2026-11-02 with the GitHub code search API through the `gh` CLI, using read-only calls.
Lovable query: `lovable-tagger "@supabase/supabase-js" filename:package.json`, taking unique repos in the order GitHub returned them.
Bolt query: `path:.bolt supabase`, taking unique repos in the order GitHub returned them.
Each candidate was kept only if it was public, not a fork and not archived, and its root `package.json` listed `@supabase/supabase-js` with `vite` or `next`.
The first 35 Lovable repos and the first 15 Bolt repos that passed were scanned, 50 in all.
Each repo was shallow-cloned at its default branch through Heist's normal fetch path, with the same file and size caps as a real analysis.
Only Heist's detectors ran: no model calls, no proofs, and no request to any deployed app.
Repos that failed to clone, hit the caps, or were not a supported stack are counted below and left out of every percentage.
This is a convenience sample from search ranking, not a random sample of all Lovable or Bolt apps.

## Outcomes

| Outcome | Repos |
| --- | --- |
| Scanned | 50 |
| Total | 50 |

Every percentage below is out of the 50 scanned repos.

## Headline

Repos with at least one confirmed critical finding: 30 of 50 (60%).
Repos with at least one confirmed finding of any severity: 39 of 50 (78%).
Repos with only findings marked possible, not confirmed: 1 of 50 (2%).
Repos with no database rules (migrations) in the repo: 9 of 50 (18%).
For those repos Heist cannot check tables or storage buckets, so mistakes 3 and 4 are unknown, not clean.
Repos with migration files Heist could not read: 8 of 50 (16%).
Findings per repo: median 4.5, range 0 to 88.
Confirmed findings per repo: median 3, range 0 to 86.

## By mistake

A repo counts once per mistake, however many findings it has.
A repo is under Possible, not confirmed only when none of its findings for that mistake is confirmed.

| Mistake | Confirmed | Possible, not confirmed |
| --- | --- | --- |
| 1. Secret keys in front-end code | 17 of 50 (34%) | 0 of 50 (0%) |
| 2. Supabase admin (service role) key reachable from the browser | 8 of 50 (16%) | 0 of 50 (0%) |
| 3. Tables anyone can read | 23 of 50 (46%) | 3 of 50 (6%) |
| 4. Public or unprotected storage buckets | 0 of 50 (0%) | 1 of 50 (2%) |
| 5. Server functions or routes with no sign-in check | 25 of 50 (50%) | 0 of 50 (0%) |
| 6. Records changed by an ID from the request without an owner check | 0 of 50 (0%) | 12 of 50 (24%) |
| 7. Paid AI or API calls anyone can trigger | 6 of 50 (12%) | 0 of 50 (0%) |

## Manual review

The numbers above are what Heist's detectors report, with no human check.
A manual review of the 30 repos with a confirmed critical finding found that about half of them rest only on findings that are likely false positives or outside the browser code.
The main causes were secrets matched in docs, test files, discarded migrations and editor configs rather than in the app's code, public-by-design values (a captcha site key, a public API key, signed storage URLs, a well-known sandbox passkey), the service role key read by Node scripts or server code outside the folders Heist already skips, and tables readable by signed-in users that hold only catalog or app content.
On that stricter reading, 16 of the 50 repos (32%) have a confirmed critical finding in the app's code or database rules.
One more repo has a service role key committed in its docs, which is a serious leak even though it is not in the browser code.
Mistake 2 drops the most: only 1 of the 8 flagged repos puts the service role key in browser code.
Mistake 5 was not reviewed by hand, and some of those functions may be public on purpose (webhooks, contact forms).

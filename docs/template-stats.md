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
The optional semgrep community rules were off, so there is no row for other community findings.
Repos that failed to clone, hit the caps, or were not a supported stack are counted below and left out of every percentage.
This is a convenience sample from search ranking, not a random sample of all Lovable or Bolt apps.
The numbers are Heist's detector output as is; a manual spot check of an earlier run was used to fix false positives in the detectors, and it adds nothing to these numbers.

## Outcomes

| Outcome | Repos |
| --- | --- |
| Scanned | 50 |
| Not a supported stack (Vite or Next.js with Supabase) | 0 |
| Over Heist's size caps | 0 |
| Not a valid GitHub repo URL | 0 |
| Could not be cloned | 0 |
| Took longer than the 300 second limit | 0 |
| Crashed in Heist | 0 |
| Total | 50 |

Every percentage below is out of the 50 scanned repos.

## Headline

Repos with at least one confirmed critical finding: 22 of 50 (44%).
Repos with at least one confirmed finding of any severity: 36 of 50 (72%).
Repos with only findings marked possible, not confirmed: 3 of 50 (6%).
Repos with no database rules (migrations) in the repo: 9 of 50 (18%).
For those repos Heist cannot check tables or storage buckets, so mistakes 3 and 4 are unknown, not clean.
Repos with migration files Heist could not read: 8 of 50 (16%).
Findings per repo: median 3.5, range 0 to 85.
Confirmed findings per repo: median 2, range 0 to 75.

## By mistake

A repo counts once per mistake, however many findings it has.
A repo is under Possible, not confirmed only when none of its findings for that mistake is confirmed.

| Mistake | Confirmed | Possible, not confirmed |
| --- | --- | --- |
| 1. Secret keys in browser code or committed public files | 4 of 50 (8%) | 11 of 50 (22%) |
| 2. Supabase admin (service role) key in browser code or a committed public file | 4 of 50 (8%) | 0 of 50 (0%) |
| 3. Tables anyone (or any signed-in user) can read | 20 of 50 (40%) | 6 of 50 (12%) |
| 4. Public or unprotected storage buckets | 0 of 50 (0%) | 1 of 50 (2%) |
| 5. Server functions or routes with no sign-in check | 25 of 50 (50%) | 0 of 50 (0%) |
| 6. Records changed by an ID from the request without an owner check | 0 of 50 (0%) | 12 of 50 (24%) |
| 7. Paid AI or API calls anyone can trigger | 6 of 50 (12%) | 0 of 50 (0%) |

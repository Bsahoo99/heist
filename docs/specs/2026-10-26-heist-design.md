# Heist: design

Name: **Heist**.
Tagline: "See how your vibe-coded app gets robbed, before someone else does."
Pitch line: "Scanners give you a list of warnings. Heist shows you the robbery, proves it, and teaches you how to lock the door."
Event: Meta Global AI Developer Hackathon, Indie track, solo builder working full days.
Building period: Oct 27 to Nov 4, 2026. Submission due Nov 4, 9:00 PM ET; we submit by 12:00 PM ET that day.

## 1. Intent and the why

Millions of people now ship apps they did not write and do not understand, because an AI wrote the code.
Those apps leak data in predictable ways.
UpGuard found 16,326 databases with publicly readable tables in Sept 2026, Moltbook leaked about 1.5M API keys through a key in frontend JavaScript, and the Tea app leaked about 72,000 photos from an open storage bucket.

Existing tools fall into two camps, and neither reaches this person.
Repo explainers (DeepWiki, GitDiagram, Code2Tutorial, video explainers) describe structure but ignore security and never show one action playing out.
Vibe-code scanners (VibeEval, CheckVibe, Vibe App Scanner) and pro tools (Snyk, Semgrep, ZeroPath) output lists of alerts and fix prompts that a beginner cannot understand, so the same mistake comes back next time.

Heist takes a public GitHub repo and shows, visually and inside that exact app, how an attacker would get in.
It replays the attack on a 2.5D isometric map of the app, proves the worst kind of leak with fake data, and explains every step in three layers: the story (anyone can follow), the why (what this step protects and what breaks without it), and the code (real file, line, and data at that point, plus the fix).

The builder wants the user to come away understanding their own app and the security basics behind it, not just with a patched line.

## 2. Hero user

The non-expert vibe coder looking at their own app: someone who built it with Lovable, Bolt, Cursor, v0 or similar, synced it to GitHub, and does not really know what the code does.
Learners exploring other people's repos are a welcome side audience, but no design decision is made for them.

## 3. Goals

1. Paste a public GitHub repo URL and get a result in about 2 minutes for a small-to-medium app.
2. Detect the seven most common vibe-coding security mistakes (section 6) reliably, with low false alarms.
3. Open with "the heist": an animated replay of the worst finding, then the full list of findings.
4. Prove the most damaging leak (open database rows) for real, offline, using fake data.
5. Explain each step at three depths: story, why, code, with an exact fix and a copy-paste fix prompt.
6. Every claim traces back to real code. Nothing appears in the scene unless it maps to a file and line.
7. Export the replay as MP4 and GIF, give each analysis a public share page, and give passing apps a README badge.
8. Use Meta's models visibly and beyond a basic integration (section 9).

## 4. Non-goals

- Not a general-purpose security scanner for every language and framework.
- Not live penetration testing of deployed sites.
- Not a chat-with-your-repo bot. There is no chat box in v1.
- Not automatic pull requests or code rewriting. We show the fix; the user applies it.
- Not compliance reports, dashboards for security teams, or CI integration.
- Not private repos, zip uploads, or local folders. Public GitHub URLs only.
- No user accounts or sign-in in v1. Anyone can paste a repo, within the rate limits.

## 5. Anti-goals (failure even if it technically works)

- Presenting a guess as a confirmed vulnerability. Wrong findings destroy trust.
- Anything that helps someone attack an app they do not own: no requests to deployed URLs, no working exploit payloads aimed at live targets.
- Looking like a generic explainer, chatbot, or "AI for education" tool. The hackathon lists those as anti-projects.
- Touching real user data. Proofs only ever use fake seeded data.
- A demo that fails live. Demo repos are pre-analyzed and cached.
- An unbounded bill if the project goes viral.

## 6. Scope for v1

### Supported apps

1. **First:** Vite + React + Supabase, including Supabase Edge Functions. This is the Lovable and Bolt default, and these apps have no server routes of their own, so their security lives in Supabase rules and Edge Functions.
2. **Second:** Next.js + Supabase (v0, Cursor), including API routes and server actions.

Everything else gets a friendly "not supported yet" message rather than a weak result.
Repos are capped at about 2,000 files and about 5 MB of source after excluding dependencies, builds, and assets.

### The seven mistakes

| # | Mistake | Status shown |
|---|---|---|
| 1 | Secret keys in frontend code (hardcoded, or in `VITE_*` / `NEXT_PUBLIC_*` variables) | Confirmed |
| 2 | Supabase `service_role` key reachable from the browser | Confirmed |
| 3 | Tables with RLS off, open to everyone (for example `using (true)`), or open to any signed-in user (for example `auth.uid() is not null`) | Confirmed, then **proved** |
| 4 | Storage buckets that are public or have no policies | Confirmed |
| 5 | Edge Functions or routes with no auth check, including functions deployed with JWT verification off | Confirmed |
| 6 | Missing ownership checks: a record read or changed by an ID from the request without checking it belongs to the signed-in user | Always "possible, worth checking" |
| 7 | Paid AI or API calls in Edge Functions or routes with no auth or rate limit | Confirmed |

Stretch classes if time allows: `dangerouslySetInnerHTML` with user input (XSS), raw SQL built from strings, wide-open CORS.

### When database rules are not in the repo

Some apps were set up by clicking in the Supabase dashboard, so `supabase/migrations` is missing or incomplete and mistakes 3 and 4 cannot be checked.
Heist then shows a clear "We can't see your database rules" card that explains why that matters and gives a read-only SQL query the user can paste into their own Supabase dashboard to check for themselves.

## 7. The experience

### Analysis

The isometric map is on screen from the moment the user submits.
It lights up as Heist works ("found 6 tables", "found 3 Edge Functions", "checking locks"), so the 1 to 2 minute wait becomes part of the show.

### The map

A fixed, hand-designed city block, the same for every app, filled in with each repo's own parts:

| Zone | App part |
|---|---|
| Street | The visitor, anonymous or signed in |
| Shop window | The front end running in the browser |
| Guard desk | Supabase Auth |
| Side doors | Edge Functions (or Next.js routes) |
| Vault | The database, with one box per table |
| Warehouse | Storage buckets |
| Across the road | Outside services such as AI APIs |

Parts the app does not use are greyed out.
There is no automatic layout algorithm.

### The heist

The results page opens by auto-playing the replay of the single worst finding, about 20 to 30 seconds long.
A faint ghost line first shows the legitimate path (visitor, guard desk, their own vault box), then the attacker's path takes the shortcut past the missing lock.
After the replay come the full list of findings, a step player (play, pause, step forward and back) for each finding, and a panel per stop with three tabs: Story, Why, Code.
The Story tab uses the heist metaphor (vault, lock, side door, key under the doormat).
The Why and Code tabs are plain and technical.

### Proof

For mistake 3, Heist proves the leak.
It applies the repo's own migrations to a throwaway Postgres in a sandbox, seeds every table with obviously fake rows ("Test Alice", "Test Bob", fake emails and notes), then queries as an anonymous visitor and as a different signed-in user.
The leaked fake rows are shown on screen as the climax of the replay.

### Fixes

Every finding gets the fix explained in plain language, the exact code or SQL change, and a "Copy fix prompt" button with a prompt written for Lovable, Bolt or Cursor, so the user can paste it into the tool that wrote the bug.

### Clean apps

When nothing is found, the replay shows the heist failing: the attacker tries each door and the vault, the locks hold, and a summary says the app held up against all seven checks.
Passing apps get a README badge such as `Heist-tested: 7/7 locks held` that links back to their result page.

### Sharing

Each analysis has a public share page with the replay embedded and MP4 and GIF downloads.

## 8. How it works

1. **Fetch.** Shallow clone of the public repo into a temporary workspace. Apply the size cap and ignore lists. Detect the stack and refuse unsupported ones politely.
2. **Map the app.** Parse JS/TS with tree-sitter and read `supabase/migrations`, `supabase/config.toml` and `supabase/functions` to build an app graph: pages, forms, Supabase client calls, Edge Functions, routes, tables, policies, buckets, external API calls, and the imports and calls that connect them.
3. **Detect.** Deterministic checks are the ground truth: Gitleaks for secrets, Semgrep with community rules plus custom Heist rules, and SQL parsing of migrations for RLS, policies and buckets.
4. **Triage.** Muse Spark Open, through partner inference, does a fast first pass over files and raw findings: drops obvious noise, groups duplicates, and tags which user action each finding belongs to. Its cost and speed against Muse Spark are measured and reported in the README.
5. **Trace and explain.** Muse Spark (Meta Model API, 1M context) receives the app graph, the relevant code, and each finding. It produces the ghost path, the attacker path, the three-layer explanation for every step, the fix, and the fix prompt.
6. **Validate.** Every step the model returns must reference a node and a file and line that exist in the app graph. Steps that fail are dropped, and the call is retried once with feedback. Findings only the model suspects are labeled "possible, not confirmed" and drawn differently.
7. **Prove.** For mistake 3, run the RLS proof in a Modal sandbox with network egress off.
8. **Render.** The result is a scene JSON document. The front end renders it deterministically onto the fixed map, so the same analysis always looks the same.

Stretch: a general proof agent built on Muse Code that confirms other mistake types in the sandbox.

### Scene JSON (shape, details left to the builder)

- `zones`: which map zones are active, with the repo's parts (tables, functions, buckets) placed in them and linked to graph nodes.
- `findings`: class, severity, status (`confirmed`, `proved`, `possible`), the ghost path, the attacker path, the missing guard's location, proof rows if any, the fix, and the fix prompt.
- Each path step: zone, code reference (file, line range, symbol), data at that point, and `story`, `why`, `code` texts.
- `meta`: repo, commit SHA, analyzed time, model versions, whether database rules were found.

## 9. Use of Meta models

| Model | Role | Why it matters for judging |
|---|---|---|
| Muse Spark (Meta Model API) | Whole-repo reasoning, attack-path tracing, three-layer explanations, fixes and fix prompts | Core of the product; uses the 1M context to reason across the whole app |
| Muse Spark Open (Baseten, Fireworks, or Modal) | High-volume triage of files and findings, with measured cost and speed savings | Genuine engineering choice; qualifies for "Best Build on Meta Open Weight Models" |
| Muse Image | Artwork for the fixed map and its zones, in one consistent style | Gives the scene its look; candidate for "Best Creative Build" |
| Muse Code | Used to build the project; powers the stretch proof agent | Agentic story for "Best Agentic Use-Case" |

The models do the reasoning and storytelling, while deterministic tools keep findings honest.

## 10. Stack (chosen by Claude)

- **Analysis engine:** Python 3.12 with uv, FastAPI.
- **Parsing and detection:** tree-sitter (JS/TS), Semgrep, Gitleaks, a SQL parser for migrations.
- **LLM access:** Meta Model API through its OpenAI-compatible interface; partner inference for Muse Spark Open. Exact endpoints and model IDs confirmed in the day-1 smoke test.
- **Front end:** Next.js (App Router) with TypeScript and Tailwind; SVG for the map; a small animation library for the replay and step player.
- **Video export:** Playwright plays the replay headless and records it; ffmpeg converts to MP4 and GIF.
- **Hosting:** front end on Vercel; analysis engine and proof sandboxes on Modal, with a plain container host as fallback if Modal credits do not come through.
- **Storage:** Supabase Postgres for cached analyses and share pages. Heist also scans itself as a demo moment.

## 11. Safety and cost guardrails

- Analysis only reads code. Heist never sends traffic to a deployed app.
- Proofs run only inside an isolated sandbox with network egress off, against a local copy, with fake seeded data.
- Explanations describe how an attack works and how to fix it; they do not output ready-to-run exploit scripts.
- Only public repos are accepted.
- Any real issue found in someone else's project is reported privately, never published. Public template stats are reported as aggregates only, never naming repos.
- Cost caps: hard daily spend cap, per-IP rate limit, repo size cap, and a cache keyed by repo and commit SHA. Meta API spend limit set to $150 on the billing page.
- Demo and example repos are pre-analyzed, so judging (Nov 5 to 8) costs nothing and cannot break if credits run out.

## 12. Demo and submission

### Demo app

A pet-adoption style app with logins and photo uploads, built in Lovable or Bolt on their free tier with plain prompts, the way a real user would.
Mistakes are added on purpose only if the tool does not produce enough on its own.

### Real-world numbers

Late in the build, run Heist on 30 to 50 public Lovable and Bolt starter templates and showcase repos, and report aggregate numbers only.

### The 3-minute video

| Time | Content |
|---|---|
| 0:00-0:15 | Hook: the heist replay on our Lovable app, fake users' data spilling out |
| 0:15-0:35 | The problem: real incidents (16k exposed databases, Tea, Moltbook), vibe coders don't know |
| 0:35-1:45 | The product: paste URL, map builds, heist plays, Story / Why / Code, proof rows, copy fix prompt |
| 1:45-2:10 | Fix it in Lovable, re-run, the heist fails, the badge appears |
| 2:10-2:35 | How it works: pipeline, the role of each Meta model, measured triage savings |
| 2:35-3:00 | Real-world numbers from the template scan, and the pitch line |

Recorded in the builder's own voice.
The video and the public repo make clear that all of Heist was built during the event; commit history starts Oct 26.
An X post with the replay clip goes out for the "Most Viral" bonus, plus a push for the community vote.

### Deadline

- Feature freeze on the evening of Nov 3.
- Nov 4 is only for bug fixes, the video, the README, the X post, and pre-caching demo repos.
- Submit by 12:00 PM ET on Nov 4, 9 hours before the deadline.

## 13. Priorities if time runs short

1. Pipeline steps 1 to 6 and 8 working end to end on the demo app (ugly is fine).
2. The fixed map, the heist replay with ghost line, and the three-layer panels, polished.
3. The RLS proof.
4. Fix prompts, the "heist failed" replay, and the badge.
5. Share page and MP4/GIF export.
6. Public template stats.
7. Stretch: the general proof agent and extra mistake classes.

## 14. Left to the builder

- Exact Semgrep rules, prompts, and retry logic.
- Visual style details of the map within the fixed zone layout.
- Which public templates to use as examples.

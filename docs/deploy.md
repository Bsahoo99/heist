# Deploying Heist

Heist runs as two pieces: the engine on Modal and the web app on Vercel.
Heist's own Supabase project caches finished analyses and tracks the daily model spend.
Nothing below prints a secret: keys stay in env files and go to Modal and Vercel from there.
Never paste a key on a command line or into a chat.

## 1. Create Heist's Supabase project

Create a new project in the Supabase dashboard (name `heist`, a US East region, close to Modal).
Open Project Settings, API, and keep the page open: you need the project URL and the service role (secret) key.
Open the SQL editor, paste all of `supabase/migrations/0001_heist.sql` and run it once.
In Table Editor, check that `analyses` and `spend_daily` exist and both show RLS enabled with no policies.

## 2. Fill engine/.env

Add the two Supabase values to `engine/.env` (it is gitignored), next to the model variables already there:

```
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<the service role or sb_secret_ key>
```

Run the engine locally once with them (`cd engine && uv run uvicorn heist.api:app --port 8000`), analyze a repo, and check that a `done` row appears in `analyses`.

## 3. Log in to Modal

From `engine/`, run `uv run modal token new` and finish the login in the browser.

## 4. Create the two Modal secrets

From `engine/`, copy only the variables each secret needs into a temporary env file, create the secret from that file, then delete the file:

```
grep -E '^(OPEN_API_KEY|OPEN_BASE_URL|MUSE_SPARK_OPEN_MODEL|MODEL_API_KEY|MUSE_SPARK_MODEL|META_BASE_URL)=' .env > .env.modal-meta
uv run modal secret create heist-meta --from-dotenv .env.modal-meta --force
grep -E '^(SUPABASE_URL|SUPABASE_SERVICE_ROLE_KEY)=' .env > .env.modal-supabase
uv run modal secret create heist-supabase --from-dotenv .env.modal-supabase --force
rm .env.modal-meta .env.modal-supabase
```

The `.env*` pattern in `.gitignore` keeps the temporary files out of git even if one is left behind.
Run `uv run modal secret list` and check both names are there (it shows names, not values).

## 5. Build the prover image

From `engine/`, run `uv run python -m heist.prove.sandbox warmup --modal`.
The engine also warms it on startup, but proofs are skipped until it is built, so build it before the first real run.

## 6. Pick the web domain and deploy the engine

Pick the Vercel production domain now (for example `https://heist.vercel.app`); the engine only accepts browser requests from it.
From `engine/`, deploy with that origin in the environment:

```
HEIST_WEB_ORIGINS=https://heist.vercel.app uv run modal deploy heist/modal_app.py
```

Modal prints the endpoint, `https://<workspace>--heist-engine-web.modal.run`; keep it for the web app.
The engine runs in exactly one container on purpose: live progress, joins and the rate limit live in its memory.

## 7. Deploy the web app to Vercel

From `web/`, run `vercel login`, then `vercel link` and create or pick the project (root directory `web`).
Add the engine URL for production (it is a URL, not a secret), then deploy:

```
vercel env add NEXT_PUBLIC_ENGINE_URL production
vercel deploy --prod
```

Paste the Modal endpoint from step 6 when `vercel env add` asks for the value.
`HEIST_ENGINE_URL` is optional and only needed if the badge route should reach the engine at a different address.
If the production domain Vercel gave you differs from the one in step 6, run step 6 again with the real domain in `HEIST_WEB_ORIGINS`.

## 8. Smoke checks

Set two shell variables first, so the commands below need no editing: `ENGINE=https://<workspace>--heist-engine-web.modal.run` and `WEB=https://heist.vercel.app`.

1. The engine answers: `curl -s "$ENGINE/openapi.json" | head -c 80` prints the start of a JSON document.
2. CORS allows the web app: `curl -si -X OPTIONS "$ENGINE/analyses" -H "Origin: $WEB" -H "Access-Control-Request-Method: POST" | grep -i access-control-allow-origin` shows the web origin.
3. CORS refuses others: the same command with `-H "Origin: https://example.com"` prints nothing.
4. Open `$WEB` in the browser, run the demo repo, and watch the live map build and the replay start.
5. Run the demo repo again: the results open at once, and `curl -s -X POST "$ENGINE/analyses" -H 'Content-Type: application/json' -d '{"url":"<demo repo URL>"}'` returns `"cached":true`.
6. In the Supabase SQL editor, `select id, repo, status from analyses` shows the `done` row and `select * from spend_daily` shows today's spend.
7. Heist's tables stay closed to the public: with the project URL in `SUPABASE_URL` and its anon key in `ANON` (from the dashboard, never echoed), `curl -s "$SUPABASE_URL/rest/v1/analyses?select=id" -H "apikey: $ANON"` returns a permission error, not rows.
8. The badge works: `$WEB/api/badge/<analysis id>` returns an SVG.
9. The rate limit counts real callers: start five new analyses from one network and check the sixth is refused with the rate limit copy, then check a different network (a phone hotspot) can still start one.
10. Restart survives: run `HEIST_WEB_ORIGINS=$WEB uv run modal deploy heist/modal_app.py` again from `engine/`, then reopen an earlier `/a/<id>` page; it still shows the results, now from Supabase.
11. Heist on its own public repo ends in "This stack is not supported yet", because the repo is not a Supabase app; its own database passes Heist's checks offline (`engine/tests/test_self_scan.py`).

# Heist Build Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Heist, a tool that takes a public GitHub repo of a vibe-coded Supabase app and replays how an attacker gets in on a fixed isometric map, proves open-table leaks with fake data, and teaches the fix, in time to submit to the Meta hackathon by 12:00 PM ET on Nov 4, 2026.

**Architecture:** A Python engine clones the repo, builds an app graph (tree-sitter for JS/TS, pglast for Supabase migrations), runs deterministic detectors for the seven mistakes, then uses Muse Spark Open for triage and Muse Spark for attack-path tracing and explanations, validates every model step against the graph, proves RLS leaks in a network-isolated Modal sandbox, and emits one Scene JSON document.
A Next.js front end renders that Scene deterministically onto a hand-designed SVG city block, with live progress over SSE, the replay, the step player, and Story / Why / Code panels.
Supabase Postgres caches analyses by repo and commit SHA.

**Tech Stack:** Python 3.12, uv, FastAPI, pydantic v2, tree-sitter + tree-sitter-typescript, pglast, Semgrep, Gitleaks, openai SDK (OpenAI-compatible Meta endpoint), Modal, testcontainers; Next.js App Router, TypeScript, Tailwind, motion (framer-motion), vitest, Playwright, ffmpeg; Vercel; Supabase Postgres.

**Spec:** `docs/specs/2026-10-26-heist-design.md` (read it before any task; section numbers below refer to it).

## Global Constraints

- Never use the em dash anywhere: code, copy, docs, commits.
- Commit messages never add an agent as co-author.
- Never hand-edit generated files (`shared/scene.schema.json`, `web/lib/scene.gen.ts`, any CHANGELOG).
- Long Markdown: one sentence per physical line.
- Python 3.12 exactly (`requires-python = ">=3.12,<3.13"`), managed with uv.
- Engine checks: `uv run pytest`, `uv run ruff check .`, `uv run pyright`. Web checks: `pnpm test`, `pnpm lint`, `pnpm typecheck`. Run the relevant ones before every commit and report what ran.
- Public GitHub URLs only. Repo cap: 2,000 files and 5 MB of source after ignores.
- Supported stacks: `vite_supabase` first, `next_supabase` second. Anything else: "not supported yet".
- Heist never sends a request to a deployed app. Proofs run only in a sandbox with network egress off, with fake seeded data.
- Fake proof users are exactly "Test Alice" (`alice@example.test`) and "Test Bob" (`bob@example.test`).
- Status values are exactly `confirmed`, `proved`, `possible`. The UI label for `possible` is "Possible, not confirmed".
- Missing-rules copy: card title "We can't see your database rules".
- Badge text for a clean app: `Heist-tested: 7/7 locks held`.
- Tagline: "See how your vibe-coded app gets robbed, before someone else does."
- Pitch line: "Scanners give you a list of warnings. Heist shows you the robbery, proves it, and teaches you how to lock the door."
- Story texts use the heist metaphor; Why and Code texts are plain and technical.
- No ready-to-run exploit scripts in any model output or UI text.
- Meta API spend limit $150 on the billing page; engine daily spend cap $20; 5 uncached analyses per IP per hour.
- Model output prices for spend tracking: Muse Spark $1.25 per 1M input, $0.15 per 1M cached input, $4.25 per 1M output.
- Feature freeze Nov 3 evening. Nov 4 is fixes, video, README, X post, pre-caching only.

## Review Focus

1. **The Supabase anon key is public by design.** `VITE_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `sb_publishable_*` keys, and `*_URL` variables must never be flagged as mistake 1; flagging them would make every Lovable app look broken. Pinned in Task 7.
2. **Public read on a public table is often intended.** `using (true)` on SELECT for a table like `pets` with no personal columns is low severity ("check this is intended"), not critical; personal columns (email, phone, address, message, notes, user_id-owned rows) make it critical. Pinned in Task 8.
3. **Migrations change rules over time.** A later migration that drops a permissive policy or enables RLS must clear the finding; only the final state after replaying all migrations in filename order counts. Pinned in Task 5.
4. **The model returns a step pointing at a file or line that does not exist, or invalid JSON twice.** The step is dropped, the call retried once with the errors, and on second failure the finding still appears using a deterministic template trace, never a crashed analysis. Pinned in Task 11.
5. **The repo's migrations fail to apply in the proof sandbox** (Supabase-only extensions, references to `auth.users`, `storage.objects`). The finding stays `confirmed` instead of `proved`, and the analysis completes. Pinned in Task 16.

---

## Repository layout

```
heist/
  engine/
    pyproject.toml
    heist/
      models.py            # CodeRef, Node, Edge, AppGraph, Finding, DbSchema, ProgressEvent
      scene.py             # Scene models, build_scene, schema export (__main__)
      fetch.py             # parse_github_url, clone_repo, load_workspace, detect_stack
      graph/supabase.py    # migrations replay (pglast), config.toml, functions dir
      graph/js.py          # tree-sitter: supabase client calls, invokes, external fetches
      graph/build.py       # build_app_graph
      detect/secrets.py    # mistakes 1, 2
      detect/rls.py        # mistake 3
      detect/storage.py    # mistake 4
      detect/functions.py  # mistakes 5, 6, 7 (Semgrep + config)
      detect/run.py        # run_detectors
      rules/*.yml          # custom Semgrep rules
      llm/client.py        # MetaClient, SpendTracker
      llm/triage.py
      llm/trace.py         # TraceOut models, trace_finding
      llm/templates.py     # deterministic fallback traces per mistake
      validate.py          # validate_trace, trace_with_validation
      prove/runner.py      # apply migrations + seed + query (runs inside any Postgres env)
      prove/sandbox.py     # Modal sandbox wrapper, prove_rls
      pipeline.py          # run_analysis
      store.py             # Supabase cache
      guards.py            # RateLimiter, SpendCap
      api.py               # FastAPI app
      cli.py               # `heist analyze <url-or-path>`
      modal_app.py         # Modal deployment
    scripts/smoke_meta.py
    scripts/bench_triage.py
    scripts/gen_art.py
    scripts/scan_templates.py
    tests/fixtures/vuln_app/   # minimal Vite + Supabase app containing all seven mistakes
    tests/fixtures/clean_app/  # same app with every mistake fixed
  shared/scene.schema.json     # generated
  web/
    lib/scene.gen.ts           # generated from the schema
    lib/api.ts
    lib/timeline.ts
    components/map/{layout.ts,CityMap.tsx,Zone.tsx,Paths.tsx}
    components/replay/{Replay.tsx,StepPlayer.tsx}
    components/panels/{StepPanel.tsx,FindingsList.tsx,FixCard.tsx,NoRulesCard.tsx,ProofRows.tsx}
    app/page.tsx
    app/a/[id]/page.tsx
    app/api/badge/[id]/route.ts
    scripts/export-replay.ts
    public/art/
  docs/
```

## Schedule

| Day | Date | Tasks | Milestone |
|---|---|---|---|
| 1 | Tue Oct 27 | 1, 2, 3 (Agents 101 at 12 PM ET) | Repo, smoke test, fixtures, demo app |
| 2 | Wed Oct 28 | 4, 5, 6 (Agents 102; check Meta Billing for credits) | App graph from fixture |
| 3 | Thu Oct 29 | 7, 8, 9 | All seven detectors pass on fixtures |
| 4 | Fri Oct 30 | 10, 11, 12 | **Priority 1:** `heist analyze` emits a Scene for the demo app |
| 5 | Sat Oct 31 | 13, 14 | **Priority 2:** map, replay, panels |
| 6 | Sun Nov 1 | 15, 16 | Live map over SSE; **Priority 3:** RLS proof |
| 7 | Mon Nov 2 | 17, 18 | **Priority 4:** fixes, heist failed, badge; deployed |
| 8 | Tue Nov 3 | 19, 20; freeze in the evening | **Priority 5, 6:** share, export, template stats |
| 9 | Wed Nov 4 | 21 | Submitted by 12:00 PM ET |

If a day slips, cut from the bottom of spec section 13, never from Review Focus tests.
Use weekday office hours (10-11 AM ET, Discord #office-hours) for any Meta API blocker on the day it appears.

---

## Day 1: Tue Oct 27

### Task 1: Repo scaffold

**Files:**
- Create: `heist/.gitignore`, `heist/README.md`, `heist/.env.example`
- Create: `engine/pyproject.toml`, `engine/heist/__init__.py`, `engine/tests/test_smoke.py`
- Create: `web/` via `create-next-app`

**Interfaces:**
- Produces: the check commands from Global Constraints, working on an empty project.

- [ ] **Step 1:** `git init` in `heist/`, branch `main`. `.gitignore` covers `.env*` (except `.env.example`), `.venv`, `node_modules`, `.next`, `data/`, `exports/`.
- [ ] **Step 2:** `uv init --package engine --python 3.12`; add deps `fastapi uvicorn pydantic openai tree-sitter tree-sitter-typescript pglast tomli-w httpx sse-starlette modal supabase`; dev deps `pytest pytest-asyncio ruff pyright testcontainers[postgres] respx`.
- [ ] **Step 3:** `engine/tests/test_smoke.py` asserts `import heist` works. Run `uv run pytest && uv run ruff check . && uv run pyright`. Expected: all pass.
- [ ] **Step 4:** `pnpm create next-app web --ts --tailwind --app --eslint --src-dir=false --import-alias "@/*"`; add `vitest @vitejs/plugin-react jsdom @testing-library/react motion json-schema-to-typescript playwright`; scripts `test: vitest run`, `typecheck: tsc --noEmit`, `gen:scene: json2ts ../shared/scene.schema.json -o lib/scene.gen.ts`. Run `pnpm test && pnpm lint && pnpm typecheck`. Expected: pass (vitest with `--passWithNoTests`).
- [ ] **Step 5:** `.env.example` lists `MODEL_API_KEY`, `META_BASE_URL=https://api.meta.ai/v1`, `MUSE_SPARK_MODEL`, `OPEN_BASE_URL`, `OPEN_API_KEY`, `MUSE_SPARK_OPEN_MODEL`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `NEXT_PUBLIC_ENGINE_URL`. README holds the tagline and pitch line only for now.
- [ ] **Step 6:** Commit `chore: scaffold engine and web`. Create the public GitHub repo and push (repo must be public per the rules).

### Task 2: Meta API smoke test

**Files:**
- Create: `engine/scripts/smoke_meta.py`, `docs/meta-models.md`

**Interfaces:**
- Produces: confirmed values for `MUSE_SPARK_MODEL`, `MUSE_SPARK_OPEN_MODEL`, `OPEN_BASE_URL`, and whether Muse Image is callable, recorded in `docs/meta-models.md`. Tasks 10, 11 and 13 read these.

- [ ] **Step 1 (user):** Create the Meta API key on dev.meta.ai, set the $150 spend limit on Billing, put the key in `engine/.env`. Create a Baseten or Fireworks key for Muse Spark Open (Baseten model `meta-models/muse-spark-open-1026`).
- [ ] **Step 2:** `smoke_meta.py` calls `GET {META_BASE_URL}/models` and prints IDs; sends one chat completion to Muse Spark asking for `{"ok": true}` in JSON mode; sends the same to Muse Spark Open on the partner endpoint; tries one Muse Image generation and reports the HTTP status. Prints latency and token usage per call.
- [ ] **Step 3:** Run `uv run python scripts/smoke_meta.py`. Expected: two `{"ok": true}` responses and a model list. If Muse Image is not on the API, record that and plan to make art in the Meta AI app by hand (Task 13 Step 6).
- [ ] **Step 4:** Write the confirmed IDs, endpoints, JSON-mode support, and observed latency into `docs/meta-models.md`. Commit `chore: meta api smoke test`.

### Task 3: Fixture apps and the demo app

**Files:**
- Create: `engine/tests/fixtures/vuln_app/**`, `engine/tests/fixtures/clean_app/**`, `engine/tests/conftest.py`, `docs/demo-app.md`

**Interfaces:**
- Produces: fixtures `vuln_app_path` and `clean_app_path` (pytest, `Path`). Every detector test uses the expectations below, so keep the files exactly as listed.

`vuln_app` contents (each mistake marked with a `// HEIST-FIXTURE: mN` or `-- HEIST-FIXTURE: mN` comment on the guilty line):

| File | Content | Expected |
|---|---|---|
| `package.json` | deps `vite`, `react`, `@supabase/supabase-js` | stack `vite_supabase` |
| `src/lib/supabase.ts` | `createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY)` | no finding |
| `.env` | `VITE_SUPABASE_URL=...`, `VITE_SUPABASE_ANON_KEY=<anon JWT>`, `VITE_OPENAI_API_KEY=sk-heist-fake-...` | m1 on the OpenAI var only |
| `src/lib/admin.ts` | client built from `import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY` | m2 |
| `src/pages/Pets.tsx` | `supabase.from('pets').select()` | graph edge only |
| `src/pages/Requests.tsx` | `supabase.from('adoption_requests').select()`, `functions.invoke('update-request')` | graph edges |
| `src/pages/Upload.tsx` | `supabase.storage.from('id-documents').upload(...)` | graph edge |
| `supabase/migrations/0001_init.sql` | `profiles` (RLS on, `auth.uid() = id`); `pets` (name, species, photo_url; RLS on, select `using (true)`); `adoption_requests` (user_id, email, phone, message; RLS on, select `using (auth.uid() is not null)`); `messages` (sender_id, body; RLS never enabled) | m3: pets low, adoption_requests critical, messages critical |
| `supabase/migrations/0002_storage.sql` | bucket `pet-photos` public true; bucket `id-documents` private with no policies on `storage.objects` | m4: id-documents high, pet-photos low |
| `supabase/migrations/0003_tighten.sql` | creates `notes` with `using (true)`, then drops that policy and adds `auth.uid() = user_id` | no finding for notes (Review Focus 3) |
| `supabase/config.toml` | `[functions.send-email] verify_jwt = false` | m5 |
| `supabase/functions/send-email/index.ts` | sends mail, no Authorization check | m5 |
| `supabase/functions/update-request/index.ts` | service-role client, `.update(body).eq('id', body.id)`, no user filter | m6 possible |
| `supabase/functions/ai-describe/index.ts` | `fetch('https://api.openai.com/v1/...')`, no auth, no rate limit | m7 |

`clean_app` is the same tree with every row fixed (secrets moved to function env, service role removed from `src/`, owner policies everywhere, bucket policies added, `verify_jwt` on and `auth.getUser()` checks, `.eq('user_id', user.id)` added, auth plus a per-user counter on `ai-describe`). Expected: zero confirmed or proved findings.

- [ ] **Step 1:** Write both fixtures. All fake keys must be clearly fake (`sk-heist-fake-` prefix, anon JWT signed with a dummy secret) so GitHub push protection does not trip.
- [ ] **Step 2:** `conftest.py` exposes the two path fixtures plus `tmp_copy(path) -> Path` that copies a fixture into `tmp_path`.
- [ ] **Step 3 (user, can run in parallel):** Build the pet-adoption demo app in Lovable or Bolt on the free tier with plain prompts (signup, pet list, adoption request form, photo and ID upload, an AI "describe this pet" button). Sync to a public GitHub repo. Record the prompts used and the repo URL in `docs/demo-app.md`. Do not add mistakes by hand yet; Task 12 decides whether it needs any.
- [ ] **Step 4:** Commit `test: add vulnerable and clean fixture apps`.

---

## Day 2: Wed Oct 28

### Task 4: Core models and fetch

**Files:**
- Create: `engine/heist/models.py`, `engine/heist/fetch.py`
- Test: `engine/tests/test_fetch.py`

**Interfaces:**
- Produces (in `models.py`, all pydantic `BaseModel`):
  - `ZoneId = Literal["street","shop_window","guard_desk","side_doors","vault","warehouse","across_road"]`
  - `Stack = Literal["vite_supabase","next_supabase"]`
  - `CodeRef(file: str, start_line: int, end_line: int, symbol: str | None = None)` with `file` relative to the app root, POSIX separators.
  - `Node(id: str, kind: Literal["page","client_call","function","route","table","policy","bucket","external_api","auth"], name: str, zone: ZoneId, ref: CodeRef | None)`
  - `Edge(src: str, dst: str, kind: Literal["imports","queries","invokes","uploads","calls_external"])`
  - `AppGraph(stack: Stack, nodes: list[Node], edges: list[Edge], has_db_rules: bool, db: DbSchema | None)` with `node(id) -> Node` raising `KeyError`.
  - `Finding(id: str, mistake: int, severity: Literal["critical","high","medium","low"], status: Literal["confirmed","proved","possible"], title: str, node_ids: list[str], refs: list[CodeRef], source: Literal["heist","gitleaks","semgrep_community"], evidence: dict[str, Any] = {})`
  - `ProgressEvent(kind: Literal["stage","node_found","finding","done","error"], message: str, data: dict[str, Any] = {})`
- Produces (in `fetch.py`):
  - `class UnsupportedRepo(Exception)` with `.reason: str` (user-facing copy).
  - `Workspace(root: Path, app_root: Path, commit_sha: str, files: list[str])` (`files` relative to `app_root`).
  - `parse_github_url(url: str) -> tuple[str, str]`
  - `load_workspace(path: Path, commit_sha: str = "local") -> Workspace` (applies ignores and caps, finds `app_root`).
  - `clone_repo(url: str, dest: Path) -> Workspace` (`git clone --depth 1`, then `load_workspace`).
  - `detect_stack(ws: Workspace) -> Stack`

- [ ] **Step 1: Write the failing tests**

```python
def test_parse_github_url_variants():
    assert parse_github_url("https://github.com/acme/pawpal") == ("acme", "pawpal")
    assert parse_github_url("https://github.com/acme/pawpal.git") == ("acme", "pawpal")
    assert parse_github_url("github.com/acme/pawpal/tree/main") == ("acme", "pawpal")

def test_parse_github_url_rejects_other_hosts():
    with pytest.raises(UnsupportedRepo, match="public GitHub"):
        parse_github_url("https://gitlab.com/acme/pawpal")

def test_load_workspace_ignores_deps_and_builds(vuln_app_path, tmp_copy):
    root = tmp_copy(vuln_app_path)
    (root / "node_modules/x").mkdir(parents=True); (root / "node_modules/x/a.js").write_text("x")
    (root / "dist").mkdir(); (root / "dist/b.js").write_text("x")
    ws = load_workspace(root)
    assert not any(f.startswith(("node_modules/", "dist/")) for f in ws.files)

def test_detect_stack_vite(vuln_app_path):
    assert detect_stack(load_workspace(vuln_app_path)) == "vite_supabase"

def test_app_root_found_in_subfolder(vuln_app_path, tmp_path):
    shutil.copytree(vuln_app_path, tmp_path / "apps/web")
    ws = load_workspace(tmp_path)
    assert ws.app_root == tmp_path / "apps/web"
    assert detect_stack(ws) == "vite_supabase"

def test_too_many_files(tmp_path):
    for i in range(2001): (tmp_path / f"f{i}.ts").write_text("x")
    with pytest.raises(UnsupportedRepo, match="too big"):
        load_workspace(tmp_path)

def test_unsupported_stack(tmp_path):
    (tmp_path / "main.py").write_text("print(1)")
    with pytest.raises(UnsupportedRepo, match="not supported yet"):
        detect_stack(load_workspace(tmp_path))
```

- [ ] **Step 2:** Run `uv run pytest tests/test_fetch.py -v`. Expected: FAIL on import.
- [ ] **Step 3:** Implement `models.py` and `fetch.py`. Ignore dirs: `node_modules .git dist build .next .vercel coverage public/assets`; ignore binary and image extensions. Cap 2,000 files and 5 MB total. `app_root` is the shallowest directory (max depth 3) holding a `package.json` that depends on `@supabase/supabase-js`. `vite_supabase` when that `package.json` has `vite`; `next_supabase` when it has `next`.
- [ ] **Step 4:** Run the tests. Expected: PASS. Run ruff and pyright.
- [ ] **Step 5:** Commit `feat(engine): models, fetch and stack detection`.

### Task 5: Supabase parsing (migrations replay, config, functions)

**Files:**
- Create: `engine/heist/graph/supabase.py`
- Modify: `engine/heist/models.py` (add DbSchema types)
- Test: `engine/tests/test_supabase_parse.py`

**Interfaces:**
- Produces (in `models.py`):
  - `Policy(name: str, table: str, command: Literal["select","insert","update","delete","all"], roles: list[str], using: str | None, check: str | None, ref: CodeRef)`
  - `Column(name: str, type: str)`
  - `Table(name: str, schema: str, columns: list[Column], rls_enabled: bool, policies: list[Policy], ref: CodeRef)`
  - `Bucket(id: str, public: bool, ref: CodeRef)`
  - `DbSchema(tables: dict[str, Table], buckets: dict[str, Bucket], storage_policies: list[Policy], migration_files: list[str])`
- Produces (in `graph/supabase.py`):
  - `replay_migrations(ws: Workspace) -> DbSchema | None` (None when `supabase/migrations` is missing or empty).
  - `read_function_config(ws: Workspace) -> dict[str, dict[str, Any]]` (from `supabase/config.toml` `[functions.*]`).
  - `list_edge_functions(ws: Workspace) -> dict[str, str]` (function name to entry file path).

- [ ] **Step 1: Write the failing tests**

```python
def test_tables_and_rls(vuln_app_path):
    db = replay_migrations(load_workspace(vuln_app_path))
    assert set(db.tables) >= {"profiles", "pets", "adoption_requests", "messages", "notes"}
    assert db.tables["messages"].rls_enabled is False
    assert db.tables["pets"].policies[0].using == "true"
    assert db.tables["adoption_requests"].policies[0].using == "(auth.uid() IS NOT NULL)"

def test_later_migration_wins(vuln_app_path):
    db = replay_migrations(load_workspace(vuln_app_path))
    usings = [p.using for p in db.tables["notes"].policies]
    assert usings == ["(auth.uid() = user_id)"]

def test_policy_ref_points_at_create_policy_line(vuln_app_path):
    db = replay_migrations(load_workspace(vuln_app_path))
    ref = db.tables["pets"].policies[0].ref
    line = (vuln_app_path / ref.file).read_text().splitlines()[ref.start_line - 1]
    assert "create policy" in line.lower()

def test_buckets(vuln_app_path):
    db = replay_migrations(load_workspace(vuln_app_path))
    assert db.buckets["pet-photos"].public is True
    assert db.buckets["id-documents"].public is False

def test_no_migrations_returns_none(vuln_app_path, tmp_copy):
    root = tmp_copy(vuln_app_path); shutil.rmtree(root / "supabase/migrations")
    assert replay_migrations(load_workspace(root)) is None

def test_function_config_and_list(vuln_app_path):
    ws = load_workspace(vuln_app_path)
    assert read_function_config(ws)["send-email"]["verify_jwt"] is False
    assert set(list_edge_functions(ws)) == {"send-email", "update-request", "ai-describe"}
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement with `pglast.parse_sql` per file, in filename order, handling `CreateStmt`, `AlterTableStmt` (ENABLE/DISABLE ROW LEVEL SECURITY), `CreatePolicyStmt`, `DropStmt` (policy, table), `AlterPolicy`, and `InsertStmt` into `storage.buckets`. Deparse `using`/`check` expressions with `pglast.stream.RawStream` so they compare as strings like above. Line numbers come from statement `stmt_location` offsets. A file pglast cannot parse is skipped and recorded in `DbSchema.migration_files` with a `!` prefix so the UI can say so; it never raises.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit `feat(engine): replay supabase migrations into DbSchema`.

### Task 6: JS/TS graph and the app graph

**Files:**
- Create: `engine/heist/graph/js.py`, `engine/heist/graph/build.py`
- Test: `engine/tests/test_graph.py`

**Interfaces:**
- Consumes: `Workspace`, `replay_migrations`, `list_edge_functions`.
- Produces:
  - `scan_js(ws: Workspace) -> tuple[list[Node], list[Edge]]`
  - `build_app_graph(ws: Workspace, stack: Stack) -> AppGraph`
- Node id scheme (later tasks and the model prompt rely on it): `page:<file>`, `table:<name>`, `policy:<table>:<name>`, `bucket:<id>`, `fn:<name>`, `route:<path>`, `ext:<host>`, `auth:supabase`, `client:<file>:<line>`.
- Zone mapping: page and client_call to `shop_window`, auth to `guard_desk`, function and route to `side_doors`, table and policy to `vault`, bucket to `warehouse`, external_api to `across_road`.

- [ ] **Step 1: Write the failing tests**

```python
def test_graph_links_pages_to_tables_functions_buckets(vuln_app_path):
    ws = load_workspace(vuln_app_path)
    g = build_app_graph(ws, "vite_supabase")
    e = {(x.src, x.dst, x.kind) for x in g.edges}
    assert ("page:src/pages/Pets.tsx", "table:pets", "queries") in e
    assert ("page:src/pages/Requests.tsx", "fn:update-request", "invokes") in e
    assert ("page:src/pages/Upload.tsx", "bucket:id-documents", "uploads") in e
    assert ("fn:ai-describe", "ext:api.openai.com", "calls_external") in e

def test_zones_and_flags(vuln_app_path):
    g = build_app_graph(load_workspace(vuln_app_path), "vite_supabase")
    assert g.node("table:messages").zone == "vault"
    assert g.node("fn:send-email").zone == "side_doors"
    assert g.has_db_rules is True

def test_every_node_ref_exists(vuln_app_path):
    g = build_app_graph(load_workspace(vuln_app_path), "vite_supabase")
    for n in g.nodes:
        if n.ref:
            lines = (vuln_app_path / n.ref.file).read_text().splitlines()
            assert 1 <= n.ref.start_line <= n.ref.end_line <= len(lines)
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement with tree-sitter-typescript (TSX grammar for `.tsx`/`.jsx`). Match call chains `*.from('<lit>')` (table, unless receiver chain includes `.storage`), `*.storage.from('<lit>')`, `*.functions.invoke('<lit>')`, `fetch('<https lit>')` (host only). Edge source is the enclosing page file node, or `fn:<name>` when inside `supabase/functions/<name>/`. Next.js: `app/**/route.ts` and files with `"use server"` become `route:` nodes. Non-literal arguments are skipped, not guessed.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit `feat(engine): build app graph from code and migrations`.

---

## Day 3: Thu Oct 29

All detectors share one signature, registered in `detect/run.py`:
`Detector = Callable[[Workspace, AppGraph], list[Finding]]` and `run_detectors(ws: Workspace, g: AppGraph) -> list[Finding]` (sorted by severity, then mistake number; ids `m<mistake>-<slug>`).
Each test file asserts against the Task 3 table, and a shared test asserts `clean_app` yields no `confirmed` or `proved` findings.

### Task 7: Mistakes 1 and 2 (secrets in the front end)

**Files:**
- Create: `engine/heist/detect/secrets.py`, `engine/heist/detect/run.py`
- Test: `engine/tests/test_detect_secrets.py`, `engine/tests/test_detect_clean.py`

**Interfaces:**
- Produces: `find_frontend_secrets(ws: Workspace, g: AppGraph) -> list[Finding]`, `run_detectors`.

- [ ] **Step 1: Write the failing tests**

```python
def test_flags_openai_key_in_vite_env(vuln_app_path):
    f = findings_for(vuln_app_path, find_frontend_secrets)
    m1 = [x for x in f if x.mistake == 1]
    assert [x.evidence["var"] for x in m1] == ["VITE_OPENAI_API_KEY"]
    assert m1[0].severity == "critical" and m1[0].status == "confirmed"

@pytest.mark.parametrize("line", [
    "VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
    "VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_abc123",
    "VITE_SUPABASE_URL=https://xyz.supabase.co",
])
def test_public_supabase_values_never_flagged(tmp_copy, vuln_app_path, line):
    root = tmp_copy(vuln_app_path); (root / ".env").write_text(line + "\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []

def test_flags_service_role_in_frontend(vuln_app_path):
    m2 = [x for x in findings_for(vuln_app_path, find_frontend_secrets) if x.mistake == 2]
    assert m2[0].refs[0].file == "src/lib/admin.ts"

def test_service_role_jwt_value_flagged_even_if_named_anon(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text("VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.x\n")
    assert any(x.mistake == 2 for x in findings_for(root, find_frontend_secrets))

def test_clean_app_has_no_confirmed_findings(clean_app_path):
    assert [f for f in all_findings(clean_app_path) if f.status != "possible"] == []
```

(`findings_for` and `all_findings` are small helpers in `conftest.py` that load the workspace, build the graph and run one or all detectors.)

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Front-end scope: everything under `app_root` except `supabase/functions/**`, server-only Next files (`route.ts`, `"use server"`, files importing `server-only`). Mistake 1: env vars with `VITE_`/`NEXT_PUBLIC_` prefix whose name matches `KEY|SECRET|TOKEN|PASSWORD` and whose value is not an anon JWT, `sb_publishable_*`, or a URL; plus Gitleaks (`gitleaks detect --no-git --report-format json`) hits inside front-end scope, `source="gitleaks"`, dropping any hit on a line the env-var rule already flagged. Mistake 2: any front-end reference to an env var whose name contains `SERVICE_ROLE`, or any JWT value whose decoded payload has `"role": "service_role"`. Never put the secret value in `evidence`; store the variable name and the first 4 characters only.
- [ ] **Step 4:** Run the tests. Expected: PASS except the clean-app test, which passes after Task 9.
- [ ] **Step 5:** Commit `feat(engine): detect front-end secrets and service role leaks`.

### Task 8: Mistakes 3 and 4 (database and storage rules)

**Files:**
- Create: `engine/heist/detect/rls.py`, `engine/heist/detect/storage.py`
- Test: `engine/tests/test_detect_rls.py`, `engine/tests/test_detect_storage.py`

**Interfaces:**
- Produces: `find_rls_issues(ws, g) -> list[Finding]`, `find_storage_issues(ws, g) -> list[Finding]`. RLS findings carry `evidence = {"table": str, "reason": "rls_off" | "open_to_everyone" | "open_to_any_user", "personal_columns": list[str]}`; Task 16 reads `table`.

- [ ] **Step 1: Write the failing tests**

```python
def test_rls_findings(vuln_app_path):
    f = {x.evidence["table"]: x for x in findings_for(vuln_app_path, find_rls_issues)}
    assert f["messages"].evidence["reason"] == "rls_off" and f["messages"].severity == "critical"
    assert f["adoption_requests"].evidence["reason"] == "open_to_any_user"
    assert f["adoption_requests"].severity == "critical"
    assert f["pets"].evidence["reason"] == "open_to_everyone" and f["pets"].severity == "low"
    assert "profiles" not in f and "notes" not in f

def test_personal_columns_make_open_table_critical(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    p = root / "supabase/migrations/0004_x.sql"
    p.write_text("alter table pets add column owner_email text;")
    f = {x.evidence["table"]: x for x in findings_for(root, find_rls_issues)}
    assert f["pets"].severity == "critical"
    assert f["pets"].evidence["personal_columns"] == ["owner_email"]

def test_no_rules_yields_no_rls_findings(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path); shutil.rmtree(root / "supabase/migrations")
    assert findings_for(root, find_rls_issues) == []

def test_storage_findings(vuln_app_path):
    f = {x.evidence["bucket"]: x for x in findings_for(vuln_app_path, find_storage_issues)}
    assert f["id-documents"].severity == "high"
    assert f["pet-photos"].severity == "low"
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Only `public` schema tables. `open_to_everyone`: a SELECT/ALL policy whose `using` is `true` and whose roles include `public` or `anon`. `open_to_any_user`: `using` is `(auth.uid() IS NOT NULL)` or `(auth.role() = 'authenticated')` with no other condition. Personal columns: name matches `email|phone|address|message|note|body|ssn|dob|birth|secret|token|password` or the table has a `user_id`/`owner_id`/`sender_id` column. Severity: `rls_off` and `open_to_any_user` critical; `open_to_everyone` critical with personal columns, else low. Storage: public bucket low unless its id matches `id|doc|passport|private|invoice|avatar` then high; private bucket with no `storage.objects` policy mentioning its id is high; refs point at the bucket insert line.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit `feat(engine): detect open tables and buckets`.

### Task 9: Mistakes 5, 6 and 7 (Edge Functions and routes)

**Files:**
- Create: `engine/heist/detect/functions.py`, `engine/heist/rules/heist-functions.yml`
- Test: `engine/tests/test_detect_functions.py`

**Interfaces:**
- Produces: `find_function_issues(ws, g) -> list[Finding]`.

- [ ] **Step 1: Write the failing tests**

```python
def test_function_findings(vuln_app_path):
    f = findings_for(vuln_app_path, find_function_issues)
    by = {(x.mistake, x.evidence["function"]) for x in f}
    assert (5, "send-email") in by
    assert (6, "update-request") in by
    assert (7, "ai-describe") in by
    m6 = next(x for x in f if x.mistake == 6)
    assert m6.status == "possible"

def test_verify_jwt_false_is_cited(vuln_app_path):
    m5 = [x for x in findings_for(vuln_app_path, find_function_issues) if x.mistake == 5]
    assert any(r.file == "supabase/config.toml" for r in m5[0].refs)

def test_auth_check_clears_m5_and_m7(clean_app_path):
    f = findings_for(clean_app_path, find_function_issues)
    assert not [x for x in f if x.mistake in (5, 7)]
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Write Semgrep rules: `heist-no-auth-check` (function body with no `auth.getUser(`, `getClaims(`, `req.headers.get("Authorization")` followed by verification), `heist-id-from-request-no-owner` (`.eq("id", $BODY.$X)` or `.eq('id', params.$X)` with no `.eq("user_id", ...)` in the same chain, on a service-role client), `heist-paid-api-no-limit` (fetch to `api.openai.com|api.anthropic.com|generativelanguage.googleapis.com|api.replicate.com|api.meta.ai` in a function with no auth check). Run `semgrep --config engine/heist/rules --json` once over `supabase/functions` and Next route files, and map results to findings; combine m5 with `verify_jwt = false` from config. Semgrep community rules (`p/typescript`) run too, tagged `source="semgrep_community"`, severity from the rule, mistake 0 (they only appear if triage keeps them).
- [ ] **Step 4:** Run all engine tests. Expected: PASS, including `test_clean_app_has_no_confirmed_findings`.
- [ ] **Step 5:** Commit `feat(engine): detect unguarded functions and paid api calls`.

---

## Day 4: Fri Oct 30

### Task 10: Meta client, spend tracking, triage

**Files:**
- Create: `engine/heist/llm/client.py`, `engine/heist/llm/triage.py`, `engine/scripts/bench_triage.py`
- Test: `engine/tests/test_llm_client.py`, `engine/tests/test_triage.py`

**Interfaces:**
- Produces:
  - `class SpendTracker` with `add(model: str, usage: openai.types.CompletionUsage) -> float` (USD for that call) and `.total_usd: float`.
  - `class MetaClient(spark_model: str, open_model: str, tracker: SpendTracker)` built by `MetaClient.from_env()`; method `chat_json(self, which: Literal["spark","open"], system: str, user: str, schema: type[T]) -> T` where `T` is a pydantic model. Uses JSON mode if `docs/meta-models.md` says it works, else instructs JSON and parses. Raises `ModelOutputError(raw: str, errors: str)` on unparseable output.
  - `triage(findings: list[Finding], g: AppGraph, client: MetaClient) -> list[Finding]`

- [ ] **Step 1: Write the failing tests** (with `respx` mocking both endpoints)

```python
def test_chat_json_parses_and_tracks_spend(mock_meta):
    mock_meta.reply('{"ok": true}', prompt_tokens=1_000_000, completion_tokens=0)
    tracker = SpendTracker(); c = MetaClient("spark", "open", tracker)
    assert c.chat_json("spark", "s", "u", Ok).ok is True
    assert tracker.total_usd == pytest.approx(1.25)

def test_chat_json_raises_on_bad_json(mock_meta):
    mock_meta.reply("not json")
    with pytest.raises(ModelOutputError):
        MetaClient("spark", "open", SpendTracker()).chat_json("spark", "s", "u", Ok)

def test_triage_never_drops_heist_findings(vuln_findings, graph, mock_open_drop_all):
    out = triage(vuln_findings, graph, client_for(mock_open_drop_all))
    assert {f.id for f in vuln_findings if f.source == "heist"} <= {f.id for f in out}

def test_triage_falls_back_to_input_when_model_fails(vuln_findings, graph, mock_open_500):
    assert triage(vuln_findings, graph, client_for(mock_open_500)) == vuln_findings
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Triage sends Muse Spark Open a compact list (id, mistake, title, file:line, 3 lines of context) and gets back `TriageOut(groups: list[list[str]], noise: list[str])`. Only `semgrep_community` and `gitleaks` findings can be dropped as noise. Grouped duplicates merge into the first id, unioning `refs`. Prices for Muse Spark Open come from the provider page and live next to the Spark constants.
- [ ] **Step 4:** Run tests. Expected: PASS.
- [ ] **Step 5:** `bench_triage.py` runs triage on `vuln_app` with both models 5 times each and writes median latency, tokens, USD and agreement to `docs/bench.md`. Run it once now, again on Nov 3 for the README.
- [ ] **Step 6:** Commit `feat(engine): meta client, spend tracking, open-weights triage`.

### Task 11: Trace, explain, validate

**Files:**
- Create: `engine/heist/llm/trace.py`, `engine/heist/llm/templates.py`, `engine/heist/validate.py`, `engine/heist/llm/prompts/trace.md`
- Test: `engine/tests/test_validate.py`

**Interfaces:**
- Produces:
  - `StepOut(node_id: str, zone: ZoneId, file: str, line: int, data: str, story: str, why: str, code: str)`
  - `FixOut(explanation: str, diff: str, prompt: str)`
  - `TraceOut(ghost_path: list[StepOut], attack_path: list[StepOut], fix: FixOut)`
  - `trace_finding(f: Finding, g: AppGraph, ws: Workspace, client: MetaClient, feedback: str | None = None) -> TraceOut`
  - `fallback_trace(f: Finding, g: AppGraph) -> TraceOut` (deterministic, from `templates.py`, one template per mistake 1 to 7).
  - `validate_trace(t: TraceOut, f: Finding, g: AppGraph, ws: Workspace) -> tuple[TraceOut, list[str]]` (cleaned trace, error strings).
  - `trace_with_validation(f, g, ws, client) -> tuple[TraceOut, Literal["model","model_retry","fallback"]]`

- [ ] **Step 1: Write the failing tests**

```python
def test_drops_step_with_missing_file(f_messages, graph, ws):
    t = good_trace(f_messages); t.attack_path.append(step(file="src/nope.ts", line=1))
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert len(cleaned.attack_path) == len(t.attack_path) - 1
    assert "src/nope.ts" in errors[0]

def test_drops_step_with_line_past_eof_or_unknown_node(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path += [step(line=99_999), step(node_id="table:ghost")]
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert len(errors) == 2

def test_attack_path_must_reach_the_missing_guard(f_messages, graph, ws):
    t = good_trace(f_messages); t.attack_path = t.attack_path[:1]
    _, errors = validate_trace(t, f_messages, graph, ws)
    assert any("guard" in e for e in errors)

def test_retry_once_with_feedback_then_fallback(f_messages, graph, ws, fake_client):
    fake_client.queue(ModelOutputError("x", "bad"), ModelOutputError("x", "bad"))
    t, how = trace_with_validation(f_messages, graph, ws, fake_client)
    assert how == "fallback" and fake_client.calls == 2
    assert t.attack_path and t.fix.prompt

def test_retry_succeeds(f_messages, graph, ws, fake_client):
    fake_client.queue(bad_trace(f_messages), good_trace(f_messages))
    _, how = trace_with_validation(f_messages, graph, ws, fake_client)
    assert how == "model_retry"
    assert "src/nope.ts" in fake_client.last_feedback

def test_fallback_exists_for_every_mistake(vuln_findings, graph, ws):
    for f in vuln_findings:
        t = fallback_trace(f, graph)
        assert validate_trace(t, f, graph, ws)[1] == []
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Validation rules: `node_id` exists in the graph; `file` is in `ws.files`; `1 <= line <= len(file lines)`; `zone` equals the node's zone (overwrite silently rather than drop); at least one attack step's `file` matches a file in `f.refs` ("attack path never reaches the missing guard"); empty attack path after cleaning is an error. Trace prompt (`prompts/trace.md`) sends the graph as a node and edge list, the full text of every file in `f.refs` and their direct graph neighbours, and the finding; it demands Story in the heist metaphor, Why and Code plain, no exploit scripts, no em dashes, and a fix prompt addressed to the tool that built the app (Lovable for `vite_supabase`, Cursor or v0 for `next_supabase`). Post-process every text field to replace any em dash with " - ".
- [ ] **Step 4:** Run tests. Expected: PASS.
- [ ] **Step 5:** Commit `feat(engine): attack tracing with validation and fallback`.

### Task 12: Scene, pipeline, CLI (Priority 1 milestone)

**Files:**
- Create: `engine/heist/scene.py`, `engine/heist/pipeline.py`, `engine/heist/cli.py`, `shared/scene.schema.json` (generated)
- Test: `engine/tests/test_pipeline.py`

**Interfaces:**
- Produces (in `scene.py`):
  - `PathStep(zone: ZoneId, ref: CodeRef, node_id: str, data: str, story: str, why: str, code: str)`
  - `Fix(explanation: str, diff: str, prompt: str)`
  - `ProofRow(as_who: Literal["anonymous","another_user"], table: str, row: dict[str, Any])`
  - `SceneFinding(id, mistake, severity, status, title, ghost_path: list[PathStep], attack_path: list[PathStep], guard_ref: CodeRef, proof_rows: list[ProofRow], fix: Fix, trace_source: Literal["model","model_retry","fallback"])`
  - `SceneZone(id: ZoneId, active: bool, items: list[SceneItem])`, `SceneItem(node_id: str, label: str, kind: str, flagged: bool)`
  - `SceneMeta(repo: str, commit_sha: str, analyzed_at: datetime, stack: Stack, models: dict[str, str], has_db_rules: bool, unparsed_migrations: list[str], checks_held: int)`
  - `Scene(version: Literal[1], zones: list[SceneZone], findings: list[SceneFinding], meta: SceneMeta)`
  - `build_scene(g, findings, traces, proofs, meta) -> Scene`; findings sorted `proved` before `confirmed` before `possible`, then by severity; `findings[0]` is the worst and is what auto-plays. `checks_held` = 7 minus the number of distinct mistakes with a `confirmed` or `proved` finding.
  - `python -m heist.scene --schema` prints the JSON schema.
- Produces (in `pipeline.py`): `run_analysis(source: str, emit: Callable[[ProgressEvent], None], client: MetaClient, prove: Callable[[DbSchema, Workspace, list[str]], dict[str, list[ProofRow]]] | None = None) -> Scene` where `source` is a GitHub URL or a local path (local paths only from the CLI and tests).
- Produces (in `cli.py`): `heist analyze <url-or-path> [--out scene.json] [--offline]` where `--offline` skips the model and uses `fallback_trace` for every finding.

- [ ] **Step 1: Write the failing tests** (fake client returning `fallback_trace` output)

```python
def test_pipeline_vuln_app(vuln_app_path, fake_client):
    events = []
    s = run_analysis(str(vuln_app_path), events.append, fake_client)
    assert s.findings[0].severity == "critical"
    assert {"vault", "side_doors", "warehouse", "shop_window", "across_road"} <= {z.id for z in s.zones if z.active}
    assert [e.kind for e in events][-1] == "done"
    assert any(e.kind == "node_found" and e.data["zone"] == "vault" for e in events)

def test_pipeline_clean_app(clean_app_path, fake_client):
    s = run_analysis(str(clean_app_path), lambda e: None, fake_client)
    assert s.meta.checks_held == 7
    assert all(f.status == "possible" for f in s.findings)

def test_pipeline_without_rules(tmp_copy, vuln_app_path, fake_client):
    root = tmp_copy(vuln_app_path); shutil.rmtree(root / "supabase/migrations")
    s = run_analysis(str(root), lambda e: None, fake_client)
    assert s.meta.has_db_rules is False

def test_unsupported_repo_emits_error(tmp_path, fake_client):
    (tmp_path / "main.py").write_text("x"); events = []
    with pytest.raises(UnsupportedRepo):
        run_analysis(str(tmp_path), events.append, fake_client)
    assert events[-1].kind == "error" and "not supported yet" in events[-1].message

def test_schema_is_current():
    assert json.loads(Path("../shared/scene.schema.json").read_text()) == Scene.model_json_schema()
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Stage order and `stage` messages: "Fetching the repo", "Mapping the app", "Checking the locks", "Sorting the findings", "Planning the heist", "Proving it", "Done". Emit `node_found` per graph node with `{"zone", "label"}` and `finding` per finding. Trace findings in parallel with a thread pool of 4. `prove` is optional; when None or when a proof errors, the finding stays `confirmed`.
- [ ] **Step 4:** Generate the schema: `uv run python -m heist.scene --schema > ../shared/scene.schema.json`. Generate the web test fixtures: `uv run heist analyze tests/fixtures/vuln_app --offline --out ../web/tests/fixtures/vuln-scene.json` and the same for `clean_app` into `clean-scene.json`. Run tests. Expected: PASS.
- [ ] **Step 5:** Real run: `uv run heist analyze <demo app GitHub URL> --out ../docs/demo-scene.json` with the real Meta client. Check by eye that the worst finding's Story reads well and that `trace_source` is `model` for most findings. If the Lovable app has fewer than two critical findings, add the missing mistakes in Lovable with plain prompts (for example "make requests visible to all logged-in users") and note each one in `docs/demo-app.md`.
- [ ] **Step 6:** Commit `feat(engine): scene builder, pipeline and cli`.

---

## Day 5: Sat Oct 31

### Task 13: The city map

**Files:**
- Create: `web/lib/scene.gen.ts` (generated), `web/components/map/layout.ts`, `web/components/map/CityMap.tsx`, `web/components/map/Zone.tsx`, `web/components/map/Paths.tsx`, `engine/scripts/gen_art.py`, `web/public/art/*`
- Test: `web/components/map/layout.test.ts`, `web/components/map/CityMap.test.tsx`

**Interfaces:**
- Consumes: `Scene`, `SceneZone`, `PathStep` from `@/lib/scene.gen`.
- Produces:
  - `ZONES: Record<ZoneId, { origin: [number, number]; size: [number, number]; label: string; slots: number }>` (grid units; `vault` has 12 slots, `side_doors` 8, `warehouse` 6).
  - `isoToScreen(x: number, y: number): { x: number; y: number }` with 2:1 isometric projection, tile 64x32 px.
  - `itemPosition(zone: ZoneId, slotIndex: number): { x: number; y: number }` (overflow items share the last slot with a "+N" label).
  - `<CityMap scene={Scene} highlight?: { nodeId?: string; zone?: ZoneId } ghost?: PathStep[] attack?: PathStep[] progress?: number />` where `progress` (0 to 1) draws a partial attack line.

- [ ] **Step 1: Write the failing tests**

```ts
test("isoToScreen projects 2:1", () => {
  expect(isoToScreen(1, 0)).toEqual({ x: 32, y: 16 });
  expect(isoToScreen(0, 1)).toEqual({ x: -32, y: 16 });
});
test("zones never overlap", () => { /* pairwise rectangle check over ZONES */ });
test("inactive zones render greyed", () => {
  render(<CityMap scene={fixtureScene({ warehouse: false })} />);
  expect(screen.getByTestId("zone-warehouse")).toHaveAttribute("data-active", "false");
});
test("one vault box per table", () => {
  render(<CityMap scene={vulnScene} />);
  expect(screen.getAllByTestId(/^item-table:/)).toHaveLength(5); // profiles, pets, adoption_requests, messages, notes
});
```

(`vulnScene` and `cleanScene` import `web/tests/fixtures/{vuln,clean}-scene.json` from Task 12; `fixtureScene` builds a small Scene in the test helpers.)

- [ ] **Step 1b:** `pnpm gen:scene` to create `lib/scene.gen.ts`.
- [ ] **Step 2:** Run `pnpm test`. Expected: FAIL.
- [ ] **Step 3:** Implement. Layout reading order left to right: street, shop window, guard desk, side doors, vault at the back, warehouse beside the vault, across the road on the far side of the street. Flagged items glow red; inactive zones at 30% opacity with "Not used by this app". The SVG uses a `viewBox` and scales to the container; the whole map stays legible at 1280x720 (video size) and at 390 px wide (stacks the panel under the map).
- [ ] **Step 4:** Run tests. Expected: PASS. Check in the browser pane at 1280x720 and 390x844 with `demo-scene.json`, screenshot both.
- [ ] **Step 5:** Art. If Task 2 found Muse Image on the API, `gen_art.py` generates one isometric tile per zone plus the attacker and visitor sprites in one fixed style prompt (recorded in the script) into `web/public/art/`. If not, generate them by hand in the Meta AI app with the same prompt and save the files. Zones fall back to flat SVG shapes when an image is missing.
- [ ] **Step 6:** Commit `feat(web): fixed isometric city map`.

### Task 14: Replay, step player, panels

**Files:**
- Create: `web/lib/timeline.ts`, `web/components/replay/Replay.tsx`, `web/components/replay/StepPlayer.tsx`, `web/components/panels/StepPanel.tsx`, `web/components/panels/FindingsList.tsx`, `web/components/panels/ProofRows.tsx`
- Test: `web/lib/timeline.test.ts`, `web/components/panels/StepPanel.test.tsx`

**Interfaces:**
- Produces:
  - `type TimelineEvent = { at: number; kind: "ghost" | "attack" | "proof" | "lock-held" | "end"; stepIndex?: number; zone?: ZoneId }`
  - `buildTimeline(finding: SceneFinding | null, scene: Scene): TimelineEvent[]`
  - `<Replay scene finding autoPlay />` (drives `CityMap` from the timeline), `<StepPlayer steps index onIndex />` (play, pause, back, forward, keyboard arrows and space), `<StepPanel step />` (tabs "Story", "Why", "Code"; Code shows `file:start-end`, the snippet, and `data`), `<FindingsList findings selectedId onSelect />` (status badge; `possible` drawn dashed with "Possible, not confirmed"), `<ProofRows rows />`.

- [ ] **Step 1: Write the failing tests**

```ts
test("ghost steps come before attack steps", () => {
  const t = buildTimeline(worst(vulnScene), vulnScene);
  const firstAttack = t.findIndex(e => e.kind === "attack");
  expect(t.slice(0, firstAttack).every(e => e.kind === "ghost")).toBe(true);
});
test("replay lasts 20 to 30 seconds", () => {
  for (const f of vulnScene.findings) {
    const end = buildTimeline(f, vulnScene).at(-1)!.at;
    expect(end).toBeGreaterThanOrEqual(20_000);
    expect(end).toBeLessThanOrEqual(30_000);
  }
});
test("proved findings end on the proof", () => {
  const t = buildTimeline(provedFinding, vulnScene);
  expect(t.at(-2)!.kind).toBe("proof");
});
test("clean app: every active door holds", () => {
  const t = buildTimeline(null, cleanScene);
  expect(t.filter(e => e.kind === "lock-held").map(e => e.zone))
    .toEqual(["guard_desk", "side_doors", "vault", "warehouse"]);
});
test("story tab is default and tabs switch", async () => { /* render StepPanel, click Why, assert why text */ });
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `buildTimeline`: base durations ghost 1,500 ms per step, attack 3,000 ms per step, proof 5,000 ms, lock-held 2,500 ms per zone, end 1,000 ms; then scale every `at` linearly so the end lands in [20,000, 30,000] ms (target 25,000 when outside). Replay uses `motion` for the walking sprite along the path and the attack line, and shows the current step's Story as a caption under the map.
- [ ] **Step 4:** Run tests. Expected: PASS. In the browser pane, play the demo scene end to end and screenshot the ghost line, a mid-attack frame, and the proof climax. Fix anything that overlaps or clips.
- [ ] **Step 5:** Commit `feat(web): heist replay, step player and panels`.

---

## Day 6: Sun Nov 1

### Task 15: API, live analysis page

**Files:**
- Create: `engine/heist/api.py`, `web/lib/api.ts`, `web/app/page.tsx`, `web/app/a/[id]/page.tsx`
- Test: `engine/tests/test_api.py`, `web/e2e/analyze.spec.ts`

**Interfaces:**
- Produces (HTTP, engine):
  - `POST /analyses` body `{"url": str}` returns `{"id": str, "cached": bool}`; 400 with `{"error": reason}` for `UnsupportedRepo`; 429 for rate limit or spend cap (Task 18 wires those).
  - `GET /analyses/{id}/events` SSE stream of `ProgressEvent` JSON, replaying past events for late subscribers, ending after `done` or `error`.
  - `GET /analyses/{id}` returns `{"status": "running" | "done" | "error", "scene": Scene | null, "error": str | null}`.
- Produces (web): `startAnalysis(url: string): Promise<{ id: string; cached: boolean }>`, `subscribe(id: string, onEvent: (e: ProgressEvent) => void): () => void`, `getAnalysis(id: string)`.

- [ ] **Step 1: Write the failing tests**

```python
async def test_events_replay_for_late_subscriber(client, vuln_app_url_stub):
    r = await client.post("/analyses", json={"url": vuln_app_url_stub}); aid = r.json()["id"]
    await wait_done(client, aid)
    kinds = [e["kind"] async for e in sse(client, f"/analyses/{aid}/events")]
    assert kinds[0] == "stage" and kinds[-1] == "done"

async def test_unsupported_returns_400(client):
    r = await client.post("/analyses", json={"url": "https://gitlab.com/a/b"})
    assert r.status_code == 400 and "public GitHub" in r.json()["error"]
```

```ts
test("paste url, map builds, replay starts", async ({ page }) => {
  await page.goto("/");
  await page.getByPlaceholder("https://github.com/you/your-app").fill(STUB_URL);
  await page.getByRole("button", { name: "Run the heist" }).click();
  await expect(page.getByTestId("zone-vault")).toHaveAttribute("data-active", "true");
  await expect(page.getByTestId("replay")).toHaveAttribute("data-state", "playing", { timeout: 120_000 });
});
```

(`vuln_app_url_stub` patches `clone_repo` to copy the fixture, so tests never hit GitHub.)

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Analyses run in a background task with an in-memory event log per id (Task 18 persists results). Landing page: tagline as the heading, one input, "Run the heist" button, three example repo chips (demo app, clean app, Heist itself). `/a/[id]` shows the map immediately, lights zones and items on `node_found`, shows the current `stage` message, and on `done` loads the Scene and auto-plays the worst finding. Error state shows the reason in plain words.
- [ ] **Step 4:** Run engine tests and `pnpm exec playwright test`. Expected: PASS. Watch one live run in the browser pane on the real demo repo and screenshot mid-analysis.
- [ ] **Step 5:** Commit `feat: live analysis api and page`.

### Task 16: RLS proof in a sandbox (Priority 3)

**Files:**
- Create: `engine/heist/prove/runner.py`, `engine/heist/prove/stub.sql`, `engine/heist/prove/sandbox.py`
- Test: `engine/tests/test_prove.py` (marked `docker`, uses testcontainers Postgres 16)

**Interfaces:**
- Consumes: `DbSchema`, RLS findings' `evidence["table"]`.
- Produces:
  - `run_proof(dsn: str, migration_sql: list[str], tables: list[str]) -> dict[str, list[ProofRow]]` (inside any Postgres; raises `ProofFailed(stage: str, detail: str)`).
  - `prove_rls(db: DbSchema, ws: Workspace, tables: list[str]) -> dict[str, list[ProofRow]]` (runs `run_proof` in a Modal Sandbox from a `postgres:16` image with `block_network=True`, 120 s timeout; returns `{}` on any failure and logs why).

- [ ] **Step 1: Write the failing tests**

```python
def test_proves_open_tables(pg_dsn, vuln_migrations):
    rows = run_proof(pg_dsn, vuln_migrations, ["messages", "adoption_requests", "profiles"])
    assert any(r.as_who == "anonymous" for r in rows["messages"])
    assert any(r.as_who == "another_user" and "Test Alice" in str(r.row) for r in rows["adoption_requests"])
    assert rows["profiles"] == []

def test_only_fake_data(pg_dsn, vuln_migrations):
    rows = run_proof(pg_dsn, vuln_migrations, ["adoption_requests"])
    for r in rows["adoption_requests"]:
        assert all(str(v).endswith("@example.test") for k, v in r.row.items() if "email" in k)

def test_unappliable_migration_raises_proof_failed(pg_dsn):
    with pytest.raises(ProofFailed) as e:
        run_proof(pg_dsn, ["create extension pg_net;", "create table t(id int);"], ["t"])
    assert e.value.stage == "apply"

def test_pipeline_keeps_confirmed_when_proof_fails(vuln_app_path, fake_client):
    s = run_analysis(str(vuln_app_path), lambda e: None, fake_client, prove=lambda *a: {})
    assert all(f.status != "proved" for f in s.findings)
```

- [ ] **Step 2:** Run `uv run pytest -m docker tests/test_prove.py`. Expected: FAIL. (Requires Docker Desktop running; if Docker is unavailable on the Mac, run this file inside a Modal function instead.)
- [ ] **Step 3:** Implement. `stub.sql` recreates what Supabase provides before user migrations: roles `anon`, `authenticated`, `service_role`; schema `auth` with `auth.users(id uuid primary key, email text)`, `auth.uid()` reading `current_setting('request.jwt.claim.sub', true)`, `auth.role()` and `auth.jwt()`; schema `storage` with `buckets` and `objects`; `grant usage on schema public to anon, authenticated` and default privileges granting all on tables to both roles (Supabase's default, which is exactly why RLS matters). Apply each migration in its own transaction; skip statements that create extensions not available, then fail with `stage="apply"` only if a table in `tables` is missing afterwards. Seed: insert Alice and Bob into `auth.users`; for each target table insert 2 rows owned by Alice (owner columns `user_id|owner_id|sender_id|id` referencing her for `profiles`-like tables) with fake values by type and column name ("Test Alice", `alice@example.test`, "555-0100", "Fake note for testing"). Query each table as `anon` (`set role anon`), then as Bob (`set role authenticated`, claim sub = Bob's id) selecting rows owned by Alice. Return at most 3 rows per table.
- [ ] **Step 4:** Run tests. Expected: PASS. Wire `prove_rls` into the API's `run_analysis` call. Run the real demo repo once through Modal and confirm the scene has a `proved` finding with Test Alice rows.
- [ ] **Step 5:** Commit `feat(engine): prove rls leaks with fake data in a sandbox`.

---

## Day 7: Mon Nov 2

### Task 17: Fixes, missing rules, heist failed, badge (Priority 4)

**Files:**
- Create: `web/components/panels/FixCard.tsx`, `web/components/panels/NoRulesCard.tsx`, `web/lib/badge.ts`, `web/app/api/badge/[id]/route.ts`, `engine/heist/prove/check_rules.sql`
- Modify: `web/app/a/[id]/page.tsx`, `web/components/replay/Replay.tsx`
- Test: `web/components/panels/FixCard.test.tsx`, `web/lib/badge.test.ts`

**Interfaces:**
- Consumes: `Scene.meta.checks_held`, `Scene.meta.has_db_rules`, `SceneFinding.fix`.
- Produces: `GET /api/badge/{id}` returns `image/svg+xml`, cache 1 hour; `badgeText(scene: Scene): string` in `web/lib/badge.ts`.

- [ ] **Step 1: Write the failing tests**

```ts
test("clean badge text", () => {
  expect(badgeText(cleanScene)).toBe("Heist-tested: 7/7 locks held");
});
test("failing badge counts held checks", () => {
  expect(badgeText(vulnScene)).toBe(`Heist-tested: ${vulnScene.meta.checks_held}/7 locks held`);
});
test("copy fix prompt copies exact prompt", async () => {
  render(<FixCard fix={f.fix} />);
  await userEvent.click(screen.getByRole("button", { name: "Copy fix prompt" }));
  expect(await navigator.clipboard.readText()).toBe(f.fix.prompt);
});
test("no rules card shows read-only query", () => {
  render(<NoRulesCard />);
  expect(screen.getByRole("heading", { name: "We can't see your database rules" })).toBeVisible();
  expect(screen.getByTestId("check-sql").textContent).not.toMatch(/\b(insert|update|delete|drop|alter|create)\b/i);
});
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. FixCard: plain explanation, the diff in a code block, "Copy fix prompt". NoRulesCard: why it matters in two sentences, the query from `check_rules.sql` (lists `public` tables with `relrowsecurity` and their policies from `pg_policies`, plus `storage.buckets` with `public`), and "Paste this into the SQL editor in your Supabase dashboard." Shown when `has_db_rules` is false, above the findings list. Clean scene: Replay runs the `lock-held` timeline and ends on "Your app held up against all seven checks." with the badge Markdown (`[![Heist-tested](<origin>/api/badge/<id>)](<origin>/a/<id>)`) and a copy button.
- [ ] **Step 4:** Run tests. Expected: PASS. Browser check of a clean run and a no-rules run, screenshots.
- [ ] **Step 5:** Commit `feat(web): fixes, missing-rules card, heist failed replay, badge`.

### Task 18: Cache, guards, deploy

**Files:**
- Create: `engine/heist/store.py`, `engine/heist/guards.py`, `engine/heist/modal_app.py`, `supabase/migrations/0001_heist.sql` (Heist's own database)
- Modify: `engine/heist/api.py`
- Test: `engine/tests/test_guards.py`, `engine/tests/test_store.py`

**Interfaces:**
- Produces:
  - `Store` with `get_by_repo_sha(repo: str, sha: str) -> str | None`, `get(id: str) -> AnalysisRecord | None`, `create(repo: str, sha: str) -> str`, `finish(id: str, scene: Scene) -> None`, `fail(id: str, reason: str) -> None`.
  - `RateLimiter(limit: int = 5, window_s: int = 3600)` with `allow(ip: str) -> bool`.
  - `SpendCap(daily_usd: float = 20.0)` with `allow() -> bool` and `record(usd: float) -> None` (persisted in table `spend_daily(day date primary key, usd numeric)`).

- [ ] **Step 1: Write the failing tests**

```python
def test_rate_limit_counts_only_uncached(client, store):
    for _ in range(5): assert (await post_new(client, ip="1.1.1.1")).status_code == 200
    assert (await post_new(client, ip="1.1.1.1")).status_code == 429
    assert (await post_cached(client, ip="1.1.1.1")).status_code == 200

def test_spend_cap_blocks_new_runs(spend_cap):
    spend_cap.record(20.01)
    assert spend_cap.allow() is False

def test_same_sha_returns_cached(client, store):
    a = (await post_new(client)).json(); b = (await post_new(client)).json()
    assert b["id"] == a["id"] and b["cached"] is True
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Resolve the SHA before cloning with `git ls-remote <url> HEAD`. Concurrent requests for the same repo and SHA join the running analysis. Heist's own tables have RLS enabled with no anon policies (the engine uses the service role server-side only), so Heist passes its own scan. `modal_app.py` serves `api.app` with `@modal.asgi_app()` and secrets `heist-meta`, `heist-supabase`; image installs semgrep and gitleaks. Deploy web to Vercel with `NEXT_PUBLIC_ENGINE_URL` (a URL, so not a secret).
- [ ] **Step 4:** Run tests. Expected: PASS. `modal deploy engine/heist/modal_app.py` and `vercel deploy --prod`; run the demo repo on the production URL in the browser pane and screenshot.
- [ ] **Step 5:** Run Heist on its own public repo. Expected: no confirmed findings. Commit `feat: cache, rate limit, spend cap, deploy`.

---

## Day 8: Tue Nov 3 (feature freeze in the evening)

### Task 19: Share page and video export (Priority 5)

**Files:**
- Create: `web/scripts/export-replay.ts`, `web/app/a/[id]/opengraph-image.tsx`
- Modify: `web/app/a/[id]/page.tsx` (record mode, downloads)
- Test: `web/e2e/record.spec.ts`

**Interfaces:**
- Produces: `/a/{id}?record=1` renders only the map and caption at 1280x720, auto-plays, and sets `document.body.dataset.done = "true"` at the end. `pnpm export --id <id>` writes `exports/<id>.mp4` (H.264, 30 fps) and `exports/<id>.gif` (720 px wide, 12 fps, palette pass) and uploads both to a **private** Supabase bucket `exports` served by signed URLs (a public bucket would trip Heist's own mistake 4).

- [ ] **Step 1: Write the failing test**

```ts
test("record mode finishes within 32s and hides chrome", async ({ page }) => {
  await page.goto(`/a/${DEMO_ID}?record=1`);
  await expect(page.getByTestId("findings-list")).toHaveCount(0);
  await expect(page.locator("body")).toHaveAttribute("data-done", "true", { timeout: 32_000 });
});
```

- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement record mode and the export script (Playwright `recordVideo` at 1280x720, then `ffmpeg -i in.webm -c:v libx264 -pix_fmt yuv420p -r 30 out.mp4` and a two-pass palette GIF). Share page shows "Download MP4" and "Download GIF" when exports exist, and the OG image is a static frame of the map with the finding title.
- [ ] **Step 4:** Run the test. Expected: PASS. Export the demo replay and watch the MP4 and GIF fully; they become the X post and the video hook.
- [ ] **Step 5:** Commit `feat: share page and replay export`.

### Task 20: Template stats (Priority 6) and freeze

**Files:**
- Create: `engine/scripts/scan_templates.py`, `docs/template-stats.md`
- Local only (gitignored): `data/templates.txt`, `data/template-results.jsonl`

**Interfaces:**
- Consumes: `run_analysis`, the real `MetaClient` (or `fallback_trace` only, to save credits; the stats need findings, not explanations).

- [ ] **Step 1:** Collect 30 to 50 public Lovable and Bolt starter templates and showcase repos into `data/templates.txt`.
- [ ] **Step 2:** `scan_templates.py` runs detectors only (no model calls, no proofs) on each, writes per-repo results to the gitignored JSONL, and writes `docs/template-stats.md` with aggregates only: repos scanned, percent with at least one critical finding, percent per mistake, percent with no database rules in the repo. A test in the script asserts no repo name or URL appears in the Markdown output.
- [ ] **Step 3:** Run it. Read the numbers; anything alarming in a specific real repo gets reported privately to its owner later, never published.
- [ ] **Step 4:** Re-run `bench_triage.py` for final numbers. Run all checks (engine pytest, ruff, pyright; web test, lint, typecheck, playwright). Commit `docs: template stats and triage benchmark`.
- [ ] **Step 5:** Feature freeze. From here only bug fixes.

---

## Day 9: Wed Nov 4

### Task 21: Pre-cache, README, video, submit

**Files:**
- Modify: `README.md`
- Create: `docs/video-script.md`

- [ ] **Step 1:** Pre-cache on production: demo app (vulnerable), demo app after the Lovable fix (clean, for the badge), `clean_app` fixture repo, and Heist itself. Confirm each loads from cache with the engine stopped, so judging (Nov 5 to 8) costs nothing.
- [ ] **Step 2:** README: tagline, pitch line, the exported GIF, live link, how it works (the 8 pipeline stages), the Meta model table from spec section 9 with the measured triage numbers from `docs/bench.md`, template stats, safety guardrails, and how to run locally. Note that all work was built during the event.
- [ ] **Step 3:** Record the 3-minute video in your own voice following spec section 12 timing; script in `docs/video-script.md`. The 1:45 segment uses the real Lovable fix and re-run.
- [ ] **Step 4:** Submit on Cerebral Valley by 12:00 PM ET with the public repo, live link and video.
- [ ] **Step 5:** Post the replay clip on X for "Most Viral" and share the community vote link.

---

## Requirement coverage

| Spec requirement | Task |
|---|---|
| Public GitHub only, caps, stack detection, "not supported yet" | 4 |
| App graph from code, migrations, config, functions | 5, 6 |
| Seven mistakes with their statuses | 7, 8, 9 |
| Missing database rules card with read-only query | 12, 17 |
| Muse Spark Open triage, measured cost and speed | 10, 20 |
| Muse Spark trace, three-layer explanations, fix, fix prompt | 11 |
| Validation against real files and lines, retry once, "possible" labeling | 11, 14 |
| RLS proof with fake data, egress off | 16 |
| Scene JSON, deterministic render | 12, 13 |
| Live map during analysis | 15 |
| Fixed map, greyed zones, one box per table | 13 |
| Auto-play worst finding, ghost line, 20 to 30 s, step player, Story/Why/Code | 14 |
| Copy fix prompt, heist failed replay, badge | 17 |
| Share page, MP4 and GIF | 19 |
| Muse Image art | 13 |
| Daily spend cap, rate limit, SHA cache, pre-cached judging repos | 18, 21 |
| No traffic to deployed apps, no exploit scripts, aggregates only | Global Constraints, 11, 16, 20 |
| Demo app in Lovable, template stats, video, X post, submit by noon | 3, 12, 20, 21 |
| Stretch: Muse Code proof agent, XSS/raw SQL/CORS | Not scheduled; only if Day 8 finishes early |

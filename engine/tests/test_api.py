import asyncio
import json
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient, Response

from heist import fetch, pipeline
from heist.api import BUSY_COPY, QUEUED_COPY, ApiConfig, create_app
from heist.fetch import (
    BAD_URL_COPY,
    CLONE_FAILED_COPY,
    UNSUPPORTED_STACK_COPY,
    UnsupportedRepo,
    parse_github_url,
)
from heist.guards import RATE_LIMIT_COPY, SPEND_CAP_COPY, RateLimiter, SpendCap
from heist.llm.client import MetaClient
from heist.pipeline import GENERIC_ERROR_COPY
from heist.store import MemoryStore

from .stub_repos import (
    FIXTURES_DIR,
    STUB_OWNER,
    STUB_SHA,
    make_stub_clone,
    stub_url,
    write_plain_vite_app,
)

VULN_URL = stub_url("vuln-app")
CLEAN_URL = stub_url("clean-app")
PLAIN_URL = stub_url("plain-vite")


@pytest.fixture
def gate() -> threading.Event:
    g = threading.Event()
    g.set()
    return g


@pytest.fixture
def clones(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, gate: threading.Event) -> list[str]:
    """Stubs clone_repo with the fixtures; returns the URLs it was asked to clone."""
    repos = {
        VULN_URL: FIXTURES_DIR / "vuln_app",
        CLEAN_URL: FIXTURES_DIR / "clean_app",
        PLAIN_URL: write_plain_vite_app(tmp_path / "plain"),
    }
    stub = make_stub_clone(repos, gate)
    seen: list[str] = []

    def recording(url: str, dest: Path, sha: str | None = None):
        seen.append(url)
        return stub(url, dest, sha)

    monkeypatch.setattr(pipeline, "clone_repo", recording)
    return seen


@pytest.fixture
def vuln_app_url_stub(clones: list[str]) -> str:
    return VULN_URL


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    app = create_app(ApiConfig(offline=True, origins=["http://localhost:3000"]))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def sse(client: AsyncClient, path: str) -> AsyncIterator[dict[str, Any]]:
    """The ProgressEvents of one SSE stream, in order, until the server closes it."""
    async with client.stream("GET", path) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        async for line in r.aiter_lines():
            if line.startswith("data:"):
                yield json.loads(line.removeprefix("data:").strip())


async def collect(client: AsyncClient, aid: str) -> list[dict[str, Any]]:
    return [e async for e in sse(client, f"/analyses/{aid}/events")]


async def wait_done(client: AsyncClient, aid: str) -> list[dict[str, Any]]:
    """Waits for the run to finish by reading its stream to the end."""
    return await asyncio.wait_for(collect(client, aid), timeout=60)


async def start(client: AsyncClient, url: str) -> str:
    r = await client.post("/analyses", json={"url": url})
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def test_events_replay_for_late_subscriber(client, vuln_app_url_stub):
    r = await client.post("/analyses", json={"url": vuln_app_url_stub})
    aid = r.json()["id"]
    assert r.json()["cached"] is False
    await wait_done(client, aid)
    kinds = [e["kind"] async for e in sse(client, f"/analyses/{aid}/events")]
    assert kinds[0] == "stage" and kinds[-1] == "done"


async def test_unsupported_returns_400(client):
    r = await client.post("/analyses", json={"url": "https://gitlab.com/a/b"})
    assert r.status_code == 400 and "public GitHub" in r.json()["error"]


async def test_live_and_late_subscribers_get_the_same_events(client, clones, gate):
    gate.clear()
    aid = await start(client, VULN_URL)
    live = asyncio.create_task(collect(client, aid))
    await asyncio.sleep(0.05)  # the live subscriber is connected while the run is held
    assert not live.done()
    gate.set()
    live_events = await asyncio.wait_for(live, timeout=60)
    late_events = await wait_done(client, aid)
    assert live_events == late_events
    kinds = [e["kind"] for e in late_events]
    assert kinds.count("done") == 1 and kinds[-1] == "done"
    assert "node_found" in kinds and "finding" in kinds
    found = next(e for e in late_events if e["kind"] == "node_found")
    assert set(found["data"]) == {"zone", "label", "node_id", "kind"}


async def test_get_returns_the_scene_when_done(client, vuln_app_url_stub):
    aid = await start(client, vuln_app_url_stub)
    events = await wait_done(client, aid)
    r = await client.get(f"/analyses/{aid}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "done" and body["error"] is None
    assert body["url"] == VULN_URL
    scene = body["scene"]
    assert scene["meta"]["repo"] == VULN_URL
    assert len(scene["findings"]) == events[-1]["data"]["findings"] > 0


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/a/b",
        "not a url",
        "/etc",
        str(FIXTURES_DIR / "vuln_app"),
        "file:///etc/passwd",
    ],
)
async def test_non_github_and_local_paths_400_without_a_run(client, clones, url):
    r = await client.post("/analyses", json={"url": url})
    assert r.status_code == 400
    assert r.json() == {"error": BAD_URL_COPY}
    assert clones == []


async def test_unsupported_stack_ends_in_error(client, clones):
    aid = await start(client, PLAIN_URL)
    events = await wait_done(client, aid)
    assert events[-1] == {"kind": "error", "message": UNSUPPORTED_STACK_COPY, "data": {}}
    body = (await client.get(f"/analyses/{aid}")).json()
    assert body == {
        "status": "error",
        "scene": None,
        "error": UNSUPPORTED_STACK_COPY,
        "url": PLAIN_URL,
    }


async def test_same_url_while_running_returns_the_same_id(client, clones, gate):
    gate.clear()
    first = await client.post("/analyses", json={"url": VULN_URL})
    again = await client.post("/analyses", json={"url": "github.com/Heist-Fixtures/vuln-app.git"})
    assert again.status_code == 200
    assert again.json() == {"id": first.json()["id"], "cached": False}
    assert (await client.get(f"/analyses/{first.json()['id']}")).json()["status"] == "running"
    gate.set()
    await wait_done(client, first.json()["id"])
    assert len(clones) == 1
    # Once it has finished, the same commit is served from the cache.
    cached = await client.post("/analyses", json={"url": VULN_URL})
    assert cached.json() == {"id": first.json()["id"], "cached": True}
    assert len(clones) == 1


async def test_a_failing_client_ends_the_run_in_error(monkeypatch: pytest.MonkeyPatch, clones):
    def broken(cls: type[MetaClient], *args: Any, **kwargs: Any) -> MetaClient:
        raise RuntimeError("no client today")

    monkeypatch.setattr(MetaClient, "from_env", classmethod(broken))
    app = create_app(ApiConfig(offline=False, origins=[]))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        aid = await start(c, VULN_URL)
        events = await wait_done(c, aid)
        assert events[-1] == {"kind": "error", "message": GENERIC_ERROR_COPY, "data": {}}
        body = (await c.get(f"/analyses/{aid}")).json()
        assert body["status"] == "error" and body["error"] == GENERIC_ERROR_COPY
        # Not stuck as running: the same URL starts a fresh run.
        assert await start(c, VULN_URL) != aid
    assert clones == []


async def test_a_queued_run_says_it_is_waiting(client, clones, gate):
    gate.clear()
    first = await start(client, VULN_URL)
    second = await start(client, CLEAN_URL)
    queued = await start(client, PLAIN_URL)
    gate.set()
    first_events = await wait_done(client, first)
    queued_events = await wait_done(client, queued)
    await wait_done(client, second)
    assert queued_events[0] == {"kind": "stage", "message": QUEUED_COPY, "data": {}}
    assert queued_events[1]["message"] == "Fetching the repo"
    assert all(e["message"] != QUEUED_COPY for e in first_events)


async def test_unknown_id_404(client):
    r = await client.get("/analyses/nope")
    assert r.status_code == 404 and r.json()["error"]
    r = await client.get("/analyses/nope/events")
    assert r.status_code == 404 and r.json()["error"]


async def test_cors_allows_only_the_web_origins(client):
    ok = await client.options(
        "/analyses",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    other = await client.options(
        "/analyses",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in other.headers


def test_registry_drops_finished_records_first():
    from heist.api import AnalysisRecord, LiveRegistry

    registry = LiveRegistry(limit=3)
    records = [AnalysisRecord(id=str(i), url=f"u{i}") for i in range(4)]
    for r in records[:3]:
        registry.add(r)
    assert not registry.has_room()
    records[1].status = "done"
    assert registry.has_room()
    registry.add(records[3])
    assert [r.id for r in registry.records()] == ["0", "2", "3"]


def test_registry_never_evicts_a_running_record():
    from heist.api import AnalysisRecord, LiveRegistry, RegistryFull

    registry = LiveRegistry(limit=2)
    registry.add(AnalysisRecord(id="a", url="u"))
    registry.add(AnalysisRecord(id="b", url="u"))
    with pytest.raises(RegistryFull):
        registry.add(AnalysisRecord(id="c", url="u"))
    assert [r.id for r in registry.records()] == ["a", "b"]


def test_config_refuses_to_start_without_a_key(monkeypatch: pytest.MonkeyPatch):
    from heist import api
    from heist.cli import NO_KEY_COPY

    monkeypatch.setattr(api, "load_env", lambda path: None)
    monkeypatch.delenv("OPEN_API_KEY", raising=False)
    monkeypatch.delenv("HEIST_OFFLINE", raising=False)
    with pytest.raises(SystemExit, match=NO_KEY_COPY):
        ApiConfig.from_env()
    monkeypatch.setenv("HEIST_OFFLINE", "1")
    monkeypatch.setenv("HEIST_WEB_ORIGINS", "http://a.test, http://b.test")
    monkeypatch.delenv("HEIST_TRUSTED_PROXY_HOPS", raising=False)
    assert ApiConfig.from_env() == ApiConfig(
        offline=True, origins=["http://a.test", "http://b.test"]
    )


def test_offline_config_default_origins(monkeypatch: pytest.MonkeyPatch):
    from heist import api

    monkeypatch.setattr(api, "load_env", lambda path: None)
    monkeypatch.setenv("HEIST_OFFLINE", "1")
    monkeypatch.delenv("HEIST_WEB_ORIGINS", raising=False)
    origins = ApiConfig.from_env().origins
    assert origins == ["http://localhost:3000", "http://127.0.0.1:3000"]


@pytest.mark.parametrize(
    ("raw", "want"),
    [(None, None), ("", None), ("modal", "modal"), ("docker", "docker"), (" Docker ", "docker")],
)
def test_prover_comes_from_heist_prover(monkeypatch: pytest.MonkeyPatch, raw, want):
    from heist import api

    monkeypatch.setattr(api, "load_env", lambda path: None)
    monkeypatch.setenv("HEIST_OFFLINE", "1")
    if raw is None:
        monkeypatch.delenv("HEIST_PROVER", raising=False)
    else:
        monkeypatch.setenv("HEIST_PROVER", raw)
    assert ApiConfig.from_env().prover == want


def test_unknown_prover_refuses_to_start(monkeypatch: pytest.MonkeyPatch):
    from heist import api

    monkeypatch.setattr(api, "load_env", lambda path: None)
    monkeypatch.setenv("HEIST_OFFLINE", "1")
    monkeypatch.setenv("HEIST_PROVER", "lambda")
    with pytest.raises(SystemExit, match=api.BAD_PROVER_COPY):
        ApiConfig.from_env()


def test_prover_names_map_to_the_sandboxes():
    from heist.api import prover_fn
    from heist.prove.sandbox import prove_local, prove_rls

    assert prover_fn(None) is None
    assert prover_fn("modal") is prove_rls
    assert prover_fn("docker") is prove_local


async def test_the_chosen_prover_runs_and_proves(monkeypatch: pytest.MonkeyPatch, clones):
    from heist import api
    from heist.scene import ProofRow

    asked: list[list[str]] = []
    row = ProofRow(as_who="anonymous", table="messages", row={"body": "Fake note for testing"})

    def fake_local(db, ws, tables):
        asked.append(tables)
        return {"messages": [row]}

    monkeypatch.setattr(api, "prove_local", fake_local)
    app = create_app(ApiConfig(offline=True, origins=[], prover="docker"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        aid = await start(c, VULN_URL)
        await wait_done(c, aid)
        scene = (await c.get(f"/analyses/{aid}")).json()["scene"]
    assert asked == [["adoption_requests", "messages"]]
    first = scene["findings"][0]
    assert first["id"] == "m3-messages" and first["status"] == "proved"
    assert first["proof_rows"] == [row.model_dump()]


async def test_no_prover_proves_nothing(client, vuln_app_url_stub):
    aid = await start(client, vuln_app_url_stub)
    await wait_done(client, aid)
    scene = (await client.get(f"/analyses/{aid}")).json()["scene"]
    assert all(f["status"] != "proved" for f in scene["findings"])


@pytest.mark.parametrize("prover", [None, "docker", "modal"])
async def test_startup_warms_the_chosen_prover(monkeypatch: pytest.MonkeyPatch, prover):
    from heist import api

    warmed: list[str] = []
    monkeypatch.setattr(api, "warm_in_background", warmed.append)
    app = create_app(ApiConfig(offline=True, origins=[], prover=prover))
    async with app.router.lifespan_context(app):
        pass
    assert warmed == ([prover] if prover else [])


# ---------------------------------------------------------------------------------------------
# Cache, joining and guards (Task 18)

OFFLINE = ApiConfig(offline=True, origins=[])


@asynccontextmanager
async def client_for(app: Any, ip: str = "127.0.0.1") -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app, client=(ip, 4321))
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def shas(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """The commit `git ls-remote` reports per stub URL (default STUB_SHA); tests change it."""
    by_url: dict[str, str] = {}

    def resolve(url: str) -> str:
        owner, repo = parse_github_url(url)
        key = f"https://github.com/{owner}/{repo}".lower()
        if owner.lower() != STUB_OWNER:
            raise UnsupportedRepo(CLONE_FAILED_COPY)
        return by_url.get(key, STUB_SHA)

    monkeypatch.setattr(fetch, "resolve_head", resolve)
    return by_url


async def post(c: AsyncClient, url: str, **headers: str) -> Response:
    return await c.post("/analyses", json={"url": url}, headers=headers)


async def test_same_sha_returns_cached(client, clones):
    a = (await post(client, VULN_URL)).json()
    await wait_done(client, a["id"])
    b = (await post(client, VULN_URL)).json()
    assert b == {"id": a["id"], "cached": True}
    assert len(clones) == 1


async def test_a_new_commit_runs_again(client, clones, shas):
    first = await start(client, VULN_URL)
    await wait_done(client, first)
    shas[VULN_URL] = "1" * 40
    r = (await post(client, VULN_URL)).json()
    assert r["cached"] is False and r["id"] != first
    await wait_done(client, r["id"])
    scene = (await client.get(f"/analyses/{r['id']}")).json()["scene"]
    assert scene["meta"]["commit_sha"] == "1" * 40  # cloned at the commit it is cached under
    assert len(clones) == 2


async def test_rate_limit_counts_only_uncached(clones, shas):
    app = create_app(OFFLINE)
    ids: list[str] = []
    async with client_for(app, ip="1.1.1.1") as c:
        cached = await start(c, VULN_URL)
        await wait_done(c, cached)
        for i in range(4):
            shas[CLEAN_URL] = f"{i + 1:040x}"
            r = await post(c, CLEAN_URL, **{"X-Forwarded-For": f"9.9.9.{i}"})
            assert r.status_code == 200 and r.json()["cached"] is False
            ids.append(r.json()["id"])
        shas[CLEAN_URL] = "f" * 40
        # A forged forwarding header does not make a new client.
        refused = await post(c, CLEAN_URL, **{"X-Forwarded-For": "8.8.8.8"})
        assert refused.status_code == 429
        assert refused.json() == {"error": RATE_LIMIT_COPY}
        again = await post(c, VULN_URL)
        assert again.status_code == 200
        assert again.json() == {"id": cached, "cached": True}
        for aid in ids:
            await wait_done(c, aid)
    async with client_for(app, ip="2.2.2.2") as other:
        r = await post(other, CLEAN_URL)
        assert r.status_code == 200
        await wait_done(other, r.json()["id"])


async def test_joining_a_running_analysis_is_not_counted(clones, gate):
    gate.clear()
    app = create_app(OFFLINE, rate_limiter=RateLimiter(limit=1))
    async with client_for(app) as c:
        first = (await post(c, VULN_URL)).json()
        joined = await post(c, VULN_URL)
        assert joined.status_code == 200
        assert joined.json() == {"id": first["id"], "cached": False}
        assert (await post(c, CLEAN_URL)).status_code == 429
        gate.set()
        await wait_done(c, first["id"])
    assert len(clones) == 1


@pytest.mark.parametrize("error", [UnsupportedRepo(CLONE_FAILED_COPY), RuntimeError("git broke")])
async def test_ls_remote_failure_says_we_could_not_fetch(
    monkeypatch: pytest.MonkeyPatch, clones, error: Exception
):
    def resolve(url: str) -> str:
        raise error

    monkeypatch.setattr(fetch, "resolve_head", resolve)
    app = create_app(OFFLINE, rate_limiter=RateLimiter(limit=1))
    async with client_for(app) as c:
        for _ in range(2):  # not counted against the limit either
            r = await post(c, VULN_URL)
            assert r.status_code == 400 and r.json() == {"error": CLONE_FAILED_COPY}
    assert clones == []


async def test_an_unknown_github_repo_is_refused_before_cloning(client, clones):
    r = await post(client, "https://github.com/someone-else/app")
    assert r.status_code == 400 and r.json() == {"error": CLONE_FAILED_COPY}
    assert clones == []


async def test_cached_result_survives_a_fresh_app(clones):
    store = MemoryStore()
    async with client_for(create_app(OFFLINE, store=store)) as c:
        aid = await start(c, VULN_URL)
        await wait_done(c, aid)
    saved = store.get(aid)
    assert saved is not None and saved.status == "done"
    async with client_for(create_app(OFFLINE, store=store)) as c:
        r = await post(c, VULN_URL)
        assert r.json() == {"id": aid, "cached": True}
        body = (await c.get(f"/analyses/{aid}")).json()
        assert body["status"] == "done" and body["error"] is None
        assert body["url"] == VULN_URL
        assert body["scene"]["meta"]["commit_sha"] == STUB_SHA
        events = await wait_done(c, aid)
        assert [e["kind"] for e in events] == ["done"]
    assert len(clones) == 1


async def test_a_failed_run_is_kept_but_not_cached(clones):
    store = MemoryStore()
    async with client_for(create_app(OFFLINE, store=store)) as c:
        aid = await start(c, PLAIN_URL)
        await wait_done(c, aid)
    async with client_for(create_app(OFFLINE, store=store)) as c:
        body = (await c.get(f"/analyses/{aid}")).json()
        assert body == {
            "status": "error",
            "scene": None,
            "error": UNSUPPORTED_STACK_COPY,
            "url": PLAIN_URL.lower(),
        }
        events = await wait_done(c, aid)
        assert events == [{"kind": "error", "message": UNSUPPORTED_STACK_COPY, "data": {}}]
        r = await post(c, PLAIN_URL)
        assert r.json()["cached"] is False and r.json()["id"] != aid
        await wait_done(c, r.json()["id"])


async def test_running_records_are_never_evicted_and_a_full_registry_says_busy(clones, gate):
    gate.clear()
    app = create_app(OFFLINE, max_records=2)
    async with client_for(app) as c:
        a = await start(c, VULN_URL)
        b = await start(c, CLEAN_URL)
        full = await post(c, PLAIN_URL)
        assert full.status_code == 429 and full.json() == {"error": BUSY_COPY}
        # Joining still works, and both running records are still there.
        assert (await post(c, VULN_URL)).json() == {"id": a, "cached": False}
        assert (await c.get(f"/analyses/{a}")).json()["status"] == "running"
        assert (await c.get(f"/analyses/{b}")).json()["status"] == "running"
        gate.set()
        await wait_done(c, a)
        await wait_done(c, b)
        late = await start(c, PLAIN_URL)  # a finished record makes room
        await wait_done(c, late)


async def test_spend_cap_blocks_new_runs_but_not_cached_ones(clones, shas):
    store = MemoryStore()
    cap = SpendCap(daily_usd=20.0, ledger=store)
    async with client_for(create_app(OFFLINE, store=store, spend_cap=cap)) as c:
        aid = await start(c, VULN_URL)
        await wait_done(c, aid)
        cap.record(20.0)
        shas[CLEAN_URL] = "2" * 40
        r = await post(c, CLEAN_URL)
        assert r.status_code == 503 and r.json() == {"error": SPEND_CAP_COPY}
        assert (await post(c, VULN_URL)).json() == {"id": aid, "cached": True}
    assert len(clones) == 1


class FakeTracker:
    total_usd = 0.75


class FakeClient:
    tracker = FakeTracker()


@pytest.mark.parametrize("fails", [False, True])
async def test_the_spend_of_each_run_is_recorded(monkeypatch: pytest.MonkeyPatch, clones, fails):
    from heist import api

    def fake_from_env(cls: type[MetaClient], *args: Any, **kwargs: Any) -> Any:
        return FakeClient()

    real = api.run_analysis

    def fake_run(source: str, emit: Any, client: Any, prove: Any, **kwargs: Any):
        if fails:
            raise RuntimeError("the model fell over")
        return real(source, emit, None, prove, **kwargs)

    monkeypatch.setattr(MetaClient, "from_env", classmethod(fake_from_env))
    monkeypatch.setattr(api, "run_analysis", fake_run)
    cap = SpendCap(daily_usd=20.0, ledger=MemoryStore())
    app = create_app(ApiConfig(offline=False, origins=[]), spend_cap=cap)
    async with client_for(app) as c:
        aid = await start(c, VULN_URL)
        await wait_done(c, aid)
    for _ in range(100):  # recorded on the worker thread just after the record ends
        if cap.spent_today():
            break
        await asyncio.sleep(0.01)
    assert cap.spent_today() == pytest.approx(0.75)


class BrokenStore(MemoryStore):
    def get_by_repo_sha(self, repo: str, sha: str) -> str | None:
        raise RuntimeError("down")

    def get(self, id: str) -> Any:
        raise RuntimeError("down")

    def create(self, repo: str, sha: str, id: str | None = None) -> str:
        raise RuntimeError("down")

    def finish(self, id: str, scene: Any) -> None:
        raise RuntimeError("down")

    def fail(self, id: str, reason: str) -> None:
        raise RuntimeError("down")


async def test_a_broken_store_never_blocks_an_analysis(clones):
    async with client_for(create_app(OFFLINE, store=BrokenStore())) as c:
        aid = await start(c, VULN_URL)
        events = await wait_done(c, aid)
        assert events[-1]["kind"] == "done"
        assert (await c.get(f"/analyses/{aid}")).json()["status"] == "done"
        assert (await post(c, VULN_URL)).json() == {"id": aid, "cached": True}
        assert (await c.get("/analyses/unknown")).status_code == 404


def test_trusted_proxy_hops_come_from_the_environment(monkeypatch: pytest.MonkeyPatch):
    from heist import api

    monkeypatch.setattr(api, "load_env", lambda path: None)
    monkeypatch.setenv("HEIST_OFFLINE", "1")
    monkeypatch.setenv("HEIST_TRUSTED_PROXY_HOPS", "1")
    assert ApiConfig.from_env().trusted_proxy_hops == 1
    monkeypatch.setenv("HEIST_TRUSTED_PROXY_HOPS", "lots")
    with pytest.raises(SystemExit, match=api.BAD_HOPS_COPY):
        ApiConfig.from_env()

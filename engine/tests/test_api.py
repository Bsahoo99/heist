import asyncio
import json
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from heist import pipeline
from heist.api import QUEUED_COPY, ApiConfig, create_app
from heist.fetch import BAD_URL_COPY, UNSUPPORTED_STACK_COPY
from heist.llm.client import MetaClient
from heist.pipeline import GENERIC_ERROR_COPY

from .stub_repos import FIXTURES_DIR, make_stub_clone, stub_url, write_plain_vite_app

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

    def recording(url: str, dest: Path):
        seen.append(url)
        return stub(url, dest)

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
    # Once it has finished, the same URL runs again.
    rerun = await start(client, VULN_URL)
    assert rerun != first.json()["id"]
    await wait_done(client, rerun)


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


def test_store_keeps_the_most_recent_records():
    from heist.api import AnalysisRecord, AnalysisStore

    store = AnalysisStore(limit=3)
    records = [AnalysisRecord(id=str(i), url=f"u{i}") for i in range(5)]
    for r in records[:4]:
        store.add(r)
    records[1].status = "done"
    store.add(records[4])
    # Finished records go first; then the oldest.
    assert [r.id for r in store.records()] == ["2", "3", "4"]


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

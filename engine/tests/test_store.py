import json
import logging
from datetime import date
from typing import Any

import httpx
import pytest

from heist.pipeline import run_analysis
from heist.scene import Scene
from heist.store import (
    MemoryStore,
    StoredAnalysis,
    SupabaseStore,
    repo_key,
    store_from_env,
)

from .stub_repos import FIXTURES_DIR

KEY = "test-service-role-key-not-real"
JWT_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.not-a-real-signature"
BASE = "https://heist-test.supabase.co"
REPO = "https://github.com/acme/pawpal"
SHA = "a" * 40


@pytest.fixture(scope="module")
def scene() -> Scene:
    s = run_analysis(str(FIXTURES_DIR / "vuln_app"), lambda e: None, None)
    meta = s.meta.model_copy(update={"repo": "https://github.com/Acme/PawPal", "commit_sha": SHA})
    return s.model_copy(update={"meta": meta})


def test_repo_key_is_case_insensitive():
    assert repo_key("https://github.com/Acme/PawPal") == REPO
    assert repo_key("https://github.com/acme/pawpal/") == REPO


# ---------------------------------------------------------------------------------------------
# MemoryStore


def test_memory_store_round_trip(scene: Scene):
    store = MemoryStore()
    aid = store.create(REPO, SHA)
    assert store.get(aid) == StoredAnalysis(aid, REPO, SHA, "running", None, None)
    assert store.get_by_repo_sha(REPO, SHA) is None  # running is not cached
    store.finish(aid, scene)
    assert store.get_by_repo_sha(REPO, SHA) == aid
    got = store.get(aid)
    assert got is not None and got.status == "done" and got.scene == scene


def test_memory_store_failed_runs_are_not_cached():
    store = MemoryStore()
    aid = store.create(REPO, SHA, id="given-id")
    assert aid == "given-id"
    store.fail(aid, "nope", repo=REPO, sha=SHA)
    assert store.get_by_repo_sha(REPO, SHA) is None
    got = store.get(aid)
    assert got is not None and got.status == "error" and got.error == "nope"


def test_memory_store_finish_without_create_still_caches(scene: Scene):
    store = MemoryStore()
    store.finish("late", scene)
    assert store.get_by_repo_sha(REPO, SHA) == "late"


def test_memory_store_is_bounded(scene: Scene):
    store = MemoryStore(limit=2)
    ids = [store.create(REPO, f"{i:040d}") for i in range(3)]
    assert store.get(ids[0]) is None and store.get(ids[2]) is not None


def test_memory_store_spend():
    store = MemoryStore()
    day = date(2026, 11, 3)
    assert store.spend_on(day) == 0.0
    assert store.add_spend(day, 1.5) == 1.5
    assert store.add_spend(day, 2.0) == 3.5
    assert store.spend_on(date(2026, 11, 4)) == 0.0


# ---------------------------------------------------------------------------------------------
# SupabaseStore


class Recorder:
    def __init__(self, reply: Any = None, status: int = 200):
        self.requests: list[httpx.Request] = []
        self.reply = reply
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.reply is None:
            return httpx.Response(self.status)
        return httpx.Response(self.status, json=self.reply)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def _store(rec: Recorder, key: str = KEY) -> SupabaseStore:
    return SupabaseStore(BASE + "/", key, transport=httpx.MockTransport(rec))


def _params(req: httpx.Request) -> dict[str, str]:
    return dict(req.url.params)


def test_supabase_headers_carry_the_key_only_in_headers():
    rec = Recorder(reply=[])
    _store(rec).get_by_repo_sha(REPO, SHA)
    req = rec.last
    assert req.headers["apikey"] == KEY
    # A non-JWT secret key goes in `apikey` only; the gateway rejects it as a bearer token.
    assert "authorization" not in req.headers
    assert KEY not in str(req.url)


def test_supabase_legacy_jwt_key_is_also_the_bearer():
    rec = Recorder(reply=[])
    _store(rec, JWT_KEY).get_by_repo_sha(REPO, SHA)
    assert rec.last.headers["authorization"] == f"Bearer {JWT_KEY}"


def test_supabase_get_by_repo_sha_filters_done_rows():
    rec = Recorder(reply=[{"id": "abc"}])
    assert _store(rec).get_by_repo_sha(REPO, SHA) == "abc"
    req = rec.last
    assert req.method == "GET" and req.url.path == "/rest/v1/analyses"
    assert _params(req) == {
        "select": "id",
        "repo": f"eq.{REPO}",
        "sha": f"eq.{SHA}",
        "status": "eq.done",
        "limit": "1",
    }


def test_supabase_get_parses_the_scene(scene: Scene):
    row = {
        "id": "abc",
        "repo": REPO,
        "sha": SHA,
        "status": "done",
        "scene": scene.model_dump(mode="json"),
        "error": None,
    }
    rec = Recorder(reply=[row])
    got = _store(rec).get("abc")
    assert got == StoredAnalysis("abc", REPO, SHA, "done", scene, None)
    assert _params(rec.last) == {
        "select": "id,repo,sha,status,scene,error",
        "id": "eq.abc",
        "limit": "1",
    }


def test_supabase_get_unknown_and_bad_rows_are_none():
    assert _store(Recorder(reply=[])).get("abc") is None
    bad = [{"id": "abc", "repo": REPO, "sha": SHA, "status": "done", "scene": {"x": 1}}]
    assert _store(Recorder(reply=bad)).get("abc") is None


def test_supabase_create_inserts_a_running_row():
    rec = Recorder(status=201)
    aid = _store(rec).create(REPO, SHA, id="abc")
    assert aid == "abc"
    req = rec.last
    assert req.method == "POST" and req.url.path == "/rest/v1/analyses"
    assert json.loads(req.content) == {"id": "abc", "repo": REPO, "sha": SHA, "status": "running"}
    assert req.headers["prefer"] == "return=minimal"


def test_supabase_finish_upserts_the_whole_row(scene: Scene):
    rec = Recorder(status=201)
    _store(rec).finish("abc", scene)
    req = rec.last
    assert req.method == "POST" and req.url.path == "/rest/v1/analyses"
    assert _params(req) == {"on_conflict": "id"}
    assert req.headers["prefer"] == "resolution=merge-duplicates,return=minimal"
    body = json.loads(req.content)
    assert body["id"] == "abc" and body["status"] == "done" and body["error"] is None
    assert body["repo"] == REPO and body["sha"] == SHA  # from the Scene, normalised
    assert Scene.model_validate(body["scene"]) == scene
    assert body["finished_at"]


def test_supabase_fail_upserts_repo_and_commit_too():
    rec = Recorder(status=201)
    _store(rec).fail("abc", "We couldn't fetch that repo.", repo=REPO, sha=SHA)
    req = rec.last
    # An upsert, so a failed run is kept even when its `create` never reached the database.
    assert req.method == "POST" and req.url.path == "/rest/v1/analyses"
    assert _params(req) == {"on_conflict": "id"}
    assert req.headers["prefer"] == "resolution=merge-duplicates,return=minimal"
    body = json.loads(req.content)
    assert body["id"] == "abc" and body["repo"] == REPO and body["sha"] == SHA
    assert body["status"] == "error" and body["error"] == "We couldn't fetch that repo."
    assert body["finished_at"] and "scene" not in body


def test_supabase_finish_of_an_already_cached_commit_drops_its_own_row(scene: Scene, caplog):
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":  # the unique done index: this commit is already cached
            return httpx.Response(409, json={"code": "23505"})
        return httpx.Response(204)

    SupabaseStore(BASE, KEY, transport=httpx.MockTransport(handler)).finish("abc", scene)
    assert [r.method for r in seen] == ["POST", "DELETE"]
    # Only this run's own unfinished row goes; the cached done row stays.
    assert _params(seen[1]) == {"id": "eq.abc", "status": "neq.done"}
    assert "already cached" in caplog.text
    assert KEY not in caplog.text and BASE not in caplog.text


def test_memory_store_fail_without_create_is_kept():
    store = MemoryStore()
    store.fail("late", "nope", repo=REPO, sha=SHA)
    assert store.get("late") == StoredAnalysis("late", REPO, SHA, "error", None, "nope")


def test_supabase_spend_reads_the_day_and_adds_by_rpc():
    rec = Recorder(reply=[{"usd": 3.25}])
    store = _store(rec)
    assert store.spend_on(date(2026, 11, 3)) == 3.25
    assert rec.last.url.path == "/rest/v1/spend_daily"
    assert _params(rec.last) == {"select": "usd", "day": "eq.2026-11-03"}

    rec.reply = 4.5
    assert store.add_spend(date(2026, 11, 3), 1.25) == 4.5
    req = rec.last
    assert req.method == "POST" and req.url.path == "/rest/v1/rpc/add_spend"
    assert json.loads(req.content) == {"day": "2026-11-03", "usd": 1.25}


def test_supabase_spend_of_an_unseen_day_is_zero():
    assert _store(Recorder(reply=[])).spend_on(date(2026, 11, 3)) == 0.0


def _down(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("boom " + str(request.url))


@pytest.mark.parametrize(
    "transport",
    [
        httpx.MockTransport(_down),
        httpx.MockTransport(lambda r: httpx.Response(500, json={"message": "secret detail"})),
        httpx.MockTransport(lambda r: httpx.Response(200, content=b"not json")),
    ],
)
def test_supabase_failures_never_raise_or_leak(transport, scene: Scene, caplog):
    caplog.set_level(logging.DEBUG)
    store = SupabaseStore(BASE, KEY, transport=transport)
    assert store.get_by_repo_sha(REPO, SHA) is None
    assert store.get("abc") is None
    aid = store.create(REPO, SHA)
    assert aid  # the analysis still gets an id and runs in memory
    store.finish(aid, scene)
    store.fail(aid, "x", repo=REPO, sha=SHA)
    assert store.spend_on(date(2026, 11, 3)) is None
    assert store.add_spend(date(2026, 11, 3), 1.0) is None
    logged = caplog.text
    assert "store" in logged
    for leak in (KEY, BASE, "heist-test", "secret detail", "PawPal", scene.findings[0].title):
        assert leak not in logged


def test_store_from_env_picks_the_backend(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
    assert isinstance(store_from_env(), MemoryStore)
    monkeypatch.setenv("SUPABASE_URL", BASE)
    assert isinstance(store_from_env(), MemoryStore)  # both are needed
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", KEY)
    store = store_from_env()
    assert isinstance(store, SupabaseStore)
    assert KEY not in repr(store)


# ---------------------------------------------------------------------------------------------
# Exported replays (private bucket `exports`, signed links)

NO_EXPORTS = {"mp4": None, "gif": None, "png": None}


def _signed(name: str) -> dict[str, Any]:
    return {
        "error": None,
        "path": name,
        "signedURL": f"/object/sign/exports/{name}?token=tok-{name}",
    }


def _missing(name: str) -> dict[str, Any]:
    return {
        "error": "Either the object does not exist or you do not have access to it",
        "path": name,
        "signedURL": None,
    }


def test_memory_store_has_no_exports():
    assert MemoryStore().export_links("abc") == NO_EXPORTS


def test_supabase_export_links_sign_all_three_in_one_request():
    rec = Recorder(reply=[_signed("abc.mp4"), _signed("abc.gif"), _signed("abc.png")])
    links = _store(rec).export_links("abc")
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == f"{BASE}/storage/v1/object/sign/exports"
    assert json.loads(req.content) == {
        "expiresIn": 3600,
        "paths": ["abc.mp4", "abc.gif", "abc.png"],
    }
    assert req.headers["apikey"] == KEY and "authorization" not in req.headers
    storage = f"{BASE}/storage/v1/object/sign/exports"
    assert links == {
        "mp4": f"{storage}/abc.mp4?token=tok-abc.mp4&download=heist-abc.mp4",
        "gif": f"{storage}/abc.gif?token=tok-abc.gif&download=heist-abc.gif",
        "png": f"{storage}/abc.png?token=tok-abc.png",
    }
    assert all(KEY not in v for v in links.values() if v)


def test_supabase_export_links_send_a_legacy_key_as_the_bearer_too():
    rec = Recorder(reply=[])
    _store(rec, JWT_KEY).export_links("abc")
    assert rec.last.headers["authorization"] == f"Bearer {JWT_KEY}"


def test_supabase_export_links_leave_out_missing_files():
    rec = Recorder(reply=[_signed("abc.mp4"), _missing("abc.gif"), _missing("abc.png")])
    links = _store(rec).export_links("abc")
    assert links["mp4"] is not None and links["gif"] is None and links["png"] is None


@pytest.mark.parametrize(
    "reply",
    [
        [],
        {"message": "not a list"},
        [{"path": "abc.mp4", "signedURL": "https://elsewhere.example/abc.mp4"}],
        [{"path": "abc.mp4", "signedURL": "/object/sign/exports/abc.mp4"}],  # no token
        ["abc.mp4"],
    ],
)
def test_supabase_export_links_odd_replies_are_null(reply: Any):
    assert _store(Recorder(reply=reply)).export_links("abc") == NO_EXPORTS


@pytest.mark.parametrize(
    "transport",
    [
        httpx.MockTransport(_down),
        httpx.MockTransport(
            lambda r: httpx.Response(400, json={"statusCode": "404", "error": "not_found"})
        ),
        httpx.MockTransport(lambda r: httpx.Response(500, json={"message": "secret detail"})),
        httpx.MockTransport(lambda r: httpx.Response(200, content=b"not json")),
    ],
)
def test_supabase_export_links_failures_are_null_and_never_leak(transport, caplog):
    store = SupabaseStore(BASE, KEY, transport=transport)
    with caplog.at_level(logging.INFO):
        assert store.export_links("abc") == NO_EXPORTS
    assert KEY not in caplog.text and "secret detail" not in caplog.text and BASE not in caplog.text

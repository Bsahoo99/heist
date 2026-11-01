"""HTTP API: start an analysis, stream its progress, read its Scene.

Run with `uv run uvicorn heist.api:app --port 8000`. Each analysis runs `run_analysis` in a
worker thread (at most `MAX_RUNNING` at once; later ones wait their turn) and keeps a live
in-memory record: its status, an append-only event log, and the Scene or the error copy.

Starting an analysis first asks GitHub which commit the repo is at (`git ls-remote`). The same
repo at the same commit is never analyzed twice: a finished run is served from the cache
(`cached: true`), and a running one is joined. Only new runs pass the guards: a full registry,
the daily spend cap and the per-client rate limit. Finished and failed runs are written to the
`Store` (Heist's Supabase in production), so results outlive the process.
"""

import asyncio
import logging
import re
import sys
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette import EventSourceResponse

from heist import fetch
from heist.cli import ENV_PATH, NO_KEY_COPY
from heist.fetch import CLONE_FAILED_COPY, UnsupportedRepo, parse_github_url
from heist.guards import (
    RATE_LIMIT_COPY,
    SPEND_CAP_COPY,
    RateLimiter,
    SpendCap,
    client_ip,
)
from heist.llm.client import MetaClient
from heist.llm.config import env, load_env
from heist.models import ProgressEvent
from heist.pipeline import GENERIC_ERROR_COPY, Prove, run_analysis
from heist.prove.sandbox import Prover, prove_local, prove_rls, warm_in_background
from heist.scene import Scene
from heist.store import (
    MemoryStore,
    Store,
    new_id,
    no_export_links,
    repo_key,
    store_from_env,
)

log = logging.getLogger(__name__)

MAX_RUNNING = 2
RESOLVE_TTL_S = 60.0  # how long a repo's commit is remembered between requests
MAX_RESOLVING = 8  # `git ls-remote` subprocesses at once
MAX_RECORDS = 50
DEFAULT_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
NOT_FOUND_COPY = "This analysis is gone. Run it again."
QUEUED_COPY = "Waiting for a free crew"
BUSY_COPY = "Heist is busy with other heists right now. Try again in a few minutes."
BAD_HOPS_COPY = "HEIST_TRUSTED_PROXY_HOPS must be a whole number, 0 or more."
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # ids are `secrets.token_urlsafe(9)`

Status = Literal["running", "done", "error"]
PROVERS: tuple[Prover, ...] = ("modal", "docker")
BAD_PROVER_COPY = "HEIST_PROVER must be modal, docker or unset."


def parse_prover(raw: str | None) -> Prover | None:
    """`HEIST_PROVER`: modal (Modal Sandbox), docker (local container), unset for no proofs."""
    value = (raw or "").strip().lower()
    if not value:
        return None
    for p in PROVERS:
        if value == p:
            return p
    raise SystemExit(BAD_PROVER_COPY)


def parse_hops(raw: str | None) -> int:
    """`HEIST_TRUSTED_PROXY_HOPS`: proxies of our own in front of the engine (see `client_ip`)."""
    value = (raw or "").strip()
    if not value:
        return 0
    if not value.isdigit():
        raise SystemExit(BAD_HOPS_COPY)
    return int(value)


def prover_fn(prover: Prover | None) -> Prove | None:
    if prover is None:
        return None
    return prove_rls if prover == "modal" else prove_local


@dataclass(frozen=True)
class ApiConfig:
    offline: bool
    origins: list[str]
    prover: Prover | None = None
    trusted_proxy_hops: int = 0

    @classmethod
    def from_env(cls) -> "ApiConfig":
        """`HEIST_OFFLINE=1` runs with template traces; otherwise a model key is required.

        `HEIST_PROVER` picks where RLS proofs run (see `parse_prover`); unset proves nothing.
        `HEIST_TRUSTED_PROXY_HOPS` is 0 (unset) on Modal and locally (see `client_ip`).
        """
        load_env(ENV_PATH)
        offline = env("HEIST_OFFLINE") == "1"
        if not offline and not env("OPEN_API_KEY"):
            raise SystemExit(NO_KEY_COPY)
        raw = env("HEIST_WEB_ORIGINS")
        origins = [o.strip() for o in raw.split(",") if o.strip()] if raw else DEFAULT_ORIGINS
        return cls(
            offline=offline,
            origins=origins,
            prover=parse_prover(env("HEIST_PROVER")),
            trusted_proxy_hops=parse_hops(env("HEIST_TRUSTED_PROXY_HOPS")),
        )


@dataclass(eq=False)
class AnalysisRecord:
    """One analysis. Mutated only on the event loop thread."""

    id: str
    url: str
    sha: str = ""
    status: Status = "running"
    events: list[ProgressEvent] = field(default_factory=list)
    scene: Scene | None = None
    error: str | None = None
    spend_usd: float = 0.0
    _subscribers: set[asyncio.Queue[ProgressEvent]] = field(default_factory=lambda: set())

    def publish(self, event: ProgressEvent) -> None:
        self.events.append(event)
        for q in self._subscribers:
            q.put_nowait(event)

    def finish(self, scene: Scene, done: ProgressEvent) -> None:
        # The Scene is set before `done` goes out, so a client that reacts to it can read it.
        self.scene, self.status = scene, "done"
        self.publish(done)

    def fail(self, error: ProgressEvent) -> None:
        self.error, self.status = error.message, "error"
        self.publish(error)

    def subscribe(self) -> tuple[list[ProgressEvent], asyncio.Queue[ProgressEvent]]:
        """The events so far and a queue for the ones after them (no gap: same thread)."""
        q: asyncio.Queue[ProgressEvent] = asyncio.Queue()
        self._subscribers.add(q)
        return list(self.events), q

    def unsubscribe(self, q: asyncio.Queue[ProgressEvent]) -> None:
        self._subscribers.discard(q)


class RegistryFull(Exception):
    """Every live record is still running; none may be dropped."""


class LiveRegistry:
    """The most recent analyses with their live state, in memory, on the event loop thread.

    A running record is never dropped (its worker and subscribers still need it), so when every
    slot is running a new analysis is refused. Finished records go oldest first; the `Store`
    still has them.
    """

    def __init__(self, limit: int = MAX_RECORDS):
        self.limit = limit
        self._records: OrderedDict[str, AnalysisRecord] = OrderedDict()

    def has_room(self) -> bool:
        return len(self._records) < self.limit or any(
            r.status != "running" for r in self._records.values()
        )

    def add(self, record: AnalysisRecord) -> None:
        if not self.has_room():
            raise RegistryFull
        self._records[record.id] = record
        while len(self._records) > self.limit:
            done = next(r for r in self._records.values() if r.status != "running")
            del self._records[done.id]

    def get(self, aid: str) -> AnalysisRecord | None:
        return self._records.get(aid)

    def find(self, repo: str, sha: str) -> AnalysisRecord | None:
        """A running or finished record of this repo (a `repo_key`) at this commit."""
        for r in reversed(self._records.values()):
            if r.status != "error" and r.sha == sha and repo_key(r.url) == repo:
                return r
        return None

    def records(self) -> list[AnalysisRecord]:
        return list(self._records.values())


class StartIn(BaseModel):
    url: str


def _safely[T](op: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T | None:
    """A store call that can never sink an analysis: failures are logged by type only."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - the store is a cache, not a dependency
        log.warning("store %s failed: %s", op, type(exc).__name__)
        return None


def _work(
    record: AnalysisRecord,
    loop: asyncio.AbstractEventLoop,
    offline: bool,
    prove: Prove | None,
    store: Store,
    spend_cap: SpendCap,
) -> None:
    """Runs in a worker thread. Every record change is handed to the event loop."""
    terminal: list[ProgressEvent] = []

    def emit(e: ProgressEvent) -> None:
        if e.kind in ("done", "error"):
            terminal.append(e)  # published below, together with the Scene or the error
        else:
            loop.call_soon_threadsafe(record.publish, e)

    repo = repo_key(record.url)

    def fail(message: str) -> None:
        loop.call_soon_threadsafe(record.fail, ProgressEvent(kind="error", message=message))
        _safely("fail", store.fail, record.id, message, repo=repo, sha=record.sha)

    # The cap is checked again here, when the run really starts: runs admitted before the
    # day's budget ran out may have waited in the queue since.
    if not spend_cap.allow():
        fail(SPEND_CAP_COPY)
        return
    _safely("create", store.create, repo, record.sha, record.id)
    client: MetaClient | None = None
    try:
        # One client per analysis: clients are not shared across threads. Built inside the
        # try, so a failure here still ends the record instead of leaving it running.
        client = None if offline else MetaClient.from_env()
        scene = run_analysis(record.url, emit, client, prove, sha=record.sha or None)
    except Exception as exc:  # noqa: BLE001 - the pipeline already emitted the error copy
        reason = exc.reason if isinstance(exc, UnsupportedRepo) else GENERIC_ERROR_COPY
        error = next((e for e in terminal if e.kind == "error"), None)
        fail(error.message if error else reason)
    else:
        done = next((e for e in terminal if e.kind == "done"), None)
        loop.call_soon_threadsafe(
            record.finish, scene, done or ProgressEvent(kind="done", message="Done")
        )
        _safely("finish", store.finish, record.id, scene)
    finally:
        if client is not None:
            spend = client.tracker.total_usd
            loop.call_soon_threadsafe(setattr, record, "spend_usd", spend)
            spend_cap.record(spend)
            print(f"[heist] analysis {record.id} model spend: ${spend:.4f}", file=sys.stderr)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _done_event(scene: Scene) -> ProgressEvent:
    data: dict[str, Any] = {
        "findings": len(scene.findings),
        "checks_held": scene.meta.checks_held,
        "checks_tested": scene.meta.checks_tested,
    }
    return ProgressEvent(kind="done", message="Done", data=data)


def create_app(
    config: ApiConfig,
    *,
    store: Store | None = None,
    rate_limiter: RateLimiter | None = None,
    spend_cap: SpendCap | None = None,
    max_records: int = MAX_RECORDS,
    resolve_ttl_s: float = RESOLVE_TTL_S,
) -> FastAPI:
    """The engine app. `store` defaults to memory; `store_from_env()` picks Supabase."""
    kept: Store = store if store is not None else MemoryStore()
    limiter = rate_limiter if rate_limiter is not None else RateLimiter()
    cap = spend_cap if spend_cap is not None else SpendCap(ledger=kept)
    registry = LiveRegistry(max_records)
    prove = prover_fn(config.prover)
    pool = ThreadPoolExecutor(max_workers=MAX_RUNNING, thread_name_prefix="heist-analysis")
    tasks: set[asyncio.Future[None]] = set()  # submitted and not finished: running or queued
    # Before any guard runs, every POST asks GitHub for the commit. Remember a repo's commit
    # for a minute and cap the subprocesses, so a burst of requests stays cheap.
    commits: dict[str, tuple[str, float]] = {}
    resolving = asyncio.Semaphore(MAX_RESOLVING)

    async def resolve(url: str, repo: str) -> str:
        now = time.monotonic()
        known = commits.get(repo)
        if known is not None and known[1] > now:
            return known[0]
        async with resolving:
            sha = await asyncio.to_thread(fetch.resolve_head, url)
        if resolve_ttl_s > 0:
            for key in [k for k, (_, until) in commits.items() if until <= now]:
                del commits[key]
            commits[repo] = (sha, now + resolve_ttl_s)
        return sha

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if config.prover is not None:
            # Build the prover image now, off the request path; proofs are skipped until then.
            warm_in_background(config.prover)
        yield
        pool.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(title="Heist engine", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    def live_answer(repo: str, sha: str) -> dict[str, Any] | None:
        record = registry.find(repo, sha)
        if record is None:
            return None
        return {"id": record.id, "cached": record.status == "done"}

    @app.post("/analyses")
    async def start(body: StartIn, request: Request) -> Any:
        # Only public GitHub URLs reach the pipeline, which also reads local paths.
        try:
            owner, name = parse_github_url(body.url)
        except UnsupportedRepo as exc:
            return _error(400, exc.reason)
        url = f"https://github.com/{owner}/{name}"
        repo = repo_key(url)
        try:
            sha = await resolve(url, repo)
        except UnsupportedRepo as exc:
            return _error(400, exc.reason)
        except Exception as exc:  # noqa: BLE001 - whatever went wrong, the repo was not fetched
            log.warning("resolving the commit failed: %s", type(exc).__name__)
            return _error(400, CLONE_FAILED_COPY)

        if (answer := live_answer(repo, sha)) is not None:
            return answer
        cached = await asyncio.to_thread(_safely, "lookup", kept.get_by_repo_sha, repo, sha)
        if cached is not None:
            return {"id": cached, "cached": True}
        allowed = await asyncio.to_thread(cap.allow)
        # No awaits from here on: the checks and the new record are one step on the loop, so
        # two requests for the same commit cannot both start a run.
        if (answer := live_answer(repo, sha)) is not None:
            return answer
        if not registry.has_room():
            return _error(429, BUSY_COPY)
        if not allowed:
            return _error(503, SPEND_CAP_COPY)
        if not limiter.allow(client_ip(request, config.trusted_proxy_hops)):
            return _error(429, RATE_LIMIT_COPY)

        record = AnalysisRecord(id=new_id(), url=url, sha=sha)
        registry.add(record)
        if len(tasks) >= MAX_RUNNING:
            # Every worker is busy: say so, or the page would only show "connecting".
            record.publish(ProgressEvent(kind="stage", message=QUEUED_COPY))
        loop = asyncio.get_running_loop()
        task = loop.run_in_executor(
            pool, _work, record, loop, config.offline, prove, kept, cap
        )
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return {"id": record.id, "cached": False}

    async def lookup(aid: str) -> AnalysisRecord | None:
        """The live record, else a finished one rebuilt from the store (after a restart)."""
        if not ID_RE.match(aid):
            return None
        record = registry.get(aid)
        if record is not None:
            return record
        saved = await asyncio.to_thread(_safely, "get", kept.get, aid)
        if saved is None or saved.status == "running":
            return None  # a run that was cut off with its process is gone: run it again
        url = saved.scene.meta.repo if saved.scene else saved.repo
        rebuilt = AnalysisRecord(id=saved.id, url=url, sha=saved.sha)
        if saved.scene is not None:
            rebuilt.finish(saved.scene, _done_event(saved.scene))
        else:
            rebuilt.fail(ProgressEvent(kind="error", message=saved.error or GENERIC_ERROR_COPY))
        return rebuilt

    @app.get("/analyses/{aid}")
    async def get(aid: str) -> Any:
        record = await lookup(aid)
        if record is None:
            return _error(404, NOT_FOUND_COPY)
        return {
            "status": record.status,
            "scene": record.scene.model_dump(mode="json") if record.scene else None,
            "error": record.error,
            "url": record.url,
        }

    @app.get("/analyses/{aid}/exports")
    async def exports(aid: str) -> Any:
        """Short-lived signed links to the exported replay (MP4, GIF, poster PNG), never cached.

        Only a finished analysis (live or kept in the store) has a replay to export, so nothing
        is signed for any other id: it is a 404 without a Storage call.
        """
        record = await lookup(aid)  # also refuses ids that fail ID_RE
        if record is None or record.status != "done":
            return _error(404, NOT_FOUND_COPY)
        links = await asyncio.to_thread(_safely, "export links", kept.export_links, aid)
        return JSONResponse(links or no_export_links(), headers={"Cache-Control": "no-store"})

    @app.get("/analyses/{aid}/events")
    async def events(aid: str) -> Any:
        record = await lookup(aid)
        if record is None:
            return _error(404, NOT_FOUND_COPY)

        async def stream() -> AsyncIterator[dict[str, str]]:
            past, queue = record.subscribe()
            try:
                for e in past:
                    yield {"data": e.model_dump_json()}
                    if e.kind in ("done", "error"):
                        return
                while True:
                    e = await queue.get()
                    yield {"data": e.model_dump_json()}
                    if e.kind in ("done", "error"):
                        return
            finally:
                record.unsubscribe(queue)

        return EventSourceResponse(stream(), ping=15, headers={"Cache-Control": "no-store"})

    return app


def __getattr__(name: str) -> FastAPI:
    """`heist.api:app`, built on first use so importing this module reads no environment."""
    if name == "app":
        built = create_app(ApiConfig.from_env(), store=store_from_env())
        globals()["app"] = built
        return built
    raise AttributeError(name)

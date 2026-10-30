"""HTTP API: start an analysis, stream its progress, read its Scene.

Run with `uv run uvicorn heist.api:app --port 8000`. Each analysis runs `run_analysis` in a
worker thread (at most `MAX_RUNNING` at once; later ones wait their turn) and keeps an
in-memory record: its status, an append-only event log, and the Scene or the error copy.
"""

import asyncio
import secrets
import sys
from collections import OrderedDict
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette import EventSourceResponse

from heist.cli import ENV_PATH, NO_KEY_COPY
from heist.fetch import UnsupportedRepo, parse_github_url
from heist.llm.client import MetaClient
from heist.llm.config import env, load_env
from heist.models import ProgressEvent
from heist.pipeline import GENERIC_ERROR_COPY, Prove, run_analysis
from heist.prove.sandbox import Prover, prove_local, prove_rls, warm_in_background
from heist.scene import Scene

MAX_RUNNING = 2
MAX_RECORDS = 50
DEFAULT_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
NOT_FOUND_COPY = "This analysis is gone. Run it again."
QUEUED_COPY = "Waiting for a free crew"

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


def prover_fn(prover: Prover | None) -> Prove | None:
    if prover is None:
        return None
    return prove_rls if prover == "modal" else prove_local


@dataclass(frozen=True)
class ApiConfig:
    offline: bool
    origins: list[str]
    prover: Prover | None = None

    @classmethod
    def from_env(cls) -> "ApiConfig":
        """`HEIST_OFFLINE=1` runs with template traces; otherwise a model key is required.

        `HEIST_PROVER` picks where RLS proofs run (see `parse_prover`); unset proves nothing.
        """
        load_env(ENV_PATH)
        offline = env("HEIST_OFFLINE") == "1"
        if not offline and not env("OPEN_API_KEY"):
            raise SystemExit(NO_KEY_COPY)
        raw = env("HEIST_WEB_ORIGINS")
        origins = [o.strip() for o in raw.split(",") if o.strip()] if raw else DEFAULT_ORIGINS
        return cls(offline=offline, origins=origins, prover=parse_prover(env("HEIST_PROVER")))


@dataclass(eq=False)
class AnalysisRecord:
    """One analysis. Mutated only on the event loop thread."""

    id: str
    url: str
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


class AnalysisStore:
    """The most recent analyses, in memory. Task 18 swaps in a persistent store behind this."""

    def __init__(self, limit: int = MAX_RECORDS):
        self.limit = limit
        self._records: OrderedDict[str, AnalysisRecord] = OrderedDict()

    def add(self, record: AnalysisRecord) -> None:
        self._records[record.id] = record
        while len(self._records) > self.limit:
            # Drop the oldest finished record; if every one is still running, the oldest.
            done = next((r for r in self._records.values() if r.status != "running"), None)
            victim = done or next(iter(self._records.values()))
            del self._records[victim.id]

    def get(self, aid: str) -> AnalysisRecord | None:
        return self._records.get(aid)

    def running_for(self, url: str) -> AnalysisRecord | None:
        key = url.lower()
        return next(
            (r for r in self._records.values() if r.status == "running" and r.url.lower() == key),
            None,
        )

    def records(self) -> list[AnalysisRecord]:
        return list(self._records.values())


class StartIn(BaseModel):
    url: str


def _work(
    record: AnalysisRecord, loop: asyncio.AbstractEventLoop, offline: bool, prove: Prove | None
) -> None:
    """Runs in a worker thread. Every record change is handed to the event loop."""
    terminal: list[ProgressEvent] = []

    def emit(e: ProgressEvent) -> None:
        if e.kind in ("done", "error"):
            terminal.append(e)  # published below, together with the Scene or the error
        else:
            loop.call_soon_threadsafe(record.publish, e)

    client: MetaClient | None = None
    try:
        # One client per analysis: clients are not shared across threads. Built inside the
        # try, so a failure here still ends the record instead of leaving it running.
        client = None if offline else MetaClient.from_env()
        scene = run_analysis(record.url, emit, client, prove)
    except Exception as exc:  # noqa: BLE001 - the pipeline already emitted the error copy
        reason = exc.reason if isinstance(exc, UnsupportedRepo) else GENERIC_ERROR_COPY
        error = next((e for e in terminal if e.kind == "error"), None)
        loop.call_soon_threadsafe(record.fail, error or ProgressEvent(kind="error", message=reason))
    else:
        done = next((e for e in terminal if e.kind == "done"), None)
        loop.call_soon_threadsafe(
            record.finish, scene, done or ProgressEvent(kind="done", message="Done")
        )
    finally:
        if client is not None:
            spend = client.tracker.total_usd
            loop.call_soon_threadsafe(setattr, record, "spend_usd", spend)
            print(f"[heist] analysis {record.id} model spend: ${spend:.4f}", file=sys.stderr)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def create_app(config: ApiConfig) -> FastAPI:
    store = AnalysisStore()
    prove = prover_fn(config.prover)
    pool = ThreadPoolExecutor(max_workers=MAX_RUNNING, thread_name_prefix="heist-analysis")
    tasks: set[asyncio.Future[None]] = set()  # submitted and not finished: running or queued

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

    @app.post("/analyses")
    async def start(body: StartIn) -> Any:
        # Only public GitHub URLs reach the pipeline, which also reads local paths.
        try:
            owner, repo = parse_github_url(body.url)
        except UnsupportedRepo as exc:
            return _error(400, exc.reason)
        url = f"https://github.com/{owner}/{repo}"
        running = store.running_for(url)
        if running is not None:
            return {"id": running.id, "cached": False}
        record = AnalysisRecord(id=secrets.token_urlsafe(9), url=url)
        store.add(record)
        if len(tasks) >= MAX_RUNNING:
            # Every worker is busy: say so, or the page would only show "connecting".
            record.publish(ProgressEvent(kind="stage", message=QUEUED_COPY))
        loop = asyncio.get_running_loop()
        task = loop.run_in_executor(pool, _work, record, loop, config.offline, prove)
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return {"id": record.id, "cached": False}

    @app.get("/analyses/{aid}")
    async def get(aid: str) -> Any:
        record = store.get(aid)
        if record is None:
            return _error(404, NOT_FOUND_COPY)
        return {
            "status": record.status,
            "scene": record.scene.model_dump(mode="json") if record.scene else None,
            "error": record.error,
            "url": record.url,
        }

    @app.get("/analyses/{aid}/events")
    async def events(aid: str) -> Any:
        record = store.get(aid)
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
        built = create_app(ApiConfig.from_env())
        globals()["app"] = built
        return built
    raise AttributeError(name)

"""Where finished analyses and the daily model spend are kept, so they outlive the process.

Two backends behind one `Store` protocol:
- `MemoryStore`: the default (tests, local dev). Gone on restart.
- `SupabaseStore`: Heist's own Supabase project (`supabase/migrations/0001_heist.sql`) over
  PostgREST, with the service role key, server side only. Chosen by `store_from_env` when
  `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are both set.

A store is a cache, never a dependency: `SupabaseStore` swallows every failure, logs only the
operation and the error type or HTTP status (never the key, a URL or a Scene), and answers
"unknown" (`None`), so an analysis carries on in memory.

Repos are keyed by `repo_key`: the canonical GitHub URL, lower-cased (GitHub names are not
case sensitive). The live registry in `heist.api` holds what only a running process can hold:
the event log and the subscribers.
"""

import logging
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal, Protocol

import httpx
from pydantic import ValidationError

from heist.llm.config import env
from heist.scene import Scene

log = logging.getLogger(__name__)

Status = Literal["running", "done", "error"]
STATUSES: tuple[Status, ...] = ("running", "done", "error")
MEMORY_LIMIT = 500
SUPABASE_TIMEOUT_S = 5.0


def repo_key(url: str) -> str:
    """`https://github.com/Owner/Repo` -> `https://github.com/owner/repo`."""
    return url.strip().removesuffix("/").lower()


def new_id() -> str:
    return secrets.token_urlsafe(9)


@dataclass(frozen=True)
class StoredAnalysis:
    id: str
    repo: str
    sha: str
    status: Status
    scene: Scene | None
    error: str | None


class SpendLedger(Protocol):
    """Model spend in USD per UTC day. `None` means the backend could not answer."""

    def spend_on(self, day: date) -> float | None: ...

    def add_spend(self, day: date, usd: float) -> float | None: ...


class Store(SpendLedger, Protocol):
    def get_by_repo_sha(self, repo: str, sha: str) -> str | None:
        """The id of a finished analysis of this repo at this commit, if one is kept."""
        ...

    def get(self, id: str) -> StoredAnalysis | None: ...

    def create(self, repo: str, sha: str, id: str | None = None) -> str:
        """Record a running analysis; returns its id (a new one unless `id` is given)."""
        ...

    def finish(self, id: str, scene: Scene) -> None:
        """Mark it done. Repo and commit come from the Scene, so this works without `create`."""
        ...

    def fail(self, id: str, reason: str, *, repo: str, sha: str) -> None:
        """Mark it failed; carries repo and commit, so this too works without `create`."""
        ...


def _now() -> str:
    return datetime.now(UTC).isoformat()


class MemoryStore:
    """A bounded in-memory store. Thread safe: workers write while requests read."""

    def __init__(self, limit: int = MEMORY_LIMIT):
        self.limit = limit
        self._rows: OrderedDict[str, StoredAnalysis] = OrderedDict()
        self._spend: dict[date, float] = {}
        self._lock = threading.Lock()

    def _put(self, row: StoredAnalysis) -> None:
        with self._lock:
            self._rows[row.id] = row
            self._rows.move_to_end(row.id)
            while len(self._rows) > self.limit:
                self._rows.popitem(last=False)

    def get_by_repo_sha(self, repo: str, sha: str) -> str | None:
        with self._lock:
            for row in reversed(self._rows.values()):
                if row.status == "done" and row.repo == repo and row.sha == sha:
                    return row.id
        return None

    def get(self, id: str) -> StoredAnalysis | None:
        with self._lock:
            return self._rows.get(id)

    def create(self, repo: str, sha: str, id: str | None = None) -> str:
        aid = id or new_id()
        self._put(StoredAnalysis(aid, repo, sha, "running", None, None))
        return aid

    def finish(self, id: str, scene: Scene) -> None:
        repo, sha = repo_key(scene.meta.repo), scene.meta.commit_sha
        self._put(StoredAnalysis(id, repo, sha, "done", scene, None))

    def fail(self, id: str, reason: str, *, repo: str, sha: str) -> None:
        self._put(StoredAnalysis(id, repo, sha, "error", None, reason))

    def spend_on(self, day: date) -> float | None:
        with self._lock:
            return self._spend.get(day, 0.0)

    def add_spend(self, day: date, usd: float) -> float | None:
        with self._lock:
            self._spend[day] = self._spend.get(day, 0.0) + usd
            return self._spend[day]


class StoreError(Exception):
    """A failed store call. The message is a safe token: an HTTP status or an error type."""

    def __init__(self, token: str, status: int | None = None):
        super().__init__(token)
        self.status = status


class SupabaseStore:
    """Heist's own tables over PostgREST. Every method is safe to call: none of them raises."""

    def __init__(
        self,
        url: str,
        service_role_key: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = SUPABASE_TIMEOUT_S,
    ):
        # httpx logs every request URL at INFO; these name the project, repos and ids.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        headers = {"apikey": service_role_key, "Content-Type": "application/json"}
        # A legacy service role key is a JWT and also goes in as the bearer token. The newer
        # `sb_secret_` keys are not JWTs: the gateway takes them in `apikey` only.
        if service_role_key.startswith("eyJ"):
            headers["Authorization"] = f"Bearer {service_role_key}"
        self._http = httpx.Client(
            base_url=url.rstrip("/") + "/rest/v1",
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    def __repr__(self) -> str:
        return "SupabaseStore()"  # never the URL or the key

    def _call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        body: Any = None,
        prefer: str | None = None,
    ) -> Any:
        headers = {"Prefer": prefer} if prefer else None
        try:
            r = self._http.request(method, path, params=params, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise StoreError(type(exc).__name__) from None
        if r.status_code >= 400:
            raise StoreError(f"HTTP {r.status_code}", r.status_code)
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            raise StoreError("bad JSON") from None

    def _safe(self, op: str, fn: Any) -> Any:
        try:
            return fn()
        except StoreError as exc:
            log.warning("store %s failed: %s", op, exc)
        except Exception as exc:  # noqa: BLE001 - the store must never sink an analysis
            log.warning("store %s failed: %s", op, type(exc).__name__)
        return None

    def get_by_repo_sha(self, repo: str, sha: str) -> str | None:
        params = {
            "select": "id",
            "repo": f"eq.{repo}",
            "sha": f"eq.{sha}",
            "status": "eq.done",
            "limit": "1",
        }

        def run() -> str | None:
            rows = self._call("GET", "/analyses", params=params)
            return str(rows[0]["id"]) if rows else None

        return self._safe("lookup", run)

    def get(self, id: str) -> StoredAnalysis | None:
        params = {"select": "id,repo,sha,status,scene,error", "id": f"eq.{id}", "limit": "1"}

        def run() -> StoredAnalysis | None:
            rows = self._call("GET", "/analyses", params=params)
            if not rows:
                return None
            return _row(rows[0])

        return self._safe("get", run)

    def create(self, repo: str, sha: str, id: str | None = None) -> str:
        aid = id or new_id()
        body = {"id": aid, "repo": repo, "sha": sha, "status": "running"}
        self._safe("create", lambda: self._call("POST", "/analyses", body=body, prefer="return=minimal"))
        return aid

    def finish(self, id: str, scene: Scene) -> None:
        body = {
            "id": id,
            "repo": repo_key(scene.meta.repo),
            "sha": scene.meta.commit_sha,
            "status": "done",
            "scene": scene.model_dump(mode="json"),
            "error": None,
            "finished_at": _now(),
        }
        # An upsert: a row whose `create` failed is still written in full.
        try:
            self._upsert(body)
        except StoreError as exc:
            if exc.status != 409:
                log.warning("store finish failed: %s", exc)
                return
            # The unique done index: another run of this commit finished first. Its row is
            # the cache; drop this run's own unfinished row so nothing stays `running`.
            log.info("store finish: already cached (%s)", exc)
            self._safe(
                "finish cleanup",
                lambda: self._call(
                    "DELETE",
                    "/analyses",
                    params={"id": f"eq.{id}", "status": "neq.done"},
                    prefer="return=minimal",
                ),
            )
        except Exception as exc:  # noqa: BLE001 - the store must never sink an analysis
            log.warning("store finish failed: %s", type(exc).__name__)

    def _upsert(self, body: dict[str, Any]) -> None:
        self._call(
            "POST",
            "/analyses",
            params={"on_conflict": "id"},
            body=body,
            prefer="resolution=merge-duplicates,return=minimal",
        )

    def fail(self, id: str, reason: str, *, repo: str, sha: str) -> None:
        body = {
            "id": id,
            "repo": repo,
            "sha": sha,
            "status": "error",
            "error": reason,
            "finished_at": _now(),
        }
        self._safe("fail", lambda: self._upsert(body))

    def spend_on(self, day: date) -> float | None:
        params = {"select": "usd", "day": f"eq.{day.isoformat()}"}

        def run() -> float:
            rows = self._call("GET", "/spend_daily", params=params)
            return float(rows[0]["usd"]) if rows else 0.0

        return self._safe("spend read", run)

    def add_spend(self, day: date, usd: float) -> float | None:
        body = {"day": day.isoformat(), "usd": usd}
        return self._safe("spend add", lambda: float(self._call("POST", "/rpc/add_spend", body=body)))


def _row(raw: dict[str, Any]) -> StoredAnalysis | None:
    status = raw.get("status")
    if status not in STATUSES:
        return None
    scene = None
    if raw.get("scene") is not None:
        try:
            scene = Scene.model_validate(raw["scene"])
        except ValidationError:
            log.warning("store get: a stored Scene no longer validates")
            return None
    if status == "done" and scene is None:
        return None
    error = raw.get("error")
    return StoredAnalysis(
        id=str(raw["id"]),
        repo=str(raw.get("repo", "")),
        sha=str(raw.get("sha", "")),
        status=status,
        scene=scene,
        error=str(error) if error is not None else None,
    )


def store_from_env() -> Store:
    """`SupabaseStore` when both Supabase variables are set, else a `MemoryStore`."""
    url, key = env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY")
    if url and key:
        return SupabaseStore(url, key)
    return MemoryStore()

"""Guards on new analyses: a per-client rate limit and a daily cap on model spend.

Both only ever stop new, uncached runs. A cached result or joining a running analysis costs
nothing, so it is always served.
"""

import ipaddress
import logging
import math
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, date, datetime

from starlette.requests import Request

from heist.store import MemoryStore, SpendLedger

log = logging.getLogger(__name__)

RATE_LIMIT = 5
RATE_WINDOW_S = 3600
DAILY_USD = 20.0
MAX_TRACKED_CLIENTS = 10_000

CACHED_STILL_OPEN = "Repos Heist has already checked still open right away."
RATE_LIMIT_COPY = (
    f"You've started {RATE_LIMIT} new heists in the last hour. Try again later. "
    + CACHED_STILL_OPEN
)
SPEND_CAP_COPY = (
    "Heist has used up today's budget for new heists. Try again tomorrow. " + CACHED_STILL_OPEN
)


class RateLimiter:
    """At most `limit` allowed calls per client in any `window_s` seconds (a sliding window).

    In memory, which is right for the single engine container. A refused call is not counted.
    """

    def __init__(
        self,
        limit: int = RATE_LIMIT,
        window_s: int = RATE_WINDOW_S,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_tracked: int = MAX_TRACKED_CLIENTS,
    ):
        self.limit = limit
        self.window_s = window_s
        self._clock = clock
        self._max_tracked = max_tracked
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _expire(self, hits: deque[float], now: float) -> None:
        while hits and hits[0] <= now - self.window_s:
            hits.popleft()

    def allow(self, ip: str) -> bool:
        now = self._clock()
        key = rate_key(ip)
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            self._expire(hits, now)
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > self._max_tracked:
                self._sweep(now)
            return True

    def _sweep(self, now: float) -> None:
        for key in list(self._hits):
            self._expire(self._hits[key], now)
            if not self._hits[key]:
                del self._hits[key]

    def tracked(self) -> int:
        with self._lock:
            return len(self._hits)


def rate_key(ip: str) -> str:
    """The bucket a client is counted in: an IPv4 address, or an IPv6 address's /64.

    A single IPv6 user usually holds a whole /64, so counting addresses would let them rotate.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def utc_today() -> date:
    return datetime.now(UTC).date()


class SpendCap:
    """Stops new runs once the UTC day's model spend reaches `daily_usd`.

    The day's total lives in the ledger (Heist's `spend_daily` table in production, so every
    process and restart sees it). This process also keeps its own tally, used when the ledger
    cannot answer, so a store outage never lifts the cap on what this process spent.
    """

    def __init__(
        self,
        daily_usd: float = DAILY_USD,
        *,
        ledger: SpendLedger | None = None,
        today: Callable[[], date] = utc_today,
    ):
        self.daily_usd = daily_usd
        self._ledger: SpendLedger = ledger if ledger is not None else MemoryStore()
        self._today = today
        self._local: dict[date, float] = {}
        self._lock = threading.Lock()

    def _ledger_total(self, day: date) -> float | None:
        try:
            return self._ledger.spend_on(day)
        except Exception:  # noqa: BLE001 - fall back to this process's own tally
            return None

    def spent_today(self) -> float:
        day = self._today()
        with self._lock:
            local = self._local.get(day, 0.0)
        return max(local, self._ledger_total(day) or 0.0)

    def allow(self) -> bool:
        return self.spent_today() < self.daily_usd

    def record(self, usd: float) -> None:
        if not math.isfinite(usd) or usd <= 0:
            return
        day = self._today()
        with self._lock:
            self._local = {day: self._local.get(day, 0.0) + usd}  # older days drop out
        try:
            self._ledger.add_spend(day, usd)
        except Exception as exc:  # noqa: BLE001 - the local tally still counts it
            log.warning("spend could not be saved: %s", type(exc).__name__)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def client_ip(request: Request, trusted_hops: int = 0) -> str:
    """The address a rate limit should count.

    `trusted_hops=0` (the default, and right on Modal) uses the socket peer. For an
    `@modal.asgi_app` the ASGI `client` is filled from the input's `client_host`
    (`modal/_serialization.py`, modal 1.6.2), which Modal's own ingress sets; headers the
    caller sends are never read, so a forged X-Forwarded-For changes nothing. Smoke check 9 in
    docs/deploy.md confirms this on the live deploy.

    Behind N proxies we run ourselves, `trusted_hops=N` reads the Nth X-Forwarded-For entry
    from the right: the one our outermost proxy wrote. The leftmost entries are whatever the
    client claimed and are never used. Anything that is not an IP falls back to the peer.
    """
    peer = request.client.host if request.client else "unknown"
    if trusted_hops <= 0:
        return peer
    values = [
        part.strip()
        for header in request.headers.getlist("x-forwarded-for")
        for part in header.split(",")
    ]
    if len(values) < trusted_hops:
        return peer
    candidate = values[-trusted_hops]
    return candidate if _is_ip(candidate) else peer

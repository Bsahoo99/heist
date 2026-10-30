from datetime import date

import pytest
from starlette.requests import Request

from heist.guards import RateLimiter, SpendCap, client_ip
from heist.store import MemoryStore


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def spend_cap() -> SpendCap:
    return SpendCap(daily_usd=20.0, ledger=MemoryStore())


def test_spend_cap_blocks_new_runs(spend_cap: SpendCap):
    assert spend_cap.allow() is True
    spend_cap.record(20.01)
    assert spend_cap.allow() is False


def test_spend_cap_blocks_at_exactly_the_cap(spend_cap: SpendCap):
    spend_cap.record(19.99)
    assert spend_cap.allow() is True
    spend_cap.record(0.01)
    assert spend_cap.allow() is False


@pytest.mark.parametrize("bad", [0.0, -5.0, float("nan"), float("inf")])
def test_spend_cap_ignores_nonsense_amounts(spend_cap: SpendCap, bad: float):
    spend_cap.record(bad)
    spend_cap.record(1.0)
    assert spend_cap.spent_today() == pytest.approx(1.0)


def test_spend_cap_rolls_over_at_the_utc_day():
    day = [date(2026, 11, 3)]
    ledger = MemoryStore()
    cap = SpendCap(daily_usd=20.0, ledger=ledger, today=lambda: day[0])
    cap.record(25.0)
    assert cap.allow() is False
    day[0] = date(2026, 11, 4)
    assert cap.allow() is True
    assert cap.spent_today() == 0.0
    assert ledger.spend_on(date(2026, 11, 3)) == pytest.approx(25.0)


def test_spend_cap_reads_what_other_processes_spent():
    ledger = MemoryStore()
    ledger.add_spend(date(2026, 11, 3), 20.0)  # another container, or an earlier deploy
    cap = SpendCap(daily_usd=20.0, ledger=ledger, today=lambda: date(2026, 11, 3))
    assert cap.allow() is False


class DownLedger:
    def spend_on(self, day: date) -> float | None:
        return None

    def add_spend(self, day: date, usd: float) -> float | None:
        return None


class BrokenLedger:
    def spend_on(self, day: date) -> float | None:
        raise RuntimeError("down")

    def add_spend(self, day: date, usd: float) -> float | None:
        raise RuntimeError("down")


@pytest.mark.parametrize("ledger", [DownLedger(), BrokenLedger()])
def test_spend_cap_falls_back_to_its_own_tally(ledger):
    cap = SpendCap(daily_usd=20.0, ledger=ledger)
    assert cap.allow() is True
    cap.record(21.0)
    assert cap.allow() is False


def test_rate_limit_is_per_ip_and_sliding():
    clock = Clock()
    limiter = RateLimiter(limit=5, window_s=3600, clock=clock)
    for _ in range(5):
        assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is False
    assert limiter.allow("2.2.2.2") is True
    clock.now += 3599
    assert limiter.allow("1.1.1.1") is False
    clock.now += 1  # the first five fall out of the window
    assert limiter.allow("1.1.1.1") is True


def test_a_refused_request_does_not_count():
    clock = Clock()
    limiter = RateLimiter(limit=2, window_s=10, clock=clock)
    assert limiter.allow("a") and limiter.allow("a")
    for _ in range(10):
        assert limiter.allow("a") is False
    clock.now += 10
    assert limiter.allow("a") is True


def test_rate_limit_forgets_idle_clients():
    clock = Clock()
    limiter = RateLimiter(limit=1, window_s=10, clock=clock, max_tracked=3)
    for ip in ("a", "b", "c", "d"):
        limiter.allow(ip)
    clock.now += 11
    limiter.allow("e")
    assert limiter.tracked() <= 3


def _request(peer: str | None, *forwarded: str) -> Request:
    headers = [(b"x-forwarded-for", v.encode()) for v in forwarded]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/analyses",
        "headers": headers,
        "client": (peer, 1234) if peer else None,
    }
    return Request(scope)


def test_client_ip_is_the_socket_peer_by_default():
    # Modal hands its web functions the caller's address as the ASGI client and drops any
    # X-Forwarded-For the caller sent, so a forged header must change nothing.
    assert client_ip(_request("203.0.113.9", "6.6.6.6")) == "203.0.113.9"


def test_client_ip_trusts_only_the_hops_it_is_told_to():
    req = _request("10.0.0.1", "6.6.6.6, 198.51.100.4")
    assert client_ip(req, trusted_hops=1) == "198.51.100.4"
    assert client_ip(req, trusted_hops=2) == "6.6.6.6"
    # Several headers read as one list, in order.
    req = _request("10.0.0.1", "6.6.6.6", "198.51.100.4")
    assert client_ip(req, trusted_hops=1) == "198.51.100.4"


@pytest.mark.parametrize(
    ("forwarded", "hops"),
    [((), 1), (("not-an-ip",), 1), (("1.2.3.4, ",), 1), (("1.2.3.4",), 2)],
)
def test_client_ip_falls_back_to_the_peer(forwarded: tuple[str, ...], hops: int):
    # Too few entries for the trusted hops, or garbage: use the socket peer.
    assert client_ip(_request("10.0.0.1", *forwarded), trusted_hops=hops) == "10.0.0.1"


def test_client_ip_without_a_peer():
    assert client_ip(_request(None)) == "unknown"


def test_ipv6_clients_are_counted_per_64_prefix():
    # One home or VM usually gets a whole /64; rotating inside it must not reset the limit.
    limiter = RateLimiter(limit=2, window_s=3600, clock=Clock())
    assert limiter.allow("2001:db8:1:2::1") and limiter.allow("2001:db8:1:2:ffff::9")
    assert limiter.allow("2001:db8:1:2:abcd::1") is False
    assert limiter.allow("2001:db8:1:3::1") is True  # the next /64 is someone else
    # IPv4 stays per address, also when written as an IPv4-mapped IPv6 address.
    assert limiter.allow("192.0.2.1") and limiter.allow("::ffff:192.0.2.1")
    assert limiter.allow("192.0.2.1") is False
    assert limiter.allow("192.0.2.2") is True


def test_guard_copy_is_plain_and_promises_only_cached_results():
    from heist.guards import RATE_LIMIT, RATE_LIMIT_COPY, SPEND_CAP_COPY

    for copy in (RATE_LIMIT_COPY, SPEND_CAP_COPY):
        assert "example" not in copy.lower()
        assert "already checked" in copy
    assert f"{RATE_LIMIT} new heists" in RATE_LIMIT_COPY

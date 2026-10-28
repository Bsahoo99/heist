import json
from pathlib import Path

import httpx
import pytest
import respx

from heist.fetch import detect_stack, load_workspace
from heist.graph.build import build_app_graph
from heist.llm.client import DEFAULT_OPEN_BASE_URL, MetaClient, SpendTracker
from heist.llm.triage import TRIAGE_MAX_TOKENS, triage
from heist.models import CodeRef, Finding
from tests.helpers import all_findings

OPEN_URL = f"{DEFAULT_OPEN_BASE_URL}/chat/completions"


def reply(content: dict) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "x",
            "object": "chat.completion",
            "created": 0,
            "model": "open",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": json.dumps(content)},
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    )


def client() -> MetaClient:
    return MetaClient("spark", "open", SpendTracker(), max_retries=0)


@pytest.fixture
def setup(vuln_app_path: Path):
    ws = load_workspace(vuln_app_path)
    g = build_app_graph(ws, detect_stack(ws))
    return ws, g, all_findings(vuln_app_path)


def mk(id: str, source: str, severity: str = "low", status: str = "possible", line: int = 1):
    return Finding(
        id=id,
        mistake=1,
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        title=id,
        node_ids=[f"n-{id}"],
        refs=[CodeRef(file="a.ts", start_line=line, end_line=line)],
        source=source,  # type: ignore[arg-type]
    )


def test_triage_never_drops_heist_findings(setup):
    ws, g, findings = setup
    with respx.mock() as router:
        router.post(OPEN_URL).mock(
            return_value=reply({"groups": [], "noise": [f.id for f in findings]})
        )
        out = triage(findings, g, ws, client())
    assert {f.id for f in findings if f.source == "heist"} <= {f.id for f in out}


def test_triage_falls_back_to_input_when_model_fails(setup):
    ws, g, findings = setup
    with respx.mock() as router:
        router.post(OPEN_URL).respond(500)
        out = triage(findings, g, ws, client())
    assert out == findings


def test_triage_falls_back_on_garbage_output(setup):
    _ws, g, findings = setup
    with respx.mock() as router:
        router.post(OPEN_URL).respond(
            json={
                "id": "x",
                "object": "chat.completion",
                "created": 0,
                "model": "o",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "nope"},
                    }
                ],
            }
        )
        assert triage(findings, g, setup[0], client()) == findings


def test_triage_merges_group_and_drops_only_community_noise(setup):
    ws, g, _ = setup
    a = mk("a", "gitleaks", "medium", "possible", 1)
    b = mk("b", "semgrep_community", "high", "confirmed", 2)
    c = mk("c", "heist", "low", "proved", 3)
    d = mk("d", "semgrep_community", "low", "possible", 4)
    e = mk("e", "gitleaks", "low", "possible", 5)
    with respx.mock() as router:
        route = router.post(OPEN_URL).mock(
            return_value=reply({"groups": [["a", "b", "ghost"]], "noise": ["c", "d", "ghost"]})
        )
        out = triage([a, b, c, d, e], g, ws, client())
    assert route.call_count == 1
    assert [f.id for f in out] == ["a", "c", "e"]
    merged = out[0]
    assert [r.start_line for r in merged.refs] == [1, 2]
    assert merged.severity == "high"
    assert merged.status == "confirmed"
    assert merged.node_ids == ["n-a", "n-b"]


def test_finding_never_appears_twice(setup):
    ws, g, _ = setup
    a, b, c = mk("a", "gitleaks"), mk("b", "gitleaks"), mk("c", "gitleaks")
    with respx.mock() as router:
        router.post(OPEN_URL).mock(
            return_value=reply({"groups": [["a", "b"], ["b", "c"], ["a", "a"]], "noise": []})
        )
        out = triage([a, b, c], g, ws, client())
    assert [f.id for f in out] == ["a", "c"]


def test_triage_request_contains_context_and_no_extra_fields(setup):
    ws, g, findings = setup
    with respx.mock() as router:
        route = router.post(OPEN_URL).mock(return_value=reply({"groups": [], "noise": []}))
        triage(findings, g, ws, client())
    body = json.loads(route.calls[0].request.content)
    assert body["max_tokens"] == TRIAGE_MAX_TOKENS
    items = json.loads(body["messages"][1]["content"])
    assert len(items) == len(findings)
    assert set(items[0]) == {"id", "mistake", "severity", "title", "source", "where", "code"}
    assert any(i["code"] for i in items)


@pytest.mark.parametrize(
    ("primary", "other", "expected"),
    [
        ("proved", "confirmed", "proved"),
        ("confirmed", "proved", "proved"),
        ("possible", "proved", "proved"),
        ("possible", "confirmed", "confirmed"),
        ("confirmed", "possible", "confirmed"),
    ],
)
def test_merge_keeps_strongest_status(setup, primary, other, expected):
    ws, g, _ = setup
    a, b = mk("a", "gitleaks", status=primary), mk("b", "gitleaks", status=other)
    with respx.mock() as router:
        router.post(OPEN_URL).mock(return_value=reply({"groups": [["a", "b"]], "noise": []}))
        out = triage([a, b], g, ws, client())
    assert out[0].status == expected


def test_heist_finding_is_always_group_primary(setup):
    ws, g, _ = setup
    a = mk("a", "gitleaks", "high")
    h = mk("h", "heist", "low", line=2)
    with respx.mock() as router:
        router.post(OPEN_URL).mock(return_value=reply({"groups": [["a", "h"]], "noise": []}))
        out = triage([a, h], g, ws, client())
    assert [f.id for f in out] == ["h"]
    assert out[0].source == "heist"
    assert out[0].severity == "high"
    assert len(out[0].refs) == 2


def test_triage_never_merges_two_heist_findings(setup):
    ws, g, findings = setup
    with respx.mock() as router:
        router.post(OPEN_URL).mock(
            return_value=reply({"groups": [["m3-adoption_requests", "m3-messages"]], "noise": []})
        )
        out = triage(findings, g, ws, client())
    ids = [f.id for f in out]
    assert ids == [f.id for f in findings]
    by_id = {f.id: f for f in out}
    originals = {f.id: f for f in findings}
    assert by_id["m3-adoption_requests"] == originals["m3-adoption_requests"]
    assert by_id["m3-messages"] == originals["m3-messages"]


def test_triage_folds_scanner_finding_into_heist_finding(setup):
    ws, g, findings = setup
    leak = mk("gl-openai", "gitleaks", "high", "confirmed", 4)
    with respx.mock() as router:
        router.post(OPEN_URL).mock(
            return_value=reply(
                {
                    "groups": [["gl-openai", "m1-vite-openai-api-key", "m2-src-lib-admin-ts"]],
                    "noise": [],
                }
            )
        )
        out = triage([*findings, leak], g, ws, client())
    ids = [f.id for f in out]
    assert "gl-openai" not in ids
    assert ids == [f.id for f in findings]
    m1 = next(f for f in out if f.id == "m1-vite-openai-api-key")
    assert leak.refs[0] in m1.refs and "n-gl-openai" in m1.node_ids
    m2 = next(f for f in out if f.id == "m2-src-lib-admin-ts")
    assert m2 == next(f for f in findings if f.id == "m2-src-lib-admin-ts")

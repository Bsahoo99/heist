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
    return MetaClient("spark", "open", SpendTracker())


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
        out = triage(findings, g, ws, MetaClient("spark", "open", SpendTracker()))
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

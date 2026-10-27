import json
import threading

import httpx
import pytest
import respx
from openai.types import CompletionUsage
from openai.types.completion_usage import PromptTokensDetails
from pydantic import BaseModel

from heist.llm.client import (
    DEFAULT_META_BASE_URL,
    DEFAULT_OPEN_BASE_URL,
    MetaClient,
    ModelOutputError,
    SpendTracker,
)

SPARK_URL = f"{DEFAULT_META_BASE_URL}/chat/completions"
OPEN_URL = f"{DEFAULT_OPEN_BASE_URL}/chat/completions"


class Ok(BaseModel):
    ok: bool


def completion(
    content: str, prompt_tokens: int = 10, completion_tokens: int = 5, cached: int | None = None
) -> dict:
    usage: dict = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }
    if cached is not None:
        usage["prompt_tokens_details"] = {"cached_tokens": cached}
    return {
        "id": "x",
        "object": "chat.completion",
        "created": 0,
        "model": "m",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": usage,
    }


@pytest.fixture
def mock_meta():
    with respx.mock(assert_all_called=False) as router:
        yield router


def test_chat_json_parses_and_tracks_spend(mock_meta):
    mock_meta.post(SPARK_URL).respond(
        json=completion('{"ok": true}', prompt_tokens=1_000_000, completion_tokens=0)
    )
    tracker = SpendTracker()
    c = MetaClient("spark", "open", tracker)
    assert c.chat_json("spark", "s", "u", Ok).ok is True
    assert tracker.total_usd == pytest.approx(1.25)


def test_chat_json_raises_on_bad_json(mock_meta):
    mock_meta.post(SPARK_URL).respond(json=completion("not json"))
    with pytest.raises(ModelOutputError) as ei:
        MetaClient("spark", "open", SpendTracker()).chat_json("spark", "s", "u", Ok)
    assert ei.value.raw == "not json"


def test_raw_is_truncated_and_redacted(mock_meta):
    mock_meta.post(SPARK_URL).respond(json=completion("sekret " + "x" * 5000))
    c = MetaClient("spark", "open", SpendTracker(), spark_key="sekret")
    with pytest.raises(ModelOutputError) as ei:
        c.chat_json("spark", "s", "u", Ok)
    assert len(ei.value.raw) <= 2000
    assert "sekret" not in ei.value.raw


def test_fenced_json_parses(mock_meta):
    mock_meta.post(OPEN_URL).respond(json=completion('```json\n{"ok": true}\n```'))
    assert MetaClient("spark", "open", SpendTracker()).chat_json("open", "s", "u", Ok).ok


def test_max_tokens_below_floor_raises():
    c = MetaClient("spark", "open", SpendTracker())
    with pytest.raises(ValueError):
        c.chat_json("open", "s", "u", Ok, max_tokens=399)


def test_json_schema_400_retries_json_object_and_remembers(mock_meta):
    route = mock_meta.post(OPEN_URL)
    route.side_effect = [
        httpx.Response(400, json={"error": {"message": "response_format json_schema unsupported"}}),
        httpx.Response(200, json=completion('{"ok": true}')),
        httpx.Response(200, json=completion('{"ok": true}')),
    ]
    c = MetaClient("spark", "open", SpendTracker())
    assert c.chat_json("open", "s", "u", Ok).ok
    assert c.chat_json("open", "s", "u", Ok).ok
    formats = [json.loads(call.request.content)["response_format"]["type"] for call in route.calls]
    assert formats == ["json_schema", "json_object", "json_object"]


def test_schema_request_is_strict_with_schema_name(mock_meta):
    route = mock_meta.post(OPEN_URL).respond(json=completion('{"ok": true}'))
    MetaClient("spark", "open", SpendTracker()).chat_json("open", "s", "u", Ok)
    fmt = json.loads(route.calls[0].request.content)["response_format"]
    assert fmt["json_schema"]["name"] == "Ok"
    assert fmt["json_schema"]["strict"] is True


def test_unrelated_400_is_not_retried(mock_meta):
    import openai

    route = mock_meta.post(OPEN_URL).respond(400, json={"error": {"message": "bad model"}})
    with pytest.raises(openai.BadRequestError):
        MetaClient("spark", "open", SpendTracker()).chat_json("open", "s", "u", Ok)
    assert route.call_count == 1


def test_from_env_falls_back_to_open_model(monkeypatch, mock_meta, caplog):
    for k, v in {
        "MODEL_API_KEY": "",
        "MUSE_SPARK_MODEL": "",
        "OPEN_API_KEY": "k",
        "OPEN_BASE_URL": DEFAULT_OPEN_BASE_URL,
        "MUSE_SPARK_OPEN_MODEL": "meta-models/open-x",
    }.items():
        monkeypatch.setenv(k, v)
    route = mock_meta.post(OPEN_URL).respond(json=completion('{"ok": true}'))
    c = MetaClient.from_env()
    assert c.models() == {"spark": "meta-models/open-x", "open": "meta-models/open-x"}
    assert c.chat_json("spark", "s", "u", Ok).ok
    assert json.loads(route.calls[0].request.content)["model"] == "meta-models/open-x"
    assert "fall back" in caplog.text


def test_from_env_uses_spark_when_configured(monkeypatch):
    for k, v in {
        "MODEL_API_KEY": "mk",
        "MUSE_SPARK_MODEL": "muse-spark",
        "OPEN_API_KEY": "ok",
        "MUSE_SPARK_OPEN_MODEL": "meta-models/open-x",
    }.items():
        monkeypatch.setenv(k, v)
    assert MetaClient.from_env().models() == {
        "spark": "muse-spark",
        "open": "meta-models/open-x",
    }


def test_cached_token_pricing():
    usage = CompletionUsage(
        prompt_tokens=1_000_000,
        completion_tokens=1_000_000,
        total_tokens=2_000_000,
        prompt_tokens_details=PromptTokensDetails(cached_tokens=400_000),
    )
    t = SpendTracker()
    cost = t.add("muse-spark", usage)
    assert cost == pytest.approx(0.6 * 1.25 + 0.4 * 0.15 + 4.25)
    assert t.total_usd == pytest.approx(cost)


def test_open_model_priced_by_model_id(monkeypatch):
    monkeypatch.setenv("OPEN_PRICE_IN_PER_M", "2")
    monkeypatch.setenv("OPEN_PRICE_OUT_PER_M", "3")
    t = SpendTracker()
    t.register_open("meta-models/muse-spark-open-1026")
    usage = CompletionUsage(prompt_tokens=1_000_000, completion_tokens=1_000_000, total_tokens=2)
    assert t.add("meta-models/muse-spark-open-1026", usage) == pytest.approx(5.0)


def test_spend_tracker_is_thread_safe():
    t = SpendTracker()
    usage = CompletionUsage(prompt_tokens=1_000_000, completion_tokens=0, total_tokens=1_000_000)
    threads = [
        threading.Thread(target=lambda: [t.add("spark", usage) for _ in range(50)])
        for _ in range(8)
    ]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert t.total_usd == pytest.approx(400 * 1.25)


def test_empty_choices_raises_model_output_error(mock_meta):
    body = completion("x")
    body["choices"] = []
    mock_meta.post(OPEN_URL).respond(json=body)
    with pytest.raises(ModelOutputError):
        MetaClient("spark", "open", SpendTracker()).chat_json("open", "s", "u", Ok)


def test_length_finish_with_empty_content_is_diagnosable(mock_meta):
    body = completion("")
    body["choices"][0]["finish_reason"] = "length"
    mock_meta.post(OPEN_URL).respond(json=body)
    with pytest.raises(ModelOutputError) as ei:
        MetaClient("spark", "open", SpendTracker()).chat_json("open", "s", "u", Ok)
    assert "finish_reason=length" in ei.value.errors

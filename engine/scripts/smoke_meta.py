"""Smoke test for the Meta Model API (Muse Spark, Muse Image) and the Muse Spark Open partner endpoint.

Each probe runs independently and is skipped when its key is empty.
Keys are loaded from engine/.env and are never printed.
"""

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

TIMEOUT = 60.0
# Muse Spark Open is a reasoning model: 50 tokens were all spent on reasoning and content came back empty.
MAX_TOKENS = int(os.environ.get("SMOKE_MAX_TOKENS", "400"))
PROMPT = 'Reply with exactly this JSON and nothing else: {"ok": true}'
SCHEMA_FORMAT: dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "ok_result",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
    },
}


def load_env(path: Path) -> None:
    """Tiny .env parser. Existing environment variables win."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def redact(text: str) -> str:
    for name in ("MODEL_API_KEY", "OPEN_API_KEY"):
        secret = env(name)
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def post_chat(
    base_url: str, key: str, model: str, response_format: dict[str, Any] | None
) -> tuple[bool, str]:
    body: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "max_tokens": MAX_TOKENS,
        "temperature": 0,
    }
    if response_format is not None:
        body["response_format"] = response_format
    label = response_format["type"] if response_format else "no response_format"
    start = time.perf_counter()
    try:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json=body,
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        ms = (time.perf_counter() - start) * 1000
        print(f"  [{label}] ERROR {type(exc).__name__} in {ms:.0f} ms: {redact(str(exc))}")
        return False, ""
    ms = (time.perf_counter() - start) * 1000
    if resp.status_code != 200:
        print(f"  [{label}] HTTP {resp.status_code} in {ms:.0f} ms: {redact(resp.text[:300])}")
        return False, ""
    data = resp.json()
    usage = data.get("usage") or {}
    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message", {})
    content = message.get("content") or ""
    reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
    print(f"  finish_reason={choice.get('finish_reason')} reasoning_chars={len(reasoning)}")
    print(
        f"  [{label}] HTTP 200 in {ms:.0f} ms, tokens prompt={usage.get('prompt_tokens')} "
        f"completion={usage.get('completion_tokens')}"
    )
    print(f"  content: {redact(content.strip())!r}")
    try:
        ok = json.loads(content).get("ok") is True
    except (json.JSONDecodeError, AttributeError):
        ok = False
    print(f'  parsed as {{"ok": true}}: {ok}')
    return ok, content


def probe_models(name: str, base_url: str, key_var: str) -> None:
    print(f"\n== {name}: GET /models ==")
    key = env(key_var)
    if not key:
        print(f"SKIPPED: {key_var} not set")
        return
    if not base_url:
        print("SKIPPED: base URL not set")
        return
    start = time.perf_counter()
    try:
        resp = httpx.get(
            f"{base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        print(f"ERROR {type(exc).__name__}: {redact(str(exc))}")
        return
    ms = (time.perf_counter() - start) * 1000
    print(f"HTTP {resp.status_code} in {ms:.0f} ms")
    if resp.status_code != 200:
        print(redact(resp.text[:300]))
        return
    try:
        ids = sorted(m.get("id", "?") for m in resp.json().get("data", []))
    except (ValueError, AttributeError):
        print("Unparseable body")
        return
    print(f"{len(ids)} models")
    for model_id in ids:
        print(f"  {model_id}")


def probe_chat(name: str, base_url: str, key_var: str, model_var: str) -> None:
    print(f"\n== {name}: chat completion ==")
    if not env(key_var):
        print(f"SKIPPED: {key_var} not set")
        return
    if not env(model_var):
        print(f"SKIPPED: {model_var} not set")
        return
    if not base_url:
        print("SKIPPED: base URL not set")
        return
    key, model = env(key_var), env(model_var)
    print(f"model: {model}")
    print("JSON mode:")
    ok, _ = post_chat(base_url, key, model, {"type": "json_object"})
    if not ok:
        print("JSON mode did not yield a clean result, retrying without response_format:")
        post_chat(base_url, key, model, None)
    print("Structured outputs (json_schema):")
    post_chat(base_url, key, model, SCHEMA_FORMAT)


def probe_image(base_url: str) -> None:
    print("\n== Meta Model API: Muse Image generation ==")
    if not env("MODEL_API_KEY"):
        print("SKIPPED: MODEL_API_KEY not set")
        return
    if not base_url:
        print("SKIPPED: META_BASE_URL not set")
        return
    model = env("MUSE_IMAGE_MODEL") or "muse-image"
    start = time.perf_counter()
    try:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/images/generations",
            headers={"Authorization": f"Bearer {env('MODEL_API_KEY')}"},
            json={"model": model, "prompt": "a small red square on a white background", "n": 1},
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        print(f"ERROR {type(exc).__name__}: {redact(str(exc))}")
        return
    ms = (time.perf_counter() - start) * 1000
    print(f"model: {model}")
    print(f"HTTP {resp.status_code} in {ms:.0f} ms")
    print(redact(resp.text[:200]))


def main() -> None:
    load_env(Path(__file__).resolve().parent.parent / ".env")
    meta_url = env("META_BASE_URL")
    open_url = env("OPEN_BASE_URL")
    probe_models("Meta Model API", meta_url, "MODEL_API_KEY")
    probe_chat("Meta Model API (Muse Spark)", meta_url, "MODEL_API_KEY", "MUSE_SPARK_MODEL")
    probe_image(meta_url)
    probe_models("Muse Spark Open partner endpoint", open_url, "OPEN_API_KEY")
    probe_chat(
        "Muse Spark Open partner endpoint", open_url, "OPEN_API_KEY", "MUSE_SPARK_OPEN_MODEL"
    )


if __name__ == "__main__":
    main()

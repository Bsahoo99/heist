# Meta models smoke test results

Date run: 2026-10-27.
Script: `engine/scripts/smoke_meta.py` (run with `cd engine && uv run python scripts/smoke_meta.py`).
Each probe is independent and prints `SKIPPED: <VAR> not set` when its key is empty.

## Muse Spark Open on Baseten

- Endpoint: `https://inference.baseten.co/v1` (OpenAI compatible, `OPEN_BASE_URL`).
- Confirmed model id: `meta-models/muse-spark-open-1026` (`MUSE_SPARK_OPEN_MODEL`).
- `GET /models` works (HTTP 200, 20 models, about 1.3 s).
- The list also contains the alias `meta-models/muse-spark-open`, which was not called.
- JSON mode (`response_format={"type":"json_object"}`): supported, returned `{"ok": true}`.
- Structured outputs (`response_format={"type":"json_schema", ...}` with a strict `{"ok": boolean}` schema): supported, returned `{"ok": true}`.
- Observed latency: 0.6 to 1.0 s for JSON mode, about 1.4 s for json_schema.
- Token usage: prompt 159, completion 83 (json_object), prompt 159, completion 270 (json_schema).
- Muse Spark Open is a reasoning model and returns its thinking in a separate `reasoning_content` field.
- Reasoning tokens count against `max_tokens`.
- With `max_tokens=50` the content came back empty (finish reason length, all tokens spent on reasoning), so use at least 400 for structured calls.
- Always read `message.content`, not `reasoning_content`, and budget generous `max_tokens` in the engine.

## Pending: Meta Model API

The Meta API key (`MODEL_API_KEY`) has not arrived yet, so these probes are skipped.
They need no code change once the key, `META_BASE_URL` and `MUSE_SPARK_MODEL` are set in `engine/.env`.

- `GET {META_BASE_URL}/models` to confirm the base URL and list model ids.
- Muse Spark chat completion in JSON mode, to confirm `MUSE_SPARK_MODEL`, JSON mode and json_schema support, latency and token usage.
- Muse Image generation (`POST {META_BASE_URL}/images/generations`, model from `MUSE_IMAGE_MODEL`, default `muse-image`), to learn whether it is callable.
- If Muse Image is not on the API, make the art by hand in the Meta AI app (Task 13 Step 6).

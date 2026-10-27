"""Client for Muse Spark (Meta Model API) and Muse Spark Open (Baseten), plus spend tracking."""

import logging
import re
import threading
from typing import Literal, TypeVar

import httpx
import openai
from openai.types import CompletionUsage
from pydantic import BaseModel, ValidationError

from heist.llm.config import env

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

DEFAULT_OPEN_BASE_URL = "https://inference.baseten.co/v1"
DEFAULT_META_BASE_URL = "https://api.meta.ai/v1"
DEFAULT_OPEN_MODEL = "meta-models/muse-spark-open-1026"

TIMEOUT_S = 120.0
MAX_RETRIES = 2
DEFAULT_MAX_TOKENS = 4000
# Muse Spark Open is a reasoning model: reasoning tokens count against max_tokens.
MIN_MAX_TOKENS = 400
RAW_LIMIT = 2000

# USD per 1M tokens: (input, cached input, output).
SPARK_PRICE = (1.25, 0.15, 4.25)
# Muse Spark Open on Baseten. Values read from the Baseten model page ("Model API pricing",
# per 1M tokens: input 1.25, cache input 0.15, output 4.25) on 2026-10-27.
# They match Spark's list price exactly, so re-verify before quoting them publicly.
# Override with OPEN_PRICE_IN_PER_M / OPEN_PRICE_OUT_PER_M / OPEN_PRICE_CACHED_PER_M.
OPEN_PRICE_DEFAULT = (1.25, 0.15, 4.25)


def _open_price() -> tuple[float, float, float]:
    def pick(name: str, default: float) -> float:
        raw = env(name)
        try:
            return float(raw) if raw else default
        except ValueError:
            return default

    return (
        pick("OPEN_PRICE_IN_PER_M", OPEN_PRICE_DEFAULT[0]),
        pick("OPEN_PRICE_CACHED_PER_M", OPEN_PRICE_DEFAULT[1]),
        pick("OPEN_PRICE_OUT_PER_M", OPEN_PRICE_DEFAULT[2]),
    )


class ModelOutputError(Exception):
    def __init__(self, raw: str, errors: str):
        super().__init__(f"model output could not be parsed: {errors[:300]}")
        self.raw = raw[:RAW_LIMIT]
        self.errors = errors


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


class SpendTracker:
    """Accumulates USD spend. Thread safe, since traces run in parallel."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0.0
        self._open_models: set[str] = set()

    def register_open(self, model: str) -> None:
        self._open_models.add(model)

    @property
    def total_usd(self) -> float:
        with self._lock:
            return self._total

    def _price(self, model: str) -> tuple[float, float, float]:
        if model in self._open_models or "open" in model.lower():
            return _open_price()
        return SPARK_PRICE

    def add(self, model: str, usage: CompletionUsage) -> float:
        p_in, p_cached, p_out = self._price(model)
        details = usage.prompt_tokens_details
        cached = min(getattr(details, "cached_tokens", None) or 0, usage.prompt_tokens)
        cost = (
            (usage.prompt_tokens - cached) * p_in
            + cached * p_cached
            + usage.completion_tokens * p_out
        ) / 1_000_000
        with self._lock:
            self._total += cost
        return cost


_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL | re.IGNORECASE)


def strip_fences(text: str) -> str:
    m = _FENCE.match(text)
    return m.group(1) if m else text.strip()


def _is_format_error(exc: openai.BadRequestError) -> bool:
    msg = str(exc).lower()
    return "response_format" in msg or "json_schema" in msg


class MetaClient:
    def __init__(
        self,
        spark_model: str,
        open_model: str,
        tracker: SpendTracker,
        *,
        spark_key: str = "",
        spark_base_url: str = "",
        open_key: str = "",
        open_base_url: str = "",
        max_retries: int = MAX_RETRIES,
    ):
        self.tracker = tracker
        self._spark_model = spark_model
        self._open_model = open_model
        tracker.register_open(open_model)
        self._secrets = [s for s in (spark_key, open_key) if s]
        self._clients = {
            "spark": self._make(spark_key, spark_base_url or DEFAULT_META_BASE_URL, max_retries),
            "open": self._make(open_key, open_base_url or DEFAULT_OPEN_BASE_URL, max_retries),
        }
        # Providers (keyed "spark"/"open") that rejected json_schema; they use json_object.
        self._downgraded: set[str] = set()

    @staticmethod
    def _make(key: str, base_url: str, max_retries: int) -> openai.OpenAI:
        return openai.OpenAI(
            api_key=key or "unset",
            base_url=base_url,
            timeout=TIMEOUT_S,
            max_retries=max_retries,
            # openai 3.x defaults to httpx2, which respx cannot mock. Plain httpx keeps tests offline.
            http_client=httpx.Client(timeout=TIMEOUT_S),  # pyright: ignore[reportArgumentType]
        )

    @classmethod
    def from_env(cls, tracker: SpendTracker | None = None) -> "MetaClient":
        tracker = tracker or SpendTracker()
        open_model = env("MUSE_SPARK_OPEN_MODEL") or DEFAULT_OPEN_MODEL
        open_key, open_url = env("OPEN_API_KEY"), env("OPEN_BASE_URL") or DEFAULT_OPEN_BASE_URL
        spark_key, spark_model = env("MODEL_API_KEY"), env("MUSE_SPARK_MODEL")
        if not spark_key or not spark_model:
            log.warning(
                "MODEL_API_KEY or MUSE_SPARK_MODEL is empty: Muse Spark calls fall back to %s",
                open_model,
            )
            return cls(
                open_model,
                open_model,
                tracker,
                spark_key=open_key,
                spark_base_url=open_url,
                open_key=open_key,
                open_base_url=open_url,
            )
        return cls(
            spark_model,
            open_model,
            tracker,
            spark_key=spark_key,
            spark_base_url=env("META_BASE_URL") or DEFAULT_META_BASE_URL,
            open_key=open_key,
            open_base_url=open_url,
        )

    def models(self) -> dict[str, str]:
        return {"spark": self._spark_model, "open": self._open_model}

    def chat_json(
        self,
        which: Literal["spark", "open"],
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> T:
        if max_tokens < MIN_MAX_TOKENS:
            raise ValueError(
                f"max_tokens must be at least {MIN_MAX_TOKENS}: reasoning tokens count against it"
            )
        model = self._spark_model if which == "spark" else self._open_model
        client = self._clients[which]
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        schema_format: dict[str, object] = {
            "type": "json_schema",
            "json_schema": {
                "name": schema.__name__,
                "strict": True,
                "schema": schema.model_json_schema(),
            },
        }
        object_format: dict[str, object] = {"type": "json_object"}
        fmt = object_format if which in self._downgraded else schema_format
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=max_tokens,
                response_format=fmt,  # type: ignore[arg-type]
            )
        except openai.BadRequestError as exc:
            if fmt is not schema_format or not _is_format_error(exc):
                raise
            log.warning("%s rejected json_schema, falling back to json_object", which)
            self._downgraded.add(which)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=max_tokens,
                response_format=object_format,  # type: ignore[arg-type]
            )
        if resp.usage is not None:
            self.tracker.add(model, resp.usage)
        if not resp.choices:
            raise ModelOutputError("", "response contained no choices")
        choice = resp.choices[0]
        raw = choice.message.content or ""
        if not raw.strip() and choice.finish_reason == "length":
            raise ModelOutputError("", "model ran out of tokens (finish_reason=length)")
        try:
            return schema.model_validate_json(strip_fences(raw))
        except ValidationError as exc:
            raise ModelOutputError(_redact(raw, self._secrets), str(exc)) from None

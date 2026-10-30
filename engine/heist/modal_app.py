"""The engine on Modal: `uv run modal deploy heist/modal_app.py` from engine/ (see docs/deploy.md).

Importing this module needs no Modal login and reads no secrets: images and secrets are
descriptions, resolved by Modal at deploy time and inside the container.

Secrets (created once, from env files, never typed on a command line):
- `heist-meta`: the model provider variables `MetaClient.from_env` reads (`OPEN_API_KEY`,
  `OPEN_BASE_URL`, `MUSE_SPARK_OPEN_MODEL`, and `MODEL_API_KEY`, `MUSE_SPARK_MODEL`,
  `META_BASE_URL` when Muse Spark is configured).
- `heist-supabase`: `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` for Heist's own database.

`HEIST_WEB_ORIGINS` (the web app's origin, for CORS) is not a secret: it is read from the
shell that runs `modal deploy` and baked into the function's environment.
"""

import os
from pathlib import Path

import modal
from fastapi import FastAPI

ENGINE_DIR = Path(__file__).resolve().parents[1]

APP_NAME = "heist-engine"
SECRET_NAMES = ("heist-meta", "heist-supabase")
SEMGREP_VERSION = "1.182.0"
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_URL = (
    f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/"
    f"gitleaks_{GITLEAKS_VERSION}_linux_x64.tar.gz"
)
UV_VERSION = "0.12.5"  # the same uv the local prover image uses

# The live registry (event logs, subscribers, joins of a running analysis) and the rate limiter
# live in this container's memory, so there is exactly one container. It takes many requests
# at once: SSE streams stay open for a whole analysis, and analyses run on worker threads.
MAX_CONTAINERS = 1
MAX_CONCURRENT_INPUTS = 100
# Analyses run on threads after their POST has returned; keep the container around long
# enough after the last request for a queued run to finish.
SCALEDOWN_WINDOW_S = 20 * 60
REQUEST_TIMEOUT_S = 30 * 60  # an SSE stream lasts as long as its analysis

CONTAINER_ENV: dict[str, str | None] = {
    "HEIST_PROVER": "modal",
    "HEIST_WEB_ORIGINS": os.environ.get("HEIST_WEB_ORIGINS", ""),
    "PYTHONDONTWRITEBYTECODE": "1",
}

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git", "ca-certificates", "curl")
    .run_commands(
        f"curl -fsSL {GITLEAKS_URL} | tar -xz -C /usr/local/bin gitleaks",
        "gitleaks version",
        # Semgrep in its own venv, so its pins never meet the engine's locked dependencies.
        "python -m venv /opt/semgrep",
        f"/opt/semgrep/bin/pip install --no-cache-dir semgrep=={SEMGREP_VERSION}",
        "ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep",
        "semgrep --version",
    )
    # The engine's dependencies exactly as locked, without the dev group.
    .uv_sync(str(ENGINE_DIR), frozen=True, extra_options="--no-dev", uv_version=UV_VERSION)
    # The package with its data files (rules, prompts, the proof stub); never engine/.env.
    .add_local_python_source("heist", ignore=["**/__pycache__", "**/__pycache__/**"])
)

app = modal.App(APP_NAME)


@app.function(
    image=image,
    secrets=[modal.Secret.from_name(name) for name in SECRET_NAMES],
    env=CONTAINER_ENV,
    max_containers=MAX_CONTAINERS,
    scaledown_window=SCALEDOWN_WINDOW_S,
    timeout=REQUEST_TIMEOUT_S,
)
@modal.concurrent(max_inputs=MAX_CONCURRENT_INPUTS)
@modal.asgi_app()
def web() -> FastAPI:
    from heist.api import ApiConfig, create_app
    from heist.store import store_from_env

    # Behind Modal the ASGI client is the caller (Modal strips forwarded headers), so the rate
    # limit counts the socket peer: HEIST_TRUSTED_PROXY_HOPS stays unset.
    return create_app(ApiConfig.from_env(), store=store_from_env())

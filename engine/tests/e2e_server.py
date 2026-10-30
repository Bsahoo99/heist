"""The engine for the web e2e tests: offline, and `clone_repo` copies local fixtures.

Run from engine/: `uv run python -m tests.e2e_server`. Stub repos:
- https://github.com/heist-fixtures/vuln-app   -> tests/fixtures/vuln_app
- https://github.com/heist-fixtures/clean-app  -> tests/fixtures/clean_app
- https://github.com/heist-fixtures/no-rules-app -> tests/fixtures/vuln_app without supabase/migrations
- https://github.com/heist-fixtures/partial-rules-app -> tests/fixtures/clean_app plus an unreadable migration
- https://github.com/heist-fixtures/plain-vite -> a Vite app without Supabase (unsupported)
Any other GitHub URL fails like a bad clone, so nothing ever reaches GitHub.

`HEIST_E2E_DELAY` (seconds, default 1) holds the run while cloning, after mapping and after
sorting the findings, so the live map can be seen lighting up. `HEIST_E2E_PORT` defaults to 8010.
`HEIST_PROVER` works as in the real engine (unset: no proofs).
"""

import os
import tempfile
import time
from pathlib import Path
from typing import Any

import uvicorn

from heist import pipeline
from heist.api import ApiConfig, create_app, parse_prover

from .stub_repos import (
    FIXTURES_DIR,
    make_stub_clone,
    stub_url,
    write_no_rules_app,
    write_partial_rules_app,
    write_plain_vite_app,
)


def _slowed(fn: Any, delay: float) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        time.sleep(delay)
        return fn(*args, **kwargs)

    return wrapper


def main() -> None:
    delay = float(os.environ.get("HEIST_E2E_DELAY", "1"))
    port = int(os.environ.get("HEIST_E2E_PORT", "8010"))
    origins = os.environ.get("HEIST_WEB_ORIGINS", "http://localhost:3100")
    scratch = Path(tempfile.mkdtemp(prefix="heist-e2e-"))
    plain = write_plain_vite_app(scratch / "plain")
    no_rules = write_no_rules_app(scratch / "no_rules")
    partial_rules = write_partial_rules_app(scratch / "partial_rules")
    repos = {
        stub_url("vuln-app"): FIXTURES_DIR / "vuln_app",
        stub_url("clean-app"): FIXTURES_DIR / "clean_app",
        stub_url("plain-vite"): plain,
        stub_url("no-rules-app"): no_rules,
        stub_url("partial-rules-app"): partial_rules,
    }
    pipeline.clone_repo = _slowed(make_stub_clone(repos), delay)
    pipeline.run_detectors = _slowed(pipeline.run_detectors, delay)
    pipeline._trace_all = _slowed(pipeline._trace_all, delay)  # pyright: ignore[reportPrivateUsage]

    config = ApiConfig(
        offline=True,
        origins=[o.strip() for o in origins.split(",") if o.strip()],
        prover=parse_prover(os.environ.get("HEIST_PROVER")),
    )
    uvicorn.run(create_app(config), host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()

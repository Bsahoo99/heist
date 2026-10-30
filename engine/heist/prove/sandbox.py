"""Run the RLS proof in a sandbox with no network: a Modal Sandbox, or a local Docker container.

Both run `python -m heist.prove.runner` next to a private Postgres 16 that listens on a local
socket only, send it the repo's migrations on stdin and read one JSON line back. Any failure
proves nothing (`{}`) and logs the stage, a fixed reason or the exception type, never SQL text
or row values.

Images are built ahead of time, never inside an analysis: `warm(prover)` runs in the background
when the API starts, and `uv run python -m heist.prove.sandbox warmup --docker|--modal` builds
by hand. Until an image is ready, proofs are skipped. Every proof has one overall deadline.

Modal needs a token on this machine (`uv run modal token new`) and `HEIST_PROVER=modal`.
"""

import argparse
import hashlib
import json
import logging
import secrets
import subprocess
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import modal

from heist.fetch import Workspace
from heist.models import DbSchema
from heist.prove.runner import ProofFailed
from heist.scene import ProofRow

log = logging.getLogger(__name__)

Prover = Literal["modal", "docker"]

PROOF_DEADLINE_S = 120  # everything an analysis waits for: create, run, read back
SANDBOX_TIMEOUT_S = 110  # the sandbox's own lifetime, inside the deadline
MAX_PAYLOAD_BYTES = 2_000_000  # all migration files together
HEIST_DIR = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/heist"
RUNNER_ARGS = ("-m", "heist.prove.runner")
# Only what the runner imports goes into the sandbox; never the rest of the engine or its .env.
SHIPPED_FILES = ("__init__.py", "prove/__init__.py", "prove/runner.py", "prove/stub.sql")
PROVER_PACKAGES = ("psycopg[binary]==3.3.6", "pglast==8.7")
POSTGRES_IMAGE = "postgres:16"

MODAL_APP = "heist-prover"
MODAL_CPU = 1.0
MODAL_MEMORY_MB = 1024

UV_IMAGE = "ghcr.io/astral-sh/uv:0.12.5"
LOCAL_DOCKERFILE = f"""\
FROM {POSTGRES_IMAGE}
COPY --from={UV_IMAGE} /uv /usr/local/bin/uv
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN uv venv --python 3.12 /opt/venv \\
 && uv pip install --python /opt/venv/bin/python --no-cache {" ".join(f"'{p}'" for p in PROVER_PACKAGES)} \\
 && chmod -R a+rX /opt/python /opt/venv
"""
LOCAL_IMAGE = "heist-prover:" + hashlib.sha256(LOCAL_DOCKERFILE.encode()).hexdigest()[:12]
DOCKER_BUILD_TIMEOUT_S = 900
DOCKER_INSPECT_TIMEOUT_S = 5


class ProofSkipped(Exception):
    """The proof did not run. `reason` is a fixed token, safe to log."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _payload(db: DbSchema, ws: Workspace, tables: list[str]) -> str:
    """The migrations in replay order (the graph's order), unparsed files included."""
    texts = []
    total = 0
    for rel in db.migration_files:
        data = (ws.app_root / rel.removeprefix("!")).read_bytes()
        total += len(data)
        if total > MAX_PAYLOAD_BYTES:
            raise ProofSkipped("migrations_too_large")
        texts.append(data.decode("utf-8", errors="replace"))
    return json.dumps({"migrations": texts, "tables": tables})


def _parse(out: str, tables: list[str]) -> dict[str, list[ProofRow]]:
    lines = [line for line in out.splitlines() if line.strip()]
    if not lines:
        raise ProofFailed("sandbox", "no answer")
    answer = json.loads(lines[-1])
    if not answer.get("ok"):
        raise ProofFailed(str(answer.get("stage", "sandbox")), str(answer.get("error", "")))
    wanted = set(tables)
    got: dict[str, list[ProofRow]] = {}
    for table, rows in dict(answer.get("rows") or {}).items():
        if table in wanted:
            parsed = [ProofRow.model_validate(r) for r in rows]
            got[table] = [r for r in parsed if r.table == table]
    return got


def _guarded(where: str, run: Callable[[str], str], db: DbSchema, ws: Workspace, tables: list[str]):
    try:
        return _parse(run(_payload(db, ws, tables)), tables)
    except ProofSkipped as exc:
        log.warning("proof in %s skipped: %s", where, exc.reason)
    except ProofFailed as exc:
        log.warning("proof in %s failed at stage %s", where, exc.stage)
    except Exception as exc:  # noqa: BLE001 - a failed proof leaves the findings confirmed
        log.warning("proof in %s failed: %s", where, type(exc).__name__)
    return {}


def _with_deadline(work: Callable[[], str], cancel: Callable[[], None], seconds: float) -> str:
    """`work()` in a helper thread; past the deadline, `cancel()` and give up on it."""
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="heist-proof")
    future = pool.submit(work)
    try:
        return future.result(timeout=seconds)
    except FutureTimeout:
        cancel()
        raise ProofFailed("timeout", "the sandbox ran out of time") from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


# ---------------------------------------------------------------------------------------------
# Modal


@dataclass(frozen=True)
class _ModalReady:
    app: modal.App
    image: modal.Image


_modal_ready: _ModalReady | None = None


def _modal_image() -> modal.Image:
    image = modal.Image.from_registry(POSTGRES_IMAGE, add_python="3.12").pip_install(
        *PROVER_PACKAGES
    )
    for rel in SHIPPED_FILES:
        image = image.add_local_file(HEIST_DIR / rel, f"{REMOTE_ROOT}/heist/{rel}")
    return image


def warm_modal() -> None:
    """Look up the app and build the image (cached by Modal after the first time)."""
    global _modal_ready
    app = modal.App.lookup(MODAL_APP, create_if_missing=True)
    image = _modal_image().build(app)
    _modal_ready = _ModalReady(app=app, image=image)


def _run_in_modal(payload: str) -> str:
    ready = _modal_ready
    if ready is None:
        raise ProofSkipped("modal_not_warm")
    started: list[modal.Sandbox] = []
    cancelled = threading.Event()

    def work() -> str:
        sb = modal.Sandbox.create(
            "python",
            *RUNNER_ARGS,
            app=ready.app,
            image=ready.image,
            block_network=True,
            timeout=SANDBOX_TIMEOUT_S,
            workdir=REMOTE_ROOT,
            env={"PYTHONPATH": REMOTE_ROOT, "PYTHONDONTWRITEBYTECODE": "1"},
            cpu=MODAL_CPU,
            memory=MODAL_MEMORY_MB,
        )
        started.append(sb)
        try:
            if cancelled.is_set():
                raise ProofFailed("timeout", "cancelled")
            sb.stdin.write(payload.encode())
            sb.stdin.write_eof()
            sb.stdin.drain()
            sb.wait(raise_on_termination=False)
            return sb.stdout.read()
        finally:
            sb.terminate()

    def cancel() -> None:
        cancelled.set()
        for sb in started:
            try:
                sb.terminate()
            except Exception as exc:  # noqa: BLE001 - best effort; Modal ends it at its timeout
                log.warning("could not stop the modal sandbox: %s", type(exc).__name__)

    return _with_deadline(work, cancel, PROOF_DEADLINE_S)


def prove_rls(db: DbSchema, ws: Workspace, tables: list[str]) -> dict[str, list[ProofRow]]:
    """The proof in a Modal Sandbox from postgres:16, network blocked, 120 s at most.

    Skipped until `warm("modal")` has built the image in this process.
    """
    return _guarded("modal", _run_in_modal, db, ws, tables)


# ---------------------------------------------------------------------------------------------
# Local Docker


def _local_image_ready() -> bool:
    try:
        found = subprocess.run(
            ["docker", "image", "inspect", LOCAL_IMAGE],
            capture_output=True,
            check=False,
            timeout=DOCKER_INSPECT_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return found.returncode == 0


def warm_local() -> None:
    """Build the local prover image if it is not there yet."""
    if _local_image_ready():
        return
    log.info("building the local prover image %s", LOCAL_IMAGE)
    subprocess.run(
        ["docker", "build", "-t", LOCAL_IMAGE, "-"],
        input=LOCAL_DOCKERFILE.encode(),
        capture_output=True,
        check=True,
        timeout=DOCKER_BUILD_TIMEOUT_S,
    )


def _run_in_docker(payload: str) -> str:
    if not _local_image_ready():
        raise ProofSkipped("docker_image_not_ready")
    image = LOCAL_IMAGE
    name = f"heist-proof-{secrets.token_hex(6)}"
    mounts: list[str] = []
    for rel in SHIPPED_FILES:
        mounts += ["-v", f"{HEIST_DIR / rel}:{REMOTE_ROOT}/heist/{rel}:ro"]
    cmd = [
        "docker", "run", "--rm", "-i", "--name", name,
        "--network", "none",
        "--user", "postgres",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "1g",
        "--cpus", "1",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=512m,mode=1777",
        *mounts,
        "-w", REMOTE_ROOT,
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint", "/opt/venv/bin/python",
        image, *RUNNER_ARGS,
    ]  # fmt: skip

    def work() -> str:
        res = subprocess.run(cmd, input=payload.encode(), capture_output=True, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"the prover container exited with {res.returncode}")
        return res.stdout.decode("utf-8", errors="replace")

    def cancel() -> None:
        # Stopping the container also ends the `docker run` client in the helper thread.
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)

    return _with_deadline(work, cancel, PROOF_DEADLINE_S)


def prove_local(db: DbSchema, ws: Workspace, tables: list[str]) -> dict[str, list[ProofRow]]:
    """The same proof in a local Docker container with `--network none`, for before Modal.

    Skipped until the image exists (`warm("docker")`).
    """
    return _guarded("docker", _run_in_docker, db, ws, tables)


# ---------------------------------------------------------------------------------------------
# Warmup


def warm(prover: Prover) -> None:
    """Build or hydrate the prover's image. Slow the first time; never call it in an analysis."""
    if prover == "modal":
        warm_modal()
    else:
        warm_local()


def warm_in_background(prover: Prover) -> threading.Thread:
    """`warm(prover)` on a daemon thread; a failure is logged by type and proofs stay skipped."""

    def run() -> None:
        try:
            warm(prover)
        except Exception as exc:  # noqa: BLE001 - proofs stay skipped; the analysis still runs
            log.warning("could not warm the %s prover: %s", prover, type(exc).__name__)
        else:
            log.info("the %s prover is ready", prover)

    t = threading.Thread(target=run, name=f"heist-warm-{prover}", daemon=True)
    t.start()
    return t


def main(argv: list[str] | None = None) -> int:
    """`python -m heist.prove.sandbox warmup --docker|--modal`."""
    parser = argparse.ArgumentParser(prog="python -m heist.prove.sandbox")
    sub = parser.add_subparsers(dest="command", required=True)
    w = sub.add_parser("warmup", help="build the prover image ahead of any analysis")
    which = w.add_mutually_exclusive_group(required=True)
    which.add_argument("--docker", action="store_const", dest="prover", const="docker")
    which.add_argument("--modal", action="store_const", dest="prover", const="modal")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    warm(args.prover)
    print(f"the {args.prover} prover is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

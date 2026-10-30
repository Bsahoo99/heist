"""Run the RLS proof in a sandbox with no network: a Modal Sandbox, or a local Docker container.

Both run `python -m heist.prove.runner` next to a private Postgres 16 that listens on a local
socket only, send it the repo's migrations on stdin and read one JSON line back. Any failure
proves nothing (`{}`) and logs the stage or the exception type, never SQL text or row values.

Modal needs a token on this machine (`uv run modal token new`) and `HEIST_PROVER=modal`.
"""

import hashlib
import json
import logging
import secrets
import subprocess
from collections.abc import Callable
from pathlib import Path

import modal

from heist.fetch import Workspace
from heist.models import DbSchema
from heist.prove.runner import ProofFailed
from heist.scene import ProofRow

log = logging.getLogger(__name__)

SANDBOX_TIMEOUT_S = 120
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


def _payload(db: DbSchema, ws: Workspace, tables: list[str]) -> str:
    """The migrations in replay order (the graph's order), unparsed files included."""
    texts = []
    for rel in db.migration_files:
        data = (ws.app_root / rel.removeprefix("!")).read_bytes()
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
    except ProofFailed as exc:
        log.warning("proof in %s failed at stage %s", where, exc.stage)
    except Exception as exc:  # noqa: BLE001 - a failed proof leaves the findings confirmed
        log.warning("proof in %s failed: %s", where, type(exc).__name__)
    return {}


# ---------------------------------------------------------------------------------------------
# Modal


def _modal_image() -> modal.Image:
    image = modal.Image.from_registry(POSTGRES_IMAGE, add_python="3.12").pip_install(
        *PROVER_PACKAGES
    )
    for rel in SHIPPED_FILES:
        image = image.add_local_file(HEIST_DIR / rel, f"{REMOTE_ROOT}/heist/{rel}")
    return image


def _run_in_modal(payload: str) -> str:
    app = modal.App.lookup(MODAL_APP, create_if_missing=True)
    sb = modal.Sandbox.create(
        "python",
        *RUNNER_ARGS,
        app=app,
        image=_modal_image(),
        block_network=True,
        timeout=SANDBOX_TIMEOUT_S,
        workdir=REMOTE_ROOT,
        env={"PYTHONPATH": REMOTE_ROOT, "PYTHONDONTWRITEBYTECODE": "1"},
        cpu=MODAL_CPU,
        memory=MODAL_MEMORY_MB,
    )
    try:
        sb.stdin.write(payload.encode())
        sb.stdin.write_eof()
        sb.stdin.drain()
        sb.wait(raise_on_termination=False)
        return sb.stdout.read()
    finally:
        sb.terminate()


def prove_rls(db: DbSchema, ws: Workspace, tables: list[str]) -> dict[str, list[ProofRow]]:
    """The proof in a Modal Sandbox from postgres:16, network blocked, 120 s at most."""
    return _guarded("modal", _run_in_modal, db, ws, tables)


# ---------------------------------------------------------------------------------------------
# Local Docker


def _ensure_local_image() -> str:
    found = subprocess.run(
        ["docker", "image", "inspect", LOCAL_IMAGE], capture_output=True, check=False, timeout=30
    )
    if found.returncode != 0:
        log.info("building the local prover image %s", LOCAL_IMAGE)
        subprocess.run(
            ["docker", "build", "-t", LOCAL_IMAGE, "-"],
            input=LOCAL_DOCKERFILE.encode(),
            capture_output=True,
            check=True,
            timeout=DOCKER_BUILD_TIMEOUT_S,
        )
    return LOCAL_IMAGE


def _run_in_docker(payload: str) -> str:
    image = _ensure_local_image()
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
    try:
        res = subprocess.run(
            cmd, input=payload.encode(), capture_output=True, check=False, timeout=SANDBOX_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)
        raise
    if res.returncode != 0:
        raise RuntimeError(f"the prover container exited with {res.returncode}")
    return res.stdout.decode("utf-8", errors="replace")


def prove_local(db: DbSchema, ws: Workspace, tables: list[str]) -> dict[str, list[ProofRow]]:
    """The same proof in a local Docker container with `--network none`, for before Modal."""
    return _guarded("docker", _run_in_docker, db, ws, tables)

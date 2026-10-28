"""The analysis pipeline: fetch, map, detect, triage, trace, prove, then build the Scene."""

import logging
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from heist.detect.run import run_detectors
from heist.fetch import (
    BAD_URL_COPY,
    UnsupportedRepo,
    Workspace,
    clone_repo,
    detect_stack,
    load_workspace,
    parse_github_url,
)
from heist.graph.build import build_app_graph
from heist.llm.client import MetaClient
from heist.llm.templates import fallback_trace
from heist.llm.trace import TraceSource, trace_with_validation
from heist.llm.triage import triage
from heist.models import AppGraph, DbSchema, Finding, ProgressEvent, TraceOut
from heist.scene import ProofRow, Scene, SceneMeta, build_scene

log = logging.getLogger(__name__)

Emit = Callable[[ProgressEvent], None]
Prove = Callable[[DbSchema, Workspace, list[str]], dict[str, list[ProofRow]]]

TRACE_WORKERS = 4
PROVED_MISTAKE = 3
GENERIC_ERROR_COPY = "Something went wrong while analyzing this repo. Please try again."


def _stage(emit: Emit, message: str) -> None:
    emit(ProgressEvent(kind="stage", message=message))


def _is_github_url(source: str) -> bool:
    try:
        parse_github_url(source)
    except UnsupportedRepo:
        return False
    return True


def _fetch(source: str, stack: ExitStack) -> tuple[Workspace, str]:
    """The workspace and the repo name shown in the Scene. Clones live in a temp dir."""
    if _is_github_url(source):
        owner, repo = parse_github_url(source)
        tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="heist-"))
        return clone_repo(source, Path(tmp) / "repo"), f"https://github.com/{owner}/{repo}"
    path = Path(source)
    if not path.is_dir():
        raise UnsupportedRepo(BAD_URL_COPY)
    return load_workspace(path), path.resolve().name


def _emit_nodes(g: AppGraph, emit: Emit) -> None:
    for n in sorted(g.nodes, key=lambda n: n.id):
        emit(
            ProgressEvent(
                kind="node_found",
                message=f"Found {n.name}",
                data={"zone": n.zone, "label": n.name, "node_id": n.id},
            )
        )


def _emit_findings(findings: list[Finding], emit: Emit) -> None:
    for f in findings:
        emit(
            ProgressEvent(
                kind="finding",
                message=f.title,
                data={
                    "id": f.id,
                    "mistake": f.mistake,
                    "severity": f.severity,
                    "status": f.status,
                    "title": f.title,
                },
            )
        )


def _trace_all(
    findings: list[Finding], g: AppGraph, ws: Workspace, client: MetaClient | None
) -> dict[str, tuple[TraceOut, TraceSource]]:
    if client is None:
        return {f.id: (fallback_trace(f, g, ws), "fallback") for f in findings}

    def one(f: Finding) -> tuple[TraceOut, TraceSource]:
        try:
            return trace_with_validation(f, g, ws, client, findings=findings)
        except Exception as exc:  # noqa: BLE001 - one bad trace must not sink the analysis
            log.warning("trace %s crashed, using the template: %s", f.id, type(exc).__name__)
            return fallback_trace(f, g, ws), "fallback"

    with ThreadPoolExecutor(max_workers=TRACE_WORKERS) as pool:
        results = list(pool.map(one, findings))
    return {f.id: r for f, r in zip(findings, results, strict=True)}


def _prove(
    prove: Prove | None, g: AppGraph, ws: Workspace, findings: list[Finding]
) -> dict[str, list[ProofRow]]:
    # Only confirmed leaks are proved: a "possible" finding (often meant to be public) never is.
    ids = [f.id for f in findings if f.mistake == PROVED_MISTAKE and f.status == "confirmed"]
    if prove is None or g.db is None or not ids:
        return {}
    try:
        rows = prove(g.db, ws, ids)
    except Exception as exc:  # noqa: BLE001 - a failed proof leaves the finding confirmed
        log.warning("proof failed, findings stay confirmed: %s", type(exc).__name__)
        return {}
    wanted = set(ids)
    return {fid: list(r) for fid, r in rows.items() if fid in wanted and r}


def _with_refs(findings: list[Finding]) -> list[Finding]:
    kept = []
    for f in findings:
        if f.refs:
            kept.append(f)
        else:
            log.warning("finding %s has no code ref, skipping it", f.id)
    return kept


def _analyze(
    source: str,
    emit: Emit,
    client: MetaClient | None,
    prove: Prove | None,
    analyzed_at: datetime | None,
    stack: ExitStack,
) -> Scene:
    _stage(emit, "Fetching the repo")
    ws, repo = _fetch(source, stack)
    app_stack = detect_stack(ws)

    _stage(emit, "Mapping the app")
    g = build_app_graph(ws, app_stack)
    _emit_nodes(g, emit)

    _stage(emit, "Checking the locks")
    findings = _with_refs(run_detectors(ws, g))

    _stage(emit, "Sorting the findings")
    if client is not None:
        findings = _with_refs(triage(findings, g, ws, client))
    _emit_findings(findings, emit)

    _stage(emit, "Planning the heist")
    traces = _trace_all(findings, g, ws, client)

    _stage(emit, "Proving it")
    proofs = _prove(prove, g, ws, findings)

    meta = SceneMeta(
        repo=repo,
        commit_sha=ws.commit_sha,
        analyzed_at=analyzed_at or datetime.now(UTC),
        stack=app_stack,
        models=client.models() if client is not None else {},
        has_db_rules=g.has_db_rules,
        unparsed_migrations=list(g.db.unparsed_migrations) if g.db else [],
        checks_held=0,  # set by build_scene
    )
    scene = build_scene(g, findings, traces, proofs, meta)
    _stage(emit, "Done")
    done: dict[str, Any] = {"findings": len(scene.findings), "checks_held": scene.meta.checks_held}
    emit(ProgressEvent(kind="done", message="Done", data=done))
    return scene


def run_analysis(
    source: str,
    emit: Emit,
    client: MetaClient | None,
    prove: Prove | None = None,
    *,
    analyzed_at: datetime | None = None,
) -> Scene:
    """Analyze a GitHub URL or a local directory (local paths only from the CLI and tests).

    `client=None` is offline mode: no triage, and every finding uses the template trace.
    Errors are reported as an `error` event and then re-raised.
    """
    try:
        with ExitStack() as stack:
            return _analyze(source, emit, client, prove, analyzed_at, stack)
    except UnsupportedRepo as exc:
        emit(ProgressEvent(kind="error", message=exc.reason))
        raise
    except Exception as exc:
        log.error("analysis failed: %s", type(exc).__name__)
        emit(ProgressEvent(kind="error", message=GENERIC_ERROR_COPY))
        raise

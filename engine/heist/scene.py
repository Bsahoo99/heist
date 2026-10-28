"""The Scene: one JSON document the front end renders onto the fixed map."""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Literal, get_args

from pydantic import BaseModel

from heist.llm.trace import TraceSource
from heist.models import AppGraph, CodeRef, Finding, Node, Stack, StepOut, TraceOut, ZoneId

log = logging.getLogger(__name__)

ZONE_ORDER: tuple[ZoneId, ...] = get_args(ZoneId)
MISTAKES = range(1, 8)
# Node kinds that never get their own box on the map.
HIDDEN_KINDS = {"policy", "client_call"}
_STATUS_RANK = {"proved": 0, "confirmed": 1, "possible": 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class PathStep(BaseModel):
    zone: ZoneId
    ref: CodeRef | None  # None only for stops with no code (visitor, Supabase Auth)
    node_id: str
    data: str
    story: str
    why: str
    code: str


class Fix(BaseModel):
    explanation: str
    diff: str
    prompt: str


class ProofRow(BaseModel):
    as_who: Literal["anonymous", "another_user"]
    table: str
    row: dict[str, Any]


class SceneFinding(BaseModel):
    id: str
    mistake: int
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["confirmed", "proved", "possible"]
    title: str
    ghost_path: list[PathStep]
    attack_path: list[PathStep]
    guard_ref: CodeRef
    proof_rows: list[ProofRow]
    fix: Fix
    trace_source: TraceSource


class SceneItem(BaseModel):
    node_id: str
    label: str
    kind: str
    flagged: bool


class SceneZone(BaseModel):
    id: ZoneId
    active: bool
    items: list[SceneItem]


class SceneMeta(BaseModel):
    repo: str
    commit_sha: str
    analyzed_at: datetime
    stack: Stack
    models: dict[str, str]
    has_db_rules: bool
    unparsed_migrations: list[str]
    checks_held: int


class Scene(BaseModel):
    version: Literal[1]
    zones: list[SceneZone]
    findings: list[SceneFinding]
    meta: SceneMeta


def _step_ref(step: StepOut, nodes: dict[str, Node]) -> CodeRef | None:
    if step.file is None or step.line is None:
        return None
    node = nodes.get(step.node_id)
    own = node.ref if node is not None else None
    if own is not None and own.file == step.file and own.start_line <= step.line <= own.end_line:
        return own.model_copy(update={"symbol": node.name if node else None})
    symbol = node.name if node is not None and own is not None else None
    return CodeRef(file=step.file, start_line=step.line, end_line=step.line, symbol=symbol)


def _path(steps: list[StepOut], nodes: dict[str, Node]) -> list[PathStep]:
    return [
        PathStep(
            zone=s.zone,
            ref=_step_ref(s, nodes),
            node_id=s.node_id,
            data=s.data,
            story=s.story,
            why=s.why,
            code=s.code,
        )
        for s in steps
    ]


def _zones(g: AppGraph, flagged: set[str]) -> list[SceneZone]:
    by_zone: dict[str, list[SceneItem]] = {z: [] for z in ZONE_ORDER}
    for n in sorted(g.nodes, key=lambda n: n.id):
        if n.kind in HIDDEN_KINDS:
            continue
        by_zone[n.zone].append(
            SceneItem(node_id=n.id, label=n.name, kind=n.kind, flagged=n.id in flagged)
        )
    return [SceneZone(id=z, active=bool(by_zone[z]), items=by_zone[z]) for z in ZONE_ORDER]


def _rank(f: SceneFinding) -> tuple[int, int, int, str]:
    return (_STATUS_RANK[f.status], _SEVERITY_RANK[f.severity], f.mistake, f.id)


def checks_held(findings: list[SceneFinding]) -> int:
    """Seven minus the mistakes (1..7) with a confirmed or proved finding."""
    broken = {f.mistake for f in findings if f.status != "possible" and f.mistake in MISTAKES}
    return len(MISTAKES) - len(broken)


def build_scene(
    g: AppGraph,
    findings: list[Finding],
    traces: dict[str, tuple[TraceOut, TraceSource]],
    proofs: dict[str, list[ProofRow]],
    meta: SceneMeta,
) -> Scene:
    """Assemble the Scene. A finding with proof rows becomes proved; meta.checks_held is set here.

    Findings are sorted proved, confirmed, possible, then by severity, mistake and id, so
    findings[0] is the worst one and the one that auto-plays.
    """
    nodes = {n.id: n for n in g.nodes}
    out: list[SceneFinding] = []
    for f in findings:
        if not f.refs:
            log.warning("finding %s has no code ref, skipping it", f.id)
            continue
        if f.id not in traces:
            log.warning("finding %s has no trace, skipping it", f.id)
            continue
        trace, source = traces[f.id]
        rows = proofs.get(f.id, [])
        out.append(
            SceneFinding(
                id=f.id,
                mistake=f.mistake,
                severity=f.severity,
                status="proved" if rows else f.status,
                title=f.title,
                ghost_path=_path(trace.ghost_path, nodes),
                attack_path=_path(trace.attack_path, nodes),
                guard_ref=f.refs[0],
                proof_rows=rows,
                fix=Fix(
                    explanation=trace.fix.explanation, diff=trace.fix.diff, prompt=trace.fix.prompt
                ),
                trace_source=source,
            )
        )
    out.sort(key=_rank)
    kept = {x.id for x in out}
    flagged = {i for f in findings if f.id in kept for i in f.node_ids}
    return Scene(
        version=1,
        zones=_zones(g, flagged),
        findings=out,
        meta=meta.model_copy(update={"checks_held": checks_held(out)}),
    )


def schema_json() -> str:
    return json.dumps(Scene.model_json_schema(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--schema"]:
        print("usage: python -m heist.scene --schema", file=sys.stderr)
        return 2
    sys.stdout.write(schema_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
    node_id: str  # the precise graph node, which may be one the map never draws
    item_id: str  # the map item in this step's zone that stands for node_id
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


class _Items:
    """Maps any graph node to the map item that stands for it.

    A policy maps to its table, a client call to its page; other visible nodes map to
    themselves. Failing that, the nearest item in the same zone (same file first) is used.
    """

    def __init__(self, g: AppGraph):
        self.nodes = {n.id: n for n in g.nodes}
        self.by_zone: dict[str, list[Node]] = {z: [] for z in ZONE_ORDER}
        for n in sorted(g.nodes, key=lambda n: n.id):
            if n.kind not in HIDDEN_KINDS:
                self.by_zone[n.zone].append(n)
        self.edges = g.edges

    def _candidates(self, node: Node) -> list[str]:
        if node.kind == "policy":
            return [f"table:{node.id.split(':', 2)[1]}"]
        if node.kind == "client_call":
            own = [f"page:{node.ref.file}"] if node.ref else []
            linked: set[str] = set()
            for e in self.edges:
                if e.dst == node.id:
                    linked.add(e.src)
                elif e.src == node.id:
                    linked.add(e.dst)
            return [*own, *sorted(i for i in linked if i.startswith("page:"))]
        return [node.id]

    def resolve(self, node_id: str, zone: str) -> str:
        items = self.by_zone.get(zone, [])
        ids = {n.id for n in items}
        node = self.nodes.get(node_id)
        if node is None:
            return node_id if node_id in ids or not items else items[0].id
        for cand in self._candidates(node):
            if cand in ids:
                return cand
        if not items:
            log.warning("no map item in zone %s for %s", zone, node_id)
            return node_id
        ref = node.ref
        if ref is not None:
            same_file = [n for n in items if n.ref is not None and n.ref.file == ref.file]
            if same_file:

                def distance(n: Node) -> tuple[int, str]:
                    start = n.ref.start_line if n.ref else 0
                    return (abs(start - ref.start_line), n.id)

                return min(same_file, key=distance).id
        return items[0].id


def _path(steps: list[StepOut], nodes: dict[str, Node], items: _Items) -> list[PathStep]:
    return [
        PathStep(
            zone=s.zone,
            ref=_step_ref(s, nodes),
            node_id=s.node_id,
            item_id=items.resolve(s.node_id, s.zone),
            data=s.data,
            story=s.story,
            why=s.why,
            code=s.code,
        )
        for s in steps
    ]


def _zones(items: _Items, flagged: set[str]) -> list[SceneZone]:
    out: list[SceneZone] = []
    for z in ZONE_ORDER:
        zone_items = [
            SceneItem(node_id=n.id, label=n.name, kind=n.kind, flagged=n.id in flagged)
            for n in items.by_zone[z]
        ]
        out.append(SceneZone(id=z, active=bool(zone_items), items=zone_items))
    return out


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
    """Assemble the Scene. meta.checks_held is set here.

    A confirmed finding with proof rows becomes proved; a possible one never does.

    Findings are sorted proved, confirmed, possible, then by severity, mistake and id, so
    findings[0] is the worst one and the one that auto-plays.
    """
    nodes = {n.id: n for n in g.nodes}
    items = _Items(g)
    out: list[SceneFinding] = []
    for f in findings:
        if not f.refs:
            log.warning("finding %s has no code ref, skipping it", f.id)
            continue
        if f.id not in traces:
            log.warning("finding %s has no trace, skipping it", f.id)
            continue
        trace, source = traces[f.id]
        rows = proofs.get(f.id, []) if f.status != "possible" else []
        out.append(
            SceneFinding(
                id=f.id,
                mistake=f.mistake,
                severity=f.severity,
                status="proved" if rows else f.status,
                title=f.title,
                ghost_path=_path(trace.ghost_path, nodes, items),
                attack_path=_path(trace.attack_path, nodes, items),
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
    flagged = {
        items.resolve(i, nodes[i].zone)
        for f in findings
        if f.id in kept
        for i in f.node_ids
        if i in nodes
    }
    return Scene(
        version=1,
        zones=_zones(items, flagged),
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

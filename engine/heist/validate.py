"""Check a traced path against the real repo: every step must point at a node and real code."""

from dataclasses import dataclass, field

from heist.fetch import Workspace
from heist.models import AppGraph, Finding, FixOut, Node, StepOut, TraceOut

EM_DASH = "\u2014"
GHOST_STEPS = (2, 5)
ATTACK_STEPS = (3, 7)


@dataclass
class Report:
    trace: TraceOut
    errors: list[str] = field(default_factory=list)
    # Fatal errors make the trace unusable even after a retry (the rest only dropped steps).
    fatal: bool = False


def scrub_dashes(t: TraceOut) -> TraceOut:
    def fix(s: str) -> str:
        return s.replace(f" {EM_DASH} ", " - ").replace(EM_DASH, " - ")

    def step(s: StepOut) -> StepOut:
        return s.model_copy(
            update={
                "data": fix(s.data),
                "story": fix(s.story),
                "why": fix(s.why),
                "code": fix(s.code),
            }
        )

    return TraceOut(
        ghost_path=[step(s) for s in t.ghost_path],
        attack_path=[step(s) for s in t.attack_path],
        fix=FixOut(
            explanation=fix(t.fix.explanation), diff=fix(t.fix.diff), prompt=fix(t.fix.prompt)
        ),
    )


class _Lines:
    def __init__(self, ws: Workspace):
        self._ws = ws
        self._files = set(ws.files)
        self._cache: dict[str, int] = {}

    def has(self, rel: str) -> bool:
        return rel in self._files

    def count(self, rel: str) -> int:
        if rel not in self._cache:
            try:
                text = (self._ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
                self._cache[rel] = len(text.splitlines())
            except OSError:
                self._cache[rel] = 0
        return self._cache[rel]


def _check_location(s: StepOut, node: Node, lines: _Lines) -> str | None:
    if s.file is None:
        if node.ref is not None:
            return f"node '{node.id}' has code, so the step needs a file and line"
        if s.line is not None:
            return f"line {s.line} was given without a file"
        return None
    if not lines.has(s.file):
        return f"file '{s.file}' is not in the repo"
    if s.line is None:
        return f"file '{s.file}' was given without a line"
    n = lines.count(s.file)
    if not 1 <= s.line <= n:
        return f"line {s.line} is outside '{s.file}' (it has {n} lines)"
    return None


def _clean_path(
    name: str, path: list[StepOut], nodes: dict[str, Node], lines: _Lines, errors: list[str]
) -> list[StepOut]:
    kept: list[StepOut] = []
    for i, s in enumerate(path, start=1):
        node = nodes.get(s.node_id)
        if node is None:
            problem: str | None = f"node '{s.node_id}' is not in the node list"
        else:
            problem = _check_location(s, node, lines)
        if problem is not None:
            errors.append(f"{name} step {i} dropped: {problem}")
            continue
        assert node is not None
        kept.append(s if s.zone == node.zone else s.model_copy(update={"zone": node.zone}))
    return kept


def check_trace(t: TraceOut, f: Finding, g: AppGraph, ws: Workspace) -> Report:
    t = scrub_dashes(t)
    nodes = {n.id: n for n in g.nodes}
    lines = _Lines(ws)
    errors: list[str] = []
    fatal = False

    ghost = _clean_path("ghost_path", t.ghost_path, nodes, lines, errors)
    attack = _clean_path("attack_path", t.attack_path, nodes, lines, errors)

    lo, hi = ATTACK_STEPS
    if not attack:
        errors.append("attack path is empty after dropping invalid steps")
        fatal = True
    elif not lo <= len(t.attack_path) <= hi:
        errors.append(f"attack path has {len(t.attack_path)} steps; use {lo} to {hi}")
    guard_files = sorted({r.file for r in f.refs})
    if attack and guard_files and not any(s.file in guard_files for s in attack):
        errors.append(
            "attack path never reaches the missing guard: at least one attack step must point "
            f"at {', '.join(guard_files)}"
        )
        fatal = True

    lo, hi = GHOST_STEPS
    if not ghost:
        errors.append("ghost path is empty after dropping invalid steps")
        fatal = True
    elif not lo <= len(t.ghost_path) <= hi:
        errors.append(f"ghost path has {len(t.ghost_path)} steps; use {lo} to {hi}")

    if not t.fix.explanation.strip() or not t.fix.prompt.strip():
        errors.append("fix needs a plain explanation and a fix prompt")
        fatal = True

    cleaned = TraceOut(ghost_path=ghost, attack_path=attack, fix=t.fix)
    return Report(trace=cleaned, errors=errors, fatal=fatal)


def validate_trace(
    t: TraceOut, f: Finding, g: AppGraph, ws: Workspace
) -> tuple[TraceOut, list[str]]:
    r = check_trace(t, f, g, ws)
    return r.trace, r.errors

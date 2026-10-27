"""Check a traced path against the real repo: every step must point at a node and real code."""

import re
from dataclasses import dataclass, field

from heist.fetch import Workspace
from heist.llm.templates import fallback_trace
from heist.models import AppGraph, Finding, Node, StepOut, TraceOut, scrub_dashes

__all__ = ["Report", "check_diff", "check_trace", "scrub_dashes", "validate_trace"]

GHOST_STEPS = (2, 5)
ATTACK_STEPS = (3, 7)
DIFF_LINE_SLACK = 3
REDACTED = "<redacted>"
DIFF_SWAPPED = "fix diff does not match the repo, so the template diff is used instead"
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Report:
    trace: TraceOut
    errors: list[str] = field(default_factory=list)
    # Fatal errors make the trace unusable even after a retry (the rest only dropped steps).
    fatal: bool = False
    # False when the only problem was a swapped fix diff, which never causes a retry.
    needs_retry: bool = False


class _Lines:
    def __init__(self, ws: Workspace):
        self._ws = ws
        self._files = set(ws.files)
        self._cache: dict[str, list[str]] = {}

    def has(self, rel: str) -> bool:
        return rel in self._files

    def text(self, rel: str) -> list[str]:
        if rel not in self._cache:
            try:
                text = (self._ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
                self._cache[rel] = text.splitlines()
            except OSError:
                self._cache[rel] = []
        return self._cache[rel]

    def count(self, rel: str) -> int:
        return len(self.text(rel))


# --- fix diffs ------------------------------------------------------------------------


def _diff_path(header: str) -> str:
    path = header[4:].split("\t", 1)[0].strip()
    if path != "/dev/null" and path[:2] in ("a/", "b/"):
        path = path[2:]
    return path


def _same(model_line: str, real: str) -> bool:
    """Equal up to whitespace. A <redacted> placeholder stands for any text."""
    a, b = "".join(model_line.split()), "".join(real.split())
    if REDACTED not in a:
        return a == b
    parts = [re.escape(p) for p in a.split(REDACTED)]
    return re.fullmatch(".*".join(parts), b) is not None


def _hunk_fits(old: list[str], start: int, real: list[str]) -> bool:
    if not old:
        return 0 <= start <= len(real)
    for shift in range(-DIFF_LINE_SLACK, DIFF_LINE_SLACK + 1):
        at = max(start, 1) - 1 + shift
        if at < 0 or at + len(old) > len(real):
            continue
        if all(_same(x, real[at + i]) for i, x in enumerate(old)):
            return True
    return False


def _is_header(rows: list[str], i: int) -> bool:
    return rows[i].startswith("--- ") and i + 1 < len(rows) and rows[i + 1].startswith("+++ ")


def _check_diff(diff: str, lines: _Lines) -> list[str]:
    problems: list[str] = []
    rows = diff.splitlines()
    i = 0
    files = 0
    while i < len(rows):
        if not _is_header(rows, i):
            i += 1
            continue
        old_path, new_path = _diff_path(rows[i]), _diff_path(rows[i + 1])
        files += 1
        i += 2
        new_file = old_path == "/dev/null"
        if not new_file and not lines.has(old_path):
            problems.append(f"diff changes '{old_path}', which is not in the repo")
        if new_path != "/dev/null" and not new_file and new_path != old_path:
            problems.append(f"diff renames '{old_path}' to '{new_path}'")
        real = [] if new_file or not lines.has(old_path) else lines.text(old_path)
        while i < len(rows) and not _is_header(rows, i):
            m = _HUNK_RE.match(rows[i])
            if not m:
                if rows[i].startswith(("-", "+", " ")) and "lines outside" not in str(problems):
                    problems.append(f"diff for '{old_path}' has lines outside any hunk")
                i += 1
                continue
            start = int(m.group(1))
            old_left = int(m.group(2) or 1)
            new_left = int(m.group(4) or 1)
            i += 1
            old: list[str] = []
            while i < len(rows) and (old_left > 0 or new_left > 0):
                row = rows[i]
                if row.startswith("@@") or _is_header(rows, i):
                    break
                if row.startswith("+"):
                    new_left -= 1
                elif row.startswith(("-", " ")) or row == "":
                    old.append(row[1:])
                    old_left -= 1
                    if not row.startswith("-"):
                        new_left -= 1
                i += 1
            if new_file:
                if old:
                    problems.append(f"diff for new file '{new_path}' has removed or context lines")
            elif lines.has(old_path) and not _hunk_fits(old, start, real):
                problems.append(f"diff hunk at '{old_path}' line {start} does not match the file")
    if files == 0:
        problems.append("fix diff is not a unified diff")
    return problems


def check_diff(diff: str, ws: Workspace) -> list[str]:
    """Problems with a fix diff: unknown files, or removed and context lines not in the file."""
    return _check_diff(diff, _Lines(ws))


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

    needs_retry = bool(errors)
    fix = t.fix
    diff_problems = _check_diff(fix.diff, lines)
    if diff_problems:
        template = fallback_trace(f, g, ws).fix.diff
        fix = fix.model_copy(update={"diff": template})
        errors.append(f"{DIFF_SWAPPED} ({'; '.join(diff_problems)})")

    cleaned = TraceOut(ghost_path=ghost, attack_path=attack, fix=fix)
    return Report(trace=cleaned, errors=errors, fatal=fatal, needs_retry=needs_retry)


def validate_trace(
    t: TraceOut, f: Finding, g: AppGraph, ws: Workspace
) -> tuple[TraceOut, list[str]]:
    r = check_trace(t, f, g, ws)
    return r.trace, r.errors

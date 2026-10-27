"""Muse Spark traces each finding: ghost path, attack path, three-layer texts and the fix."""

import json
import logging
import re
from functools import cache
from importlib import resources
from typing import Literal, Protocol, TypeVar

from pydantic import BaseModel

from heist.fetch import Workspace
from heist.llm.client import ModelOutputError
from heist.llm.templates import builder_tool, fallback_trace
from heist.models import AppGraph, Finding, FixOut, StepOut, TraceOut
from heist.validate import check_trace, scrub_dashes

__all__ = [
    "FixOut",
    "StepOut",
    "TraceOut",
    "fallback_trace",
    "redact_for_prompt",
    "trace_finding",
    "trace_with_validation",
]

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

TRACE_MAX_TOKENS = 16000
PROMPT_FILE_CAP = 120_000
FEEDBACK_HEADER = "## Problems with your previous answer"
REDACTED = "<redacted>"
# Evidence keys that may hold part of a secret value.
SECRET_EVIDENCE_KEYS = {"preview", "match", "secret", "value"}

TraceSource = Literal["model", "model_retry", "fallback"]

_ENV_ASSIGN_RE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*)(.*)$")
_STRING_RE = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\])*)\1""")
_JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
_KEY_PREFIX_RE = re.compile(
    r"^(?:sk|rk|pk_live|sk_live|sk_test|ghp|gho|github_pat|xox[abpr]|AKIA|glpat|sbp|sb_secret)[-_]"
)
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_\-+/=.]{32,}$")


class JsonChatClient(Protocol):
    """The slice of MetaClient this module needs."""

    def chat_json(
        self,
        which: Literal["spark", "open"],
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int = ...,
    ) -> T: ...


@cache
def system_prompt() -> str:
    return resources.files("heist.llm").joinpath("prompts/trace.md").read_text(encoding="utf-8")


def _is_env_named(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env")


def _redact_env(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        m = _ENV_ASSIGN_RE.match(line)
        if m is None:
            out.append(REDACTED)
        elif m.group(2).strip():
            out.append(m.group(1).rstrip() + REDACTED)
        else:
            out.append(line)
    return "\n".join(out)


def _redact_literals(line: str) -> str:
    return _STRING_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(1)}", line)


def _looks_secret(value: str) -> bool:
    if len(value) < 20 or any(c.isspace() for c in value):
        return False
    if _JWT_RE.search(value) or _KEY_PREFIX_RE.match(value):
        return True
    return bool(
        _TOKENISH_RE.match(value)
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
    )


def _redact_secret_literals(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        return f"{m.group(1)}{REDACTED}{m.group(1)}" if _looks_secret(m.group(2)) else m.group(0)

    return _STRING_RE.sub(sub, _JWT_RE.sub(REDACTED, text))


def redact_for_prompt(rel: str, text: str, findings: list[Finding]) -> str:
    """Remove secret values before any text is sent to a model.

    Every .env* file keeps its variable names but loses its values. On lines that a mistake 1
    or 2 finding points at in other files, string literal contents are replaced. As a backstop,
    JWTs and string literals that look like keys are replaced everywhere else too.
    """
    if _is_env_named(rel):
        return _redact_env(text)
    text = _redact_secret_literals(text)
    flagged: set[int] = set()
    for f in findings:
        if f.mistake not in (1, 2):
            continue
        for r in f.refs:
            if r.file == rel:
                flagged.update(range(r.start_line, max(r.start_line, r.end_line) + 1))
    if not flagged:
        return text
    lines = text.splitlines()
    for i in flagged:
        if 1 <= i <= len(lines):
            lines[i - 1] = _redact_literals(lines[i - 1])
    return "\n".join(lines)


def _read(ws: Workspace, rel: str) -> str | None:
    if rel not in ws.files:
        return None
    try:
        return (ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _numbered(text: str) -> str:
    return "\n".join(f"{i}| {line}" for i, line in enumerate(text.splitlines(), start=1))


def _finding_json(f: Finding) -> str:
    data = f.model_dump(mode="json")
    data["evidence"] = {k: v for k, v in f.evidence.items() if k not in SECRET_EVIDENCE_KEYS}
    return json.dumps(data, indent=2)


def _graph_text(g: AppGraph) -> str:
    rows = ["id | kind | name | zone | file:line"]
    for n in g.nodes:
        where = f"{n.ref.file}:{n.ref.start_line}" if n.ref else "-"
        rows.append(f"{n.id} | {n.kind} | {n.name} | {n.zone} | {where}")
    edges = [f"{e.src} -> {e.dst} ({e.kind})" for e in g.edges]
    return "## Nodes\n" + "\n".join(rows) + "\n\n## Edges\n" + ("\n".join(edges) or "(none)")


def _context_files(f: Finding, g: AppGraph) -> tuple[list[str], list[str]]:
    """(primary files, neighbour files), each in a stable order without duplicates."""
    by_id = {n.id: n for n in g.nodes}
    ref_files = [r.file for r in f.refs]
    focus = [i for i in f.node_ids if i in by_id]
    if not focus:
        focus = [n.id for n in g.nodes if n.ref is not None and n.ref.file in ref_files]
    primary = list(
        dict.fromkeys([*ref_files, *(r.file for i in focus if (r := by_id[i].ref) is not None)])
    )
    neighbours: list[str] = []
    focus_set = set(focus)
    for e in g.edges:
        other = e.dst if e.src in focus_set else e.src if e.dst in focus_set else None
        if other is None or other not in by_id:
            continue
        ref = by_id[other].ref
        if ref is not None and ref.file not in primary and ref.file not in neighbours:
            neighbours.append(ref.file)
    return primary, neighbours


def _files_text(f: Finding, g: AppGraph, ws: Workspace, findings: list[Finding], cap: int) -> str:
    primary, neighbours = _context_files(f, g)
    sections: list[str] = []
    used = 0
    for rel, required in [*((p, True) for p in primary), *((n, False) for n in neighbours)]:
        text = _read(ws, rel)
        if text is None:
            continue
        body = _numbered(redact_for_prompt(rel, text, findings))
        section = f"=== {rel} ({len(text.splitlines())} lines)\n{body}"
        if used + len(section) > cap:
            if not required:
                continue
            room = max(cap - used, 0)
            section = section[:room] + "\n[file truncated]"
        sections.append(section)
        used += len(section)
    return "\n\n".join(sections) or "(no files)"


def build_user_prompt(
    f: Finding,
    g: AppGraph,
    ws: Workspace,
    feedback: str | None = None,
    *,
    cap: int = PROMPT_FILE_CAP,
) -> str:
    parts = [
        f"App stack: {g.stack}. The tool that built it: {builder_tool(g.stack)}.",
        "## Finding\n" + _finding_json(f),
        _graph_text(g),
        "## Files\n" + _files_text(f, g, ws, [f], cap),
    ]
    if feedback:
        parts.append(
            f"{FEEDBACK_HEADER}\n{feedback}\n\nFix these problems and answer again in full."
        )
    return "\n\n".join(parts)


def trace_finding(
    f: Finding,
    g: AppGraph,
    ws: Workspace,
    client: JsonChatClient,
    feedback: str | None = None,
) -> TraceOut:
    user = build_user_prompt(f, g, ws, feedback)
    out = client.chat_json("spark", system_prompt(), user, TraceOut, max_tokens=TRACE_MAX_TOKENS)
    return scrub_dashes(out)


def trace_with_validation(
    f: Finding, g: AppGraph, ws: Workspace, client: JsonChatClient
) -> tuple[TraceOut, TraceSource]:
    """Model trace, one retry with feedback, then the deterministic template. Never raises."""
    feedback: str | None = None
    for attempt in (1, 2):
        try:
            t = trace_finding(f, g, ws, client, feedback)
        except ModelOutputError as exc:
            log.warning("trace %s attempt %d: unusable output", f.id, attempt)
            feedback = exc.errors or "the answer could not be parsed as the requested JSON"
            continue
        except Exception as exc:  # noqa: BLE001 - any client failure means retry, then fallback
            log.warning("trace %s attempt %d failed: %s", f.id, attempt, type(exc).__name__)
            feedback = "The previous request failed. Answer again with the requested JSON."
            continue
        report = check_trace(t, f, g, ws)
        if not report.errors:
            return report.trace, "model" if attempt == 1 else "model_retry"
        if attempt == 2 and not report.fatal:
            return report.trace, "model_retry"
        log.warning("trace %s attempt %d: %d problems", f.id, attempt, len(report.errors))
        feedback = "\n".join(f"- {e}" for e in report.errors)
    return fallback_trace(f, g, ws), "fallback"

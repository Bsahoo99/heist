"""Muse Spark traces each finding: ghost path, attack path, three-layer texts and the fix."""

import json
import logging
from functools import cache
from importlib import resources
from typing import Literal, Protocol, TypeVar

from pydantic import BaseModel

from heist.fetch import Workspace
from heist.llm.client import ModelOutputError
from heist.llm.redact import redact_for_prompt
from heist.llm.templates import builder_tool, fallback_trace, hosts_for_var
from heist.models import AppGraph, Finding, FixOut, StepOut, TraceOut, scrub_dashes
from heist.validate import check_trace

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
# Evidence keys that may hold part of a secret value.
SECRET_EVIDENCE_KEYS = {"preview", "match", "secret", "value"}

TraceSource = Literal["model", "model_retry", "fallback"]


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


def _secret_function_files(f: Finding, g: AppGraph) -> list[str]:
    """For leaked keys: the Edge Functions that should hold the key instead.

    Functions calling the API the key belongs to, else every Edge Function.
    """
    by_id = {n.id: n for n in g.nodes}
    hosts = {n.id for n in hosts_for_var(str(f.evidence.get("var") or ""), g)}
    fns = [n for n in g.nodes if n.kind == "function" and n.ref is not None]
    callers = [
        by_id[e.src]
        for e in g.edges
        if e.kind == "calls_external" and e.dst in hosts and e.src in by_id
    ]
    chosen = [n for n in callers if n.ref is not None] or fns
    return list(dict.fromkeys(n.ref.file for n in chosen if n.ref is not None))


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
    if f.mistake in (1, 2):
        for rel in _secret_function_files(f, g):
            if rel not in primary and rel not in neighbours:
                neighbours.append(rel)
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
    findings: list[Finding],
    cap: int = PROMPT_FILE_CAP,
) -> str:
    """The user message. `findings` (all findings of the run) widens secret redaction."""
    known = [f, *(x for x in findings if x.id != f.id)]
    parts = [
        f"App stack: {g.stack}. The tool that built it: {builder_tool(g.stack)}.",
        "## Finding\n" + _finding_json(f),
        _graph_text(g),
        "## Files\n" + _files_text(f, g, ws, known, cap),
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
    *,
    findings: list[Finding],
) -> TraceOut:
    user = build_user_prompt(f, g, ws, feedback, findings=findings)
    out = client.chat_json("spark", system_prompt(), user, TraceOut, max_tokens=TRACE_MAX_TOKENS)
    return scrub_dashes(out)


def trace_with_validation(
    f: Finding,
    g: AppGraph,
    ws: Workspace,
    client: JsonChatClient,
    *,
    findings: list[Finding],
) -> tuple[TraceOut, TraceSource]:
    """Model trace, one retry with feedback, then the deterministic template. Never raises.

    `findings` is every finding of the run, so secrets they point at are hidden in any file
    sent. An answer with only non-fatal problems (dropped steps, path length) is usable. When
    both answers are usable, the one with fewer problems wins (the retry on a tie); when only
    one is, it is returned. Both cases report "model_retry". With no usable answer the
    template trace is returned as "fallback".
    """
    feedback: str | None = None
    usable: tuple[TraceOut, int] | None = None
    for attempt in (1, 2):
        try:
            t = trace_finding(f, g, ws, client, feedback, findings=findings)
            report = check_trace(t, f, g, ws)
        except ModelOutputError as exc:
            log.warning("trace %s attempt %d: unusable output", f.id, attempt)
            feedback = exc.errors or "the answer could not be parsed as the requested JSON"
            continue
        except Exception as exc:  # noqa: BLE001 - any client failure means retry, then fallback
            log.warning("trace %s attempt %d failed: %s", f.id, attempt, type(exc).__name__)
            feedback = "The previous request failed. Answer again with the requested JSON."
            continue
        if not report.needs_retry:
            return report.trace, "model" if attempt == 1 else "model_retry"
        if not report.fatal and (usable is None or len(report.errors) <= usable[1]):
            usable = (report.trace, len(report.errors))
        log.warning("trace %s attempt %d: %d problems", f.id, attempt, len(report.errors))
        feedback = "\n".join(f"- {e}" for e in report.errors)
    if usable is not None:
        return usable[0], "model_retry"
    return fallback_trace(f, g, ws), "fallback"

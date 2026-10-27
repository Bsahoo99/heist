"""Open-weights triage: merge duplicate findings and drop scanner noise."""

import json
import logging

from pydantic import BaseModel

from heist.fetch import Workspace
from heist.llm.client import MetaClient
from heist.models import AppGraph, Finding

log = logging.getLogger(__name__)

DROPPABLE = {"semgrep_community", "gitleaks"}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CONTEXT_RADIUS = 1
# Muse Spark Open spends thousands of reasoning tokens here; 4000 returned empty content in 4 of 5 runs.
TRIAGE_MAX_TOKENS = 12000

SYSTEM = (
    "You triage security scanner findings for a Supabase web app. "
    "Return JSON with two keys. "
    '"groups": a list of lists of finding ids that describe the same underlying problem '
    "(only include groups with two or more ids). "
    '"noise": ids of findings that are false positives or irrelevant. '
    "Only findings whose source is semgrep_community or gitleaks may be listed as noise. "
    "Never list a heist finding as noise. Use only ids from the input."
)


class TriageOut(BaseModel):
    groups: list[list[str]]
    noise: list[str]


def _context(ws: Workspace, f: Finding) -> tuple[str, str]:
    if not f.refs:
        return "", ""
    ref = f.refs[0]
    where = f"{ref.file}:{ref.start_line}"
    if ref.file not in ws.files:
        return where, ""
    try:
        lines = (ws.app_root / ref.file).read_text(errors="replace").splitlines()
    except OSError:
        return where, ""
    lo = max(ref.start_line - 1 - CONTEXT_RADIUS, 0)
    hi = min(ref.start_line + CONTEXT_RADIUS, len(lines))
    return where, "\n".join(lines[lo:hi][:3])


def _payload(findings: list[Finding], ws: Workspace) -> str:
    items = []
    for f in findings:
        where, code = _context(ws, f)
        items.append(
            {
                "id": f.id,
                "mistake": f.mistake,
                "severity": f.severity,
                "title": f.title,
                "source": f.source,
                "where": where,
                "code": code,
            }
        )
    return json.dumps(items)


def _merge(primary: Finding, other: Finding) -> Finding:
    refs = list(primary.refs)
    for r in other.refs:
        if r not in refs:
            refs.append(r)
    node_ids = list(dict.fromkeys([*primary.node_ids, *other.node_ids]))
    severity = min(primary.severity, other.severity, key=_SEVERITY_RANK.__getitem__)
    status = "confirmed" if "confirmed" in (primary.status, other.status) else primary.status
    return primary.model_copy(
        update={"refs": refs, "node_ids": node_ids, "severity": severity, "status": status}
    )


def triage(
    findings: list[Finding], g: AppGraph, ws: Workspace, client: MetaClient
) -> list[Finding]:
    if not findings:
        return findings
    try:
        out = client.chat_json(
            "open", SYSTEM, _payload(findings, ws), TriageOut, max_tokens=TRIAGE_MAX_TOKENS
        )
    except Exception as exc:  # noqa: BLE001 - any failure leaves the findings untouched
        log.warning("triage failed, keeping all findings: %s", type(exc).__name__)
        return findings

    by_id = {f.id: f for f in findings}
    dropped = {i for i in out.noise if i in by_id and by_id[i].source in DROPPABLE}
    merged_into: dict[str, str] = {}  # secondary id -> primary id
    merged: dict[str, Finding] = {}
    claimed: set[str] = set()
    for group in out.groups:
        ids = [i for i in dict.fromkeys(group) if i in by_id and i not in claimed]
        if len(ids) < 2:
            continue
        claimed.update(ids)
        primary = ids[0]
        result = by_id[primary]
        for other in ids[1:]:
            result = _merge(result, by_id[other])
            merged_into[other] = primary
        merged[primary] = result

    result_list: list[Finding] = []
    for f in findings:
        if f.id in merged_into:
            continue
        if f.id in dropped and f.id not in merged:
            continue
        result_list.append(merged.get(f.id, f))
    return result_list

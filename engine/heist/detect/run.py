"""Detector registry. Each detector is a pure function of the workspace and graph."""

from collections.abc import Callable

from heist.detect.functions import find_function_issues
from heist.detect.rls import find_rls_issues
from heist.detect.secrets import find_frontend_secrets
from heist.detect.storage import find_storage_issues
from heist.fetch import Workspace
from heist.models import AppGraph, Finding

Detector = Callable[[Workspace, AppGraph], list[Finding]]

DETECTORS: list[Detector] = [
    find_frontend_secrets,
    find_rls_issues,
    find_storage_issues,
    find_function_issues,
]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_detectors(ws: Workspace, g: AppGraph) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for detector in DETECTORS:
        for f in detector(ws, g):
            seen.setdefault(f.id, f)
    return sorted(seen.values(), key=lambda f: (_SEVERITY_ORDER[f.severity], f.mistake, f.id))

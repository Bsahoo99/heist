from pathlib import Path

from heist.detect.run import Detector, run_detectors
from heist.fetch import detect_stack, load_workspace
from heist.graph.build import build_app_graph
from heist.models import Finding


def findings_for(path: Path, detector: Detector) -> list[Finding]:
    ws = load_workspace(path)
    g = build_app_graph(ws, detect_stack(ws))
    return detector(ws, g)


def all_findings(path: Path) -> list[Finding]:
    ws = load_workspace(path)
    g = build_app_graph(ws, detect_stack(ws))
    return run_detectors(ws, g)

"""Heist's own Supabase database passes Heist's own checks (plan Task 18, step 5), offline.

The scan covers the code Heist ships: every tracked file except `engine/tests/`, whose fixtures
and test data hold deliberately broken apps and fake keys for the detectors to find.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from heist.detect.run import run_detectors
from heist.fetch import load_workspace
from heist.graph.build import build_app_graph

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_DATA = "engine/tests/"


def _shipped_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-co", "--exclude-standard"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [f for f in out.splitlines() if f and not f.startswith(TEST_DATA)]


def test_heist_has_no_confirmed_findings_on_itself(tmp_path: Path):
    dest = tmp_path / "heist"
    for rel in _shipped_files():
        src = REPO_ROOT / rel
        if src.is_file() and not src.is_symlink():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
    ws = load_workspace(dest)
    g = build_app_graph(ws, "next_supabase")
    # The scan saw Heist's own tables, so a clean result means something.
    assert g.db is not None and {"analyses", "spend_daily"} <= set(g.db.tables)
    confirmed = [f.id for f in run_detectors(ws, g) if f.status != "possible"]
    assert confirmed == []

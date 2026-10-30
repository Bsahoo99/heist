"""A stand-in for `clone_repo` that copies local fixtures, so tests never hit GitHub.

Used by the API tests and by the e2e engine (`tests/e2e_server.py`). Never imported by `heist/`.
"""

import shutil
import threading
from collections.abc import Callable
from pathlib import Path

from heist.fetch import CLONE_FAILED_COPY, UnsupportedRepo, Workspace, load_workspace

FIXTURES_DIR = Path(__file__).parent.resolve() / "fixtures"
STUB_OWNER = "heist-fixtures"
STUB_SHA = "0" * 40

CloneRepo = Callable[[str, Path], Workspace]


def stub_url(name: str) -> str:
    return f"https://github.com/{STUB_OWNER}/{name}"


def write_plain_vite_app(dest: Path) -> Path:
    """A tiny Vite app with no Supabase in it: an unsupported stack."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "package.json").write_text(
        '{"name": "plain", "dependencies": {"react": "^19"}, "devDependencies": {"vite": "^7"}}\n',
        encoding="utf-8",
    )
    (dest / "index.html").write_text("<div id='root'></div>\n", encoding="utf-8")
    return dest


def make_stub_clone(repos: dict[str, Path], gate: threading.Event | None = None) -> CloneRepo:
    """`clone_repo` that copies `repos[url]` to dest; any other URL fails like a bad clone.

    With `gate`, each clone waits until the gate is set, so a test can hold a run open.
    """
    by_url = {url.lower(): path for url, path in repos.items()}

    def clone(url: str, dest: Path) -> Workspace:
        if gate is not None:
            gate.wait(timeout=30)
        src = by_url.get(url.strip().lower().removesuffix("/"))
        if src is None:
            raise UnsupportedRepo(CLONE_FAILED_COPY)
        shutil.copytree(src, dest)
        return load_workspace(dest, STUB_SHA)

    return clone

import base64
import json
import re
import subprocess
from pathlib import Path

import pytest

MARKER = re.compile(r"HEIST-FIXTURE:\s*(m[1-7])\b")


def _files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def _markers(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in _files(root):
        for m in MARKER.finditer(f.read_text()):
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def test_vuln_app_has_every_marker(vuln_app_path: Path) -> None:
    counts = _markers(vuln_app_path)
    for n in range(1, 8):
        assert counts.get(f"m{n}", 0) >= 1, f"missing marker m{n}"


def test_clean_app_has_no_markers(clean_app_path: Path) -> None:
    for f in _files(clean_app_path):
        assert "HEIST-FIXTURE" not in f.read_text(), f
    assert _markers(clean_app_path) == {}


def test_same_relative_file_list(vuln_app_path: Path, clean_app_path: Path) -> None:
    vuln = {p.relative_to(vuln_app_path) for p in _files(vuln_app_path)}
    clean = {p.relative_to(clean_app_path) for p in _files(clean_app_path)}
    assert vuln, "vuln_app is empty"
    assert vuln == clean


@pytest.mark.parametrize("app", ["vuln_app_path", "clean_app_path"])
def test_env_not_git_ignored(app: str, request: pytest.FixtureRequest) -> None:
    root: Path = request.getfixturevalue(app)
    env = root / ".env"
    assert env.is_file()
    result = subprocess.run(
        ["git", "check-ignore", "-q", str(env)], check=False, cwd=root, capture_output=True
    )
    assert result.returncode == 1


@pytest.mark.parametrize("app", ["vuln_app_path", "clean_app_path"])
def test_anon_jwt_role(app: str, request: pytest.FixtureRequest) -> None:
    root: Path = request.getfixturevalue(app)
    line = next(
        ln
        for ln in (root / ".env").read_text().splitlines()
        if ln.startswith("VITE_SUPABASE_ANON_KEY=")
    )
    token = line.split("=", 1)[1].strip()
    _header, payload, sig = token.split(".")
    assert sig
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    assert claims["role"] == "anon"
    assert claims["ref"] == "heistfixture"
    assert claims["iss"] == "supabase"

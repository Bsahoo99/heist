import shutil
import subprocess
from pathlib import Path

import pytest

from heist import fetch
from heist.fetch import UnsupportedRepo, clone_repo, detect_stack, load_workspace, parse_github_url
from heist.models import AppGraph, CodeRef, Node


def test_parse_github_url_variants():
    assert parse_github_url("https://github.com/acme/pawpal") == ("acme", "pawpal")
    assert parse_github_url("https://github.com/acme/pawpal.git") == ("acme", "pawpal")
    assert parse_github_url("github.com/acme/pawpal/tree/main") == ("acme", "pawpal")
    assert parse_github_url("https://www.github.com/acme/pawpal/") == ("acme", "pawpal")


def test_parse_github_url_rejects_other_hosts():
    with pytest.raises(UnsupportedRepo, match="public GitHub"):
        parse_github_url("https://gitlab.com/acme/pawpal")


def test_load_workspace_ignores_deps_and_builds(vuln_app_path, tmp_copy):
    root = tmp_copy(vuln_app_path)
    (root / "node_modules/x").mkdir(parents=True)
    (root / "node_modules/x/a.js").write_text("x")
    (root / "dist").mkdir()
    (root / "dist/b.js").write_text("x")
    ws = load_workspace(root)
    assert not any(f.startswith(("node_modules/", "dist/")) for f in ws.files)
    assert ".env" in ws.files
    assert ws.files == sorted(ws.files)


def test_detect_stack_vite(vuln_app_path):
    assert detect_stack(load_workspace(vuln_app_path)) == "vite_supabase"


def test_app_root_found_in_subfolder(vuln_app_path, tmp_path):
    shutil.copytree(vuln_app_path, tmp_path / "apps/web")
    (tmp_path / "README.md").write_text("hi")
    ws = load_workspace(tmp_path)
    assert ws.app_root == tmp_path / "apps/web"
    assert ws.root == tmp_path
    assert "README.md" not in ws.files
    assert "package.json" in ws.files
    assert detect_stack(ws) == "vite_supabase"


def test_too_many_files(tmp_path):
    for i in range(2001):
        (tmp_path / f"f{i}.ts").write_text("x")
    with pytest.raises(UnsupportedRepo, match="too big"):
        load_workspace(tmp_path)


def test_too_much_data(tmp_path):
    (tmp_path / "big.ts").write_bytes(b"x" * (5 * 1024 * 1024 + 1))
    with pytest.raises(UnsupportedRepo, match="too big"):
        load_workspace(tmp_path)


def test_unsupported_stack(tmp_path):
    (tmp_path / "main.py").write_text("print(1)")
    with pytest.raises(UnsupportedRepo, match="not supported yet"):
        detect_stack(load_workspace(tmp_path))


def test_detect_stack_next_wins(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"next": "1", "vite": "1", "@supabase/supabase-js": "2"}}'
    )
    assert detect_stack(load_workspace(tmp_path)) == "next_supabase"


def test_detect_stack_invalid_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{nope")
    with pytest.raises(UnsupportedRepo, match="not supported yet"):
        detect_stack(load_workspace(tmp_path))


def test_clone_failure_raises_unsupported(monkeypatch, tmp_path):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 128, "", "fatal")

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    with pytest.raises(UnsupportedRepo, match="couldn't fetch"):
        clone_repo("https://github.com/acme/pawpal", tmp_path / "dest")


def test_clone_success_reads_sha(monkeypatch, vuln_app_path, tmp_path):
    dest = tmp_path / "dest"

    def fake_run(cmd, **kwargs):
        if "clone" in cmd:
            shutil.copytree(vuln_app_path, dest)
            assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    ws = clone_repo("https://github.com/acme/pawpal", dest)
    assert ws.commit_sha == "abc123"
    assert isinstance(ws.root, Path)


def test_app_graph_node_lookup():
    n = Node(
        id="a",
        kind="page",
        name="A",
        zone="street",
        ref=CodeRef(file="a.ts", start_line=1, end_line=2),
    )
    g = AppGraph(stack="vite_supabase", nodes=[n], edges=[], has_db_rules=False, db=None)
    assert g.node("a") is n
    with pytest.raises(KeyError):
        g.node("missing")


def test_symlinked_file_excluded(vuln_app_path, tmp_copy, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("secret")
    root = tmp_copy(vuln_app_path)
    (root / "leak.ts").symlink_to(secret)
    ws = load_workspace(root)
    assert "leak.ts" not in ws.files
    assert ".env" in ws.files


def test_symlinked_package_json_treated_as_missing(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"dependencies": {"vite": "1", "@supabase/supabase-js": "2"}}')
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").symlink_to(outside)
    with pytest.raises(UnsupportedRepo, match="not supported yet"):
        detect_stack(load_workspace(root))


def test_clone_disables_symlinks(monkeypatch, vuln_app_path, tmp_path):
    dest = tmp_path / "dest"
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "clone" in cmd:
            shutil.copytree(vuln_app_path, dest)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "abc\n", "")

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    clone_repo("https://github.com/acme/pawpal", dest)
    clone_cmd = next(c for c in calls if "clone" in c)
    assert "core.symlinks=false" in clone_cmd
    assert clone_cmd.index("core.symlinks=false") < clone_cmd.index("clone")


def test_rev_parse_failure_raises_unsupported(monkeypatch, vuln_app_path, tmp_path):
    dest = tmp_path / "dest"

    def fake_run(cmd, **kwargs):
        if "clone" in cmd:
            shutil.copytree(vuln_app_path, dest)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise subprocess.TimeoutExpired(cmd, 60)

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    with pytest.raises(UnsupportedRepo, match="couldn't fetch"):
        clone_repo("https://github.com/acme/pawpal", dest)

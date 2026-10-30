import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from heist import fetch
from heist.fetch import (
    UnsupportedRepo,
    clone_repo,
    detect_stack,
    fetch_commit,
    load_workspace,
    ls_remote_head,
    parse_github_url,
)
from heist.fetch import resolve_head as real_resolve_head  # bound before conftest stubs it
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


# ---------------------------------------------------------------------------------------------
# The commit: `git ls-remote` before cloning, then a clone at exactly that commit

SHA = "c" * 40


def _git(*args: str, cwd: Path) -> str:
    cmd = ["git", "-c", "user.name=Heist", "-c", "user.email=heist@example.test"]
    cmd += ["-c", "commit.gpgsign=false", *args]
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def origin(tmp_path: Path) -> tuple[Path, list[str]]:
    """A local repo with two commits; any commit can be fetched by its SHA."""
    repo = tmp_path / "origin"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    shas = []
    for n in (1, 2):
        (repo / "app.ts").write_text(f"export const version = {n};\n")
        _git("add", "app.ts", cwd=repo)
        _git("commit", "-q", "-m", f"v{n}", cwd=repo)
        shas.append(_git("rev-parse", "HEAD", cwd=repo))
    return repo, shas


def test_ls_remote_reads_head(origin):
    repo, shas = origin
    assert ls_remote_head(str(repo)) == shas[1]


def test_ls_remote_of_a_missing_repo_fails_like_a_bad_clone(tmp_path):
    with pytest.raises(UnsupportedRepo, match="couldn't fetch"):
        ls_remote_head(str(tmp_path / "missing"))


def test_resolve_head_asks_github_without_prompting(monkeypatch):
    seen: dict[str, Any] = {}

    def fake_run(cmd, **kwargs):
        seen.update(cmd=cmd, **kwargs)
        return subprocess.CompletedProcess(cmd, 0, f"{SHA}\tHEAD\n", "")

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    assert real_resolve_head("github.com/Acme/PawPal.git") == SHA
    assert seen["cmd"] == ["git", "ls-remote", "https://github.com/Acme/PawPal.git", "HEAD"]
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert seen["timeout"] == 15


@pytest.mark.parametrize(
    "outcome",
    [
        subprocess.CompletedProcess([], 128, "", "fatal: repository not found"),
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0, "not-a-sha\tHEAD\n", ""),
        subprocess.TimeoutExpired("git", 15),
        OSError("no git"),
    ],
)
def test_resolve_head_failures_say_we_could_not_fetch(monkeypatch, outcome):
    def fake_run(cmd, **kwargs):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    with pytest.raises(UnsupportedRepo, match="couldn't fetch"):
        real_resolve_head("https://github.com/acme/pawpal")


def test_resolve_head_only_takes_github_urls(monkeypatch):
    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: pytest.fail("ran git"))
    with pytest.raises(UnsupportedRepo, match="public GitHub"):
        real_resolve_head("/etc")


def test_fetch_commit_checks_out_exactly_that_commit(origin, tmp_path):
    repo, shas = origin
    ws = fetch_commit(str(repo), tmp_path / "dest", shas[0])
    assert ws.commit_sha == shas[0]
    assert (ws.root / "app.ts").read_text() == "export const version = 1;\n"


def test_fetch_commit_of_an_unknown_commit_fails(origin, tmp_path):
    repo, _ = origin
    with pytest.raises(UnsupportedRepo, match="couldn't fetch"):
        fetch_commit(str(repo), tmp_path / "dest", "d" * 40)


def test_clone_at_a_sha_fetches_it_without_symlinks(monkeypatch, vuln_app_path, tmp_path):
    dest = tmp_path / "dest"
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        if "init" in cmd:
            shutil.copytree(vuln_app_path, dest)
        if "rev-parse" in cmd:
            return subprocess.CompletedProcess(cmd, 0, f"{SHA}\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    ws = clone_repo("https://github.com/acme/pawpal", dest, SHA)
    assert ws.commit_sha == SHA
    fetch_cmd = next(c for c in calls if "fetch" in c)
    assert fetch_cmd[-2:] == ["https://github.com/acme/pawpal.git", SHA]
    checkout = next(c for c in calls if "checkout" in c)
    assert "core.symlinks=false" in checkout
    assert checkout.index("core.symlinks=false") < checkout.index("checkout")


def test_clone_at_a_sha_refuses_a_different_head(monkeypatch, vuln_app_path, tmp_path):
    dest = tmp_path / "dest"

    def fake_run(cmd, **kwargs):
        if "init" in cmd:
            shutil.copytree(vuln_app_path, dest)
        if "rev-parse" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "e" * 40 + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    with pytest.raises(UnsupportedRepo, match="couldn't fetch"):
        clone_repo("https://github.com/acme/pawpal", dest, SHA)

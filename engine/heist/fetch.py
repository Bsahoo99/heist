import json
import os
import re
import subprocess
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from heist.models import Stack

MAX_FILES = 2000
MAX_BYTES = 5 * 1024 * 1024
MAX_APP_DEPTH = 3

IGNORED_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".vercel", "coverage"}
IGNORED_PREFIXES = ("public/assets",)
IGNORED_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".mp4", ".mov", ".webm", ".mp3", ".wav",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".gz", ".tar",
}  # fmt: skip
IGNORED_NAMES = {"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lockb"}

_NAME = r"[A-Za-z0-9_.-]+"
_URL_RE = re.compile(rf"^(?:https?://)?(?:www\.)?github\.com/({_NAME})/({_NAME})(?:/.*)?$")

BAD_URL_COPY = "Paste a public GitHub repo URL, like https://github.com/you/your-app."
TOO_BIG_COPY = "This repo is too big for Heist right now ({why}). Try a smaller app."
UNSUPPORTED_STACK_COPY = (
    "Heist supports Vite + React + Supabase and Next.js + Supabase apps. "
    "This stack is not supported yet."
)
CLONE_FAILED_COPY = "We couldn't fetch that repo. Make sure it is public and the URL is right."


class UnsupportedRepo(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Workspace:
    root: Path
    app_root: Path
    commit_sha: str
    files: list[str]  # relative to app_root, POSIX separators, sorted


def parse_github_url(url: str) -> tuple[str, str]:
    m = _URL_RE.match(url.strip())
    if not m:
        raise UnsupportedRepo(BAD_URL_COPY)
    owner, repo = m.group(1), m.group(2)
    repo = repo.removesuffix(".git")
    if not repo or repo in {".", ".."} or owner in {".", ".."}:
        raise UnsupportedRepo(BAD_URL_COPY)
    return owner, repo


def _is_ignored_rel(rel: str) -> bool:
    return any(rel == p or rel.startswith(p + "/") for p in IGNORED_PREFIXES)


def _walk(root: Path) -> list[str]:
    """All kept files under root, relative POSIX paths. Raises if over the file cap."""
    out: list[str] = []
    real_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [
            d
            for d in dirnames
            if d not in IGNORED_DIRS and not _is_ignored_rel(f"{rel_dir}/{d}".lstrip("/"))
        ]
        for name in filenames:
            if name in IGNORED_NAMES or Path(name).suffix.lower() in IGNORED_EXTS:
                continue
            rel = f"{rel_dir}/{name}".lstrip("/")
            if _is_ignored_rel(rel):
                continue
            full = Path(dirpath) / name
            if full.is_symlink() or not full.resolve().is_relative_to(real_root):
                continue
            out.append(rel)
            if len(out) > MAX_FILES:
                raise UnsupportedRepo(TOO_BIG_COPY.format(why="over 2,000 files"))
    return sorted(out)


def _has_supabase(root: Path, pkg_json: Path) -> bool:
    deps = _read_deps(root, pkg_json)
    return deps is not None and "@supabase/supabase-js" in deps


def _read_deps(root: Path, pkg_json: Path) -> set[str] | None:
    try:
        if pkg_json.is_symlink() or not pkg_json.resolve().is_relative_to(root.resolve()):
            return None
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(section, dict):
            deps.update(str(k) for k in section)  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    return deps


def _find_app_root(root: Path) -> Path:
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    while queue:
        level = [queue.popleft()]
        depth = level[0][1]
        while queue and queue[0][1] == depth:
            level.append(queue.popleft())
        level.sort(key=lambda item: item[0].as_posix())
        for directory, _ in level:
            if _has_supabase(root, directory / "package.json"):
                return directory
        if depth >= MAX_APP_DEPTH:
            continue
        for directory, _ in level:
            try:
                children = sorted(
                    p for p in directory.iterdir() if p.is_dir() and not p.is_symlink()
                )
            except OSError:
                continue
            for child in children:
                rel = child.relative_to(root).as_posix()
                if child.name in IGNORED_DIRS or _is_ignored_rel(rel):
                    continue
                queue.append((child, depth + 1))
    return root


def load_workspace(path: Path, commit_sha: str = "local") -> Workspace:
    root = path
    all_files = _walk(root)
    total = 0
    for rel in all_files:
        try:
            total += (root / rel).lstat().st_size
        except OSError:
            continue
        if total > MAX_BYTES:
            raise UnsupportedRepo(TOO_BIG_COPY.format(why="over 5 MB of source"))
    app_root = _find_app_root(root)
    if app_root == root:
        files = all_files
    else:
        prefix = app_root.relative_to(root).as_posix() + "/"
        files = [f[len(prefix) :] for f in all_files if f.startswith(prefix)]
    return Workspace(root=root, app_root=app_root, commit_sha=commit_sha, files=sorted(files))


LS_REMOTE_TIMEOUT_S = 15
GIT_TIMEOUT_S = 60
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _git_env() -> dict[str, str]:
    # Never ask for credentials: a private or missing repo fails at once instead of hanging.
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


def _git(args: list[str], timeout: float = GIT_TIMEOUT_S) -> str:
    """Run git; any failure (exit code, timeout, no git) is the clone-failed copy."""
    try:
        proc = subprocess.run(
            ["git", *args],
            check=False,
            env=_git_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        raise UnsupportedRepo(CLONE_FAILED_COPY) from None
    if proc.returncode != 0:
        raise UnsupportedRepo(CLONE_FAILED_COPY)
    return proc.stdout


def _github_remote(url: str) -> str:
    owner, repo = parse_github_url(url)
    return f"https://github.com/{owner}/{repo}.git"


def ls_remote_head(remote: str) -> str:
    """The commit `remote`'s HEAD points at, without cloning anything."""
    out = _git(["ls-remote", remote, "HEAD"], timeout=LS_REMOTE_TIMEOUT_S)
    first = out.split("\n", 1)[0].split("\t", 1)[0].strip().lower()
    if not _SHA_RE.match(first):
        raise UnsupportedRepo(CLONE_FAILED_COPY)
    return first


def resolve_head(url: str) -> str:
    """The commit a public GitHub repo's default branch is at: the cache key for its analysis."""
    return ls_remote_head(_github_remote(url))


def _rev_parse_head(dest: Path) -> str:
    sha = _git(["-C", str(dest), "rev-parse", "HEAD"]).strip()
    if not sha:
        raise UnsupportedRepo(CLONE_FAILED_COPY)
    return sha


def fetch_commit(remote: str, dest: Path, sha: str) -> Workspace:
    """Exactly commit `sha` of `remote` in `dest`, history depth 1, symlinks checked out as files."""
    no_links = ["-c", "core.symlinks=false"]
    _git([*no_links, "init", "-q", str(dest)])
    _git([*no_links, "-C", str(dest), "fetch", "-q", "--depth", "1", "--no-tags", remote, sha])
    _git([*no_links, "-C", str(dest), "checkout", "-q", "--detach", "FETCH_HEAD"])
    if _rev_parse_head(dest) != sha:
        raise UnsupportedRepo(CLONE_FAILED_COPY)
    return load_workspace(dest, sha)


def clone_repo(url: str, dest: Path, sha: str | None = None) -> Workspace:
    """A shallow clone of a public GitHub repo: at `sha` when given, else its default branch."""
    remote = _github_remote(url)
    if sha is not None:
        return fetch_commit(remote, dest, sha)
    _git(
        [
            "-c",
            "core.symlinks=false",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            remote,
            str(dest),
        ]
    )
    return load_workspace(dest, _rev_parse_head(dest))


def detect_stack(ws: Workspace) -> Stack:
    deps = _read_deps(ws.root, ws.app_root / "package.json")
    if deps is None or "@supabase/supabase-js" not in deps:
        raise UnsupportedRepo(UNSUPPORTED_STACK_COPY)
    if "next" in deps:
        return "next_supabase"
    if "vite" in deps:
        return "vite_supabase"
    raise UnsupportedRepo(UNSUPPORTED_STACK_COPY)

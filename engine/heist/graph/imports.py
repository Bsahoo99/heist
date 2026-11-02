"""Resolve JS/TS import specifiers to workspace files (relative paths, `@/` and tsconfig paths)."""

import json
import posixpath
import re

from heist.fetch import Workspace

IMPORT_RE = re.compile(r"""(?:from|import)\s*\(?\s*['"]([^'"]+)['"]""")
CONFIG_FILES = ("tsconfig.json", "jsconfig.json")
DEFAULT_EXTS = (".ts", ".tsx", ".js", ".jsx")

Aliases = list[tuple[str, list[str]]]


def _read(ws: Workspace, rel: str, present: set[str]) -> str | None:
    if rel not in present:
        return None
    try:
        return (ws.app_root / rel).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def alias_map(ws: Workspace, present: set[str]) -> Aliases:
    """(prefix, base dirs) pairs for `@/` and tsconfig/jsconfig `compilerOptions.paths`."""
    aliases: Aliases = []
    for name in CONFIG_FILES:
        text = _read(ws, name, present)
        if text is None:
            continue
        try:
            data = json.loads(re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE))
        except json.JSONDecodeError:
            continue
        opts = data.get("compilerOptions") if isinstance(data, dict) else None
        if not isinstance(opts, dict) or not isinstance(opts.get("paths"), dict):
            continue
        base = posixpath.normpath(str(opts.get("baseUrl") or "."))
        for pattern, targets in opts["paths"].items():
            if not (
                isinstance(pattern, str) and pattern.endswith("*") and isinstance(targets, list)
            ):
                continue
            dirs = [
                posixpath.normpath(posixpath.join(base, t[:-1])) if t.endswith("*") else ""
                for t in targets
                if isinstance(t, str)
            ]
            aliases.append((pattern[:-1], [d for d in dirs if d]))
    if not any(prefix == "@/" for prefix, _ in aliases):
        aliases.append(("@/", ["src", "."]))
    return aliases


def resolve_imports(
    rel: str,
    text: str,
    present: set[str],
    aliases: Aliases,
    exts: tuple[str, ...] = DEFAULT_EXTS,
) -> list[str]:
    """Workspace files that `rel` imports by relative path or alias, one level deep."""
    out: list[str] = []
    base = posixpath.dirname(rel)
    for spec in IMPORT_RE.findall(text):
        roots: list[str] = []
        if spec.startswith("."):
            roots.append(posixpath.normpath(posixpath.join(base, spec)))
        else:
            for prefix, dirs in aliases:
                if spec.startswith(prefix):
                    roots.extend(
                        posixpath.normpath(posixpath.join(d, spec[len(prefix) :])) for d in dirs
                    )
        for joined in roots:
            cands = (
                joined,
                *(joined + e for e in exts),
                *(f"{joined}/index{e}" for e in exts),
            )
            hit = next((c for c in cands if c in present), None)
            if hit is not None and hit.endswith(exts):
                out.append(hit)
                break
    return out

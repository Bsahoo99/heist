"""Which files are browser code: the ones the front-end bundle can reach.

Vite: from the module scripts in `index.html` (else `src/main.*`), following imports.
Next: from every file under `app/` and `pages/`, minus API routes, route handlers and server
actions, following imports. Without an entry point, every source file in a front-end folder is
an entry instead. Either way, files that only run on a server never count: "use server" and
"server-only" files, route handlers, Node shebang scripts, `backend/` and `server/` folders,
and Edge Function sources. Tests and root config or Node scripts never start the walk, but they
count when the bundle imports them.
"""

import posixpath
import re
from collections import deque

from heist.fetch import Workspace
from heist.graph.imports import alias_map, resolve_imports
from heist.models import Stack

SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte")
USE_SERVER_RE = re.compile(r"""\A(?:\s|//[^\n]*\n|/\*.*?\*/)*['"]use server['"]""", re.DOTALL)
SERVER_ONLY_RE = re.compile(r"""(?:import\s+['"]server-only['"]|from\s+['"]server-only['"])""")
ROUTE_RE = re.compile(r"(?:^|/)app/(?:.*/)?route\.(?:ts|js|tsx|jsx)$")
NODE_SHEBANG_RE = re.compile(r"\A#![^\n]*\bnode\b")
TEST_RE = re.compile(
    r"(?:^|/)(?:__tests__|__mocks__|tests?|e2e|cypress|playwright|fixtures)/"
    r"|\.(?:test|spec|cy)\.[a-z]+$"
)
SERVER_DIR_RE = re.compile(
    r"(?:^|/)(?:backend|server)/|(?:^|/)\.?supabase/functions/|(?:^|/)pages/api/|(?:^|/)\.bolt/"
)
NEXT_ROOTS = ("app/", "src/app/", "pages/", "src/pages/")
VITE_MAINS = tuple(f"src/main{e}" for e in (".tsx", ".ts", ".jsx", ".js"))
SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"'?#]+)""", re.IGNORECASE)
GLOB_RE = re.compile(r"""import\.meta\.glob(?:Eager)?\s*\(\s*\[?\s*['"]([^'"*]*)""")


def is_test_file(rel: str) -> bool:
    return bool(TEST_RE.search(rel))


def is_server_path(rel: str) -> bool:
    """Paths that are server code by where they live, whatever imports them."""
    return bool(SERVER_DIR_RE.search(rel) or ROUTE_RE.search(rel))


def _is_entry(rel: str) -> bool:
    """A file that may start the walk. Tests never do, but a test-named folder the bundle
    imports (`src/pages/tests/Quiz.tsx`) is still reached through that import."""
    return rel.endswith(SOURCE_EXTS) and not is_server_path(rel) and not is_test_file(rel)


def _is_package_root(ws: Workspace, parts: tuple[str, ...]) -> bool:
    return not parts or "/".join((*parts, "package.json")) in ws.files


def is_node_script(ws: Workspace, rel: str) -> bool:
    """Node scripts by location: `scripts/` or `seed.*` at a package root, `supabase/seed*`,
    and any source file at the package root (config files, one-off `.mjs` scripts)."""
    parts = tuple(rel.split("/"))
    if rel.startswith("supabase/seed"):
        return True
    for i, part in enumerate(parts[:-1]):
        if part == "scripts" and _is_package_root(ws, parts[:i]):
            return True
    return _is_package_root(ws, parts[:-1]) and rel.endswith(SOURCE_EXTS)


def _read(ws: Workspace, rel: str) -> str | None:
    try:
        return (ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def is_server_only_text(text: str) -> bool:
    return bool(
        USE_SERVER_RE.search(text) or SERVER_ONLY_RE.search(text) or NODE_SHEBANG_RE.search(text)
    )


def _vite_entries(ws: Workspace, present: set[str]) -> list[str]:
    entries: list[str] = []
    if "index.html" in present:
        html = _read(ws, "index.html") or ""
        for src in SCRIPT_SRC_RE.findall(html):
            rel = posixpath.normpath(src.lstrip("/"))
            if rel in present:
                entries.append(rel)
    return entries or [m for m in VITE_MAINS if m in present][:1]


def _next_entries(present: set[str]) -> list[str]:
    return sorted(rel for rel in present if rel.startswith(NEXT_ROOTS) and _is_entry(rel))


def _fallback_entries(ws: Workspace, present: set[str]) -> list[str]:
    return sorted(rel for rel in present if _is_entry(rel) and not is_node_script(ws, rel))


def _globbed(rel: str, text: str, present: set[str]) -> list[str]:
    """Files an `import.meta.glob('./pages/**/*.tsx')` call can load: everything under its dir."""
    out: list[str] = []
    for pattern in GLOB_RE.findall(text):
        if not pattern.startswith("."):
            continue
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), pattern))
        prefix = base.rstrip("/") + "/"
        out.extend(p for p in present if p.startswith(prefix) and p.endswith(SOURCE_EXTS))
    return out


def browser_files(ws: Workspace, stack: Stack) -> set[str]:
    """Source files the front-end bundle can reach."""
    present = set(ws.files)
    entries = _vite_entries(ws, present) if stack == "vite_supabase" else _next_entries(present)
    if not entries:
        entries = _fallback_entries(ws, present)
    aliases = alias_map(ws, present)
    seen: set[str] = set()
    out: set[str] = set()
    queue = deque(entries)
    while queue:
        rel = queue.popleft()
        if rel in seen:
            continue
        seen.add(rel)
        if is_server_path(rel):
            continue
        text = _read(ws, rel)
        if text is None or is_server_only_text(text):
            continue
        out.add(rel)
        queue.extend(resolve_imports(rel, text, present, aliases, SOURCE_EXTS))
        queue.extend(_globbed(rel, text, present))
    return out

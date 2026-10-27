"""Mistakes 5, 6 and 7: Edge Functions and routes that anyone can call, trust the request too much,
or spend paid API credits.

Semgrep (heist/rules/heist-functions.yml) only locates facts: auth calls, handlers, paid API
calls and id filters. This module combines them per file. "Has no auth check" is decided here, in
Python, from the absence of any auth call. That is more robust than a file-level
pattern-not-inside, and it lets a shared helper that is imported by relative path count.
"""

import json
import logging
import os
import posixpath
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from heist.fetch import Workspace
from heist.graph.js import FUNCTIONS_DIR, SOURCE_EXTS, route_id_for
from heist.graph.supabase import list_edge_functions, read_function_config
from heist.models import AppGraph, CodeRef, Finding

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
COMMUNITY_CONFIG = "p/typescript"
COMMUNITY_ENV = "HEIST_SEMGREP_COMMUNITY"
SEMGREP_TIMEOUT_S = 120

HTTP_VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
PAID_HOST_RE = re.compile(
    r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com"
    r"|api\.replicate\.com|api\.meta\.ai)"
)
SDK_HOSTS = {"OpenAI": "api.openai.com", "Anthropic": "api.anthropic.com"}
OWNER_FILTER_RE = re.compile(r"\b(user_id|owner_id)\b")
IMPORT_RE = re.compile(r"""(?:from|import)\s*\(?\s*['"]([^'"]+)['"]""")
SEMGREP_CHUNK = 500
MIDDLEWARE_FILES = (
    "middleware.ts",
    "middleware.js",
    "src/middleware.ts",
    "src/middleware.js",
)
CONFIG_FILES = ("tsconfig.json", "jsconfig.json")
SEVERITY_MAP: dict[str, Literal["high", "medium", "low"]] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


@dataclass
class Hit:
    rule: str
    start_line: int
    end_line: int
    text: str


@dataclass
class Target:
    """An Edge Function entry file, a Next route file or a "use server" file."""

    rel: str
    name: str  # evidence["function"]
    node_id: str
    display: str  # used in plain-English titles
    is_function: bool
    hits: list[Hit] = field(default_factory=list)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _read(ws: Workspace, rel: str, present: set[str]) -> str | None:
    if rel not in present:
        return None
    try:
        # newline="" keeps CRLF so semgrep's byte offsets line up with what we slice
        with (ws.app_root / rel).open(encoding="utf-8", newline="") as fh:
            return fh.read()
    except (UnicodeDecodeError, OSError):
        return None


def _alias_map(ws: Workspace, present: set[str]) -> list[tuple[str, list[str]]]:
    """(prefix, base dirs) pairs for `@/` and tsconfig/jsconfig `compilerOptions.paths`."""
    aliases: list[tuple[str, list[str]]] = []
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


def _resolve_imports(
    rel: str, text: str, present: set[str], aliases: list[tuple[str, list[str]]]
) -> list[str]:
    """Workspace files imported by relative path or alias, one level deep."""
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
                *(joined + e for e in SOURCE_EXTS),
                *(f"{joined}/index{e}" for e in SOURCE_EXTS),
            )
            hit = next((c for c in cands if c in present), None)
            if hit is not None and hit.endswith(SOURCE_EXTS):
                out.append(hit)
                break
    return out


def _collect_targets(ws: Workspace, texts: dict[str, str]) -> list[Target]:
    targets: list[Target] = []
    entries = list_edge_functions(ws)
    for name, rel in entries.items():
        if rel in texts:
            targets.append(Target(rel, name, f"fn:{name}", name, True))
    for rel, text in texts.items():
        if rel.startswith(FUNCTIONS_DIR) or not rel.endswith(SOURCE_EXTS):
            continue
        if "use server" not in text and not re.search(r"(^|/)route\.(ts|js)$", rel):
            continue
        route_id = route_id_for(rel, text)
        if route_id is None:
            continue
        display = route_id.removeprefix("route:action:").removeprefix("route:")
        if route_id.startswith("route:action:"):
            display = posixpath.basename(display)
        targets.append(Target(rel, route_id, route_id, display, False))
    return targets


def _run_semgrep(config: str, files: list[Path]) -> dict[str, Any] | None:
    """Scan in chunks so a huge file list cannot overflow argv; merge the results."""
    binary = shutil.which("semgrep")
    if binary is None:
        log.warning("semgrep not found, skipping function checks")
        return None
    merged: dict[str, Any] = {"results": []}
    ok = False
    for i in range(0, len(files), SEMGREP_CHUNK):
        chunk = files[i : i + SEMGREP_CHUNK]
        cmd = [
            binary,
            "scan",
            "--config",
            config,
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            "--timeout",
            "30",
            *map(str, chunk),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT_S, check=False
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("semgrep failed: %s", exc)
            continue
        try:
            data = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError):
            log.warning(
                "semgrep exited with %s and no JSON: %s", proc.returncode, proc.stderr[:300]
            )
            continue
        if isinstance(data, dict):
            ok = True
            merged["results"].extend(data.get("results", []))
    return merged if ok else None


def _path_map(ws: Workspace, rels: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for rel in rels:
        p = ws.app_root / rel
        mapping[str(p)] = rel
        mapping[os.path.realpath(p)] = rel
    return mapping


def _hits_by_file(
    data: dict[str, Any], mapping: dict[str, str], texts: dict[str, str]
) -> dict[str, list[Hit]]:
    out: dict[str, list[Hit]] = {}
    for r in data.get("results", []):
        rel = mapping.get(r.get("path", "")) or mapping.get(os.path.realpath(r.get("path", "")))
        if rel is None or rel not in texts:  # drop anything outside ws.files
            continue
        start, end = r["start"], r["end"]
        raw = texts[rel].encode("utf-8")
        snippet = raw[start["offset"] : end["offset"]].decode("utf-8", "replace")
        rule = str(r.get("check_id", "")).rsplit(".", 1)[-1]
        out.setdefault(rel, []).append(Hit(rule, start["line"], end["line"], snippet))
    return out


def _config_ref(ws: Workspace, name: str, present: set[str]) -> CodeRef | None:
    """Line of `verify_jwt = false` inside [functions.<name>] in supabase/config.toml."""
    cfg = read_function_config(ws).get(name, {})
    text = _read(ws, "supabase/config.toml", present)
    if cfg.get("verify_jwt") is not False or text is None:
        return None
    header = re.compile(rf"""^\s*\[functions\.["']?{re.escape(name)}["']?\]\s*(#.*)?$""")
    inside = False
    for i, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("["):
            inside = bool(header.match(line))
        elif inside and re.match(r"\s*verify_jwt\s*=\s*false\b", line):
            return CodeRef(file="supabase/config.toml", start_line=i, end_line=i)
    return None


def _handler_ref(t: Target) -> CodeRef:
    chosen: Hit | None = None
    for h in sorted((h for h in t.hits if h.rule == "heist-handler"), key=lambda h: h.start_line):
        if t.is_function:
            if h.text.startswith(("Deno.serve", "serve(")):
                chosen = h
                break
        else:
            m = re.match(r"export\s+(?:async\s+)?(?:function|const)\s+(\w+)", h.text)
            if not m:
                continue
            if t.node_id.startswith("route:action:") or m.group(1) in HTTP_VERBS:
                chosen = h
                break
    line = chosen.start_line if chosen else 1
    return CodeRef(file=t.rel, start_line=line, end_line=line)


def _owner_scoped(lines: list[str], hit: Hit) -> bool:
    i, j = hit.start_line - 1, hit.end_line - 1
    while j + 1 < len(lines) and lines[j + 1].lstrip().startswith("."):
        j += 1
    return bool(OWNER_FILTER_RE.search("\n".join(lines[i : j + 1])))


def _paid_hosts(t: Target) -> dict[str, int]:
    """host -> first line, for fetches and SDK clients of paid AI APIs."""
    hosts: dict[str, int] = {}
    for h in t.hits:
        host: str | None = None
        if h.rule == "heist-paid-api-call":
            m = PAID_HOST_RE.search(h.text)
            host = m.group(1) if m else None
        elif h.rule == "heist-paid-sdk-client":
            m = re.match(r"new\s+(\w+)", h.text)
            host = SDK_HOSTS.get(m.group(1)) if m else None
        if host and (host not in hosts or h.start_line < hosts[host]):
            hosts[host] = h.start_line
    return hosts


def _analyze(
    ws: Workspace, t: Target, authed: bool, text: str, present: set[str], mw_auth: bool
) -> list[Finding]:
    out: list[Finding] = []
    handler = _handler_ref(t)

    if not authed:
        hosts = _paid_hosts(t)
        for host, line in sorted(hosts.items()):
            out.append(
                Finding(
                    id=f"m7-{_slug(t.name)}-{_slug(host)}",
                    mistake=7,
                    severity="high",
                    status="confirmed",
                    title=f"Anyone can make {t.display} spend your {_vendor(host)} credits",
                    node_ids=[t.node_id],
                    refs=[CodeRef(file=t.rel, start_line=line, end_line=line)],
                    source="heist",
                    evidence={"function": t.name, "host": host},
                )
            )
        if not hosts:
            refs = [handler]
            if t.is_function and (cfg := _config_ref(ws, t.name, present)) is not None:
                refs.append(cfg)
            soft = mw_auth and not t.is_function
            out.append(
                Finding(
                    id=f"m5-{_slug(t.name)}",
                    mistake=5,
                    severity="medium" if soft else "high",
                    status="possible" if soft else "confirmed",
                    title=(
                        f"{t.display} has no sign-in check of its own (middleware may cover it)"
                        if soft
                        else f"Anyone on the internet can call {t.display}"
                    ),
                    node_ids=[t.node_id],
                    refs=refs,
                    source="heist",
                    evidence={"function": t.name},
                )
            )

    if any(h.rule == "heist-service-role-client" for h in t.hits):
        lines = text.splitlines()
        for h in sorted(t.hits, key=lambda h: h.end_line):
            if h.rule != "heist-id-from-request" or _owner_scoped(lines, h):
                continue
            out.append(
                Finding(
                    id=f"m6-{_slug(t.name)}-{h.end_line}",
                    mistake=6,
                    severity="medium",
                    status="possible",
                    title=f"{t.display} may let one user change another user's records",
                    node_ids=[t.node_id],
                    refs=[CodeRef(file=t.rel, start_line=h.end_line, end_line=h.end_line)],
                    source="heist",
                    evidence={"function": t.name},
                )
            )
    return out


def _vendor(host: str) -> str:
    return {
        "api.openai.com": "OpenAI",
        "api.anthropic.com": "Anthropic",
        "generativelanguage.googleapis.com": "Google AI",
        "api.replicate.com": "Replicate",
        "api.meta.ai": "Meta AI",
    }.get(host, host)


def _community_findings(data: dict[str, Any], app_root: Path, files: set[str]) -> list[Finding]:
    out: list[Finding] = []
    for r in data.get("results", []):
        raw = Path(str(r.get("path", "")))
        try:
            rel = raw.relative_to(app_root).as_posix()
        except ValueError:
            try:
                rel = raw.resolve().relative_to(app_root.resolve()).as_posix()
            except (ValueError, OSError):
                continue
        if rel not in files:
            continue
        extra = r.get("extra", {})
        rule = str(r.get("check_id", "rule"))
        line = int(r["start"]["line"])
        message = (
            str(extra.get("message", rule)).strip().splitlines()[0]
            if extra.get("message")
            else rule
        )
        out.append(
            Finding(
                id=f"m0-{_slug(rule.rsplit('.', 1)[-1])}-{_slug(rel)}-{line}",
                mistake=0,
                severity=SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "low"),
                status="possible",
                title=message,
                node_ids=[],
                refs=[CodeRef(file=rel, start_line=line, end_line=int(r["end"]["line"]))],
                source="semgrep_community",
                evidence={"rule": rule},
            )
        )
    return out


def find_function_issues(ws: Workspace, g: AppGraph) -> list[Finding]:
    present = set(ws.files)
    texts: dict[str, str] = {}
    for rel in ws.files:
        if not rel.endswith(SOURCE_EXTS):
            continue
        in_functions = rel.startswith(FUNCTIONS_DIR)
        t = _read(ws, rel, present)
        if t is not None and (
            in_functions or "use server" in t or re.search(r"(^|/)route\.(ts|js)$", rel)
        ):
            texts[rel] = t

    targets = _collect_targets(ws, texts)
    aliases = _alias_map(ws, present)

    # one level of imports (relative, `@/`, tsconfig paths), so a shared auth helper counts
    imports: dict[str, list[str]] = {}
    for t in targets:
        found = _resolve_imports(t.rel, texts[t.rel], present, aliases)
        imports[t.rel] = found
        for h in found:
            if h not in texts and (ht := _read(ws, h, present)) is not None:
                texts[h] = ht
    middleware = [m for m in MIDDLEWARE_FILES if m in present]
    for m in middleware:
        if m not in texts and (mt := _read(ws, m, present)) is not None:
            texts[m] = mt

    out: list[Finding] = []
    if targets:
        rels = sorted(texts)
        data = _run_semgrep(str(RULES_DIR), [ws.app_root / r for r in rels])
        if data is not None:
            by_file = _hits_by_file(data, _path_map(ws, rels), texts)

            def has(rel: str, *rules: str) -> bool:
                return any(h.rule in rules for h in by_file.get(rel, []))

            public = ("heist-auth-flow", "heist-auth-reexport")
            mw_auth = any(has(m, "heist-auth-call") for m in middleware)
            for t in targets:
                t.hits = by_file.get(t.rel, [])
                files = [t.rel, *imports.get(t.rel, [])]
                authed = any(has(f, "heist-auth-call") for f in files) or has(t.rel, *public)
                out.extend(_analyze(ws, t, authed, texts[t.rel], present, mw_auth))

    if os.environ.get(COMMUNITY_ENV) == "1":
        sources = [r for r in ws.files if r.endswith(SOURCE_EXTS)]
        if sources:
            data = _run_semgrep(COMMUNITY_CONFIG, [ws.app_root / r for r in sources])
            if data is not None:
                out.extend(_community_findings(data, ws.app_root, present))
    return out

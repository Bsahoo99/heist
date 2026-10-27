"""Mistakes 1 and 2: secrets and the Supabase service role key in the front end."""

import base64
import binascii
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from heist.fetch import Workspace
from heist.models import AppGraph, CodeRef, Finding

log = logging.getLogger(__name__)

FRONT_PREFIXES = ("VITE_", "NEXT_PUBLIC_")
SECRET_NAME_RE = re.compile(r"KEY|SECRET|TOKEN|PASSWORD|PASSWD", re.IGNORECASE)
ENV_EXCLUDED_SUFFIXES = (".example", ".sample", ".template")
PUBLIC_NAME_RE = re.compile(r"ANON|PUBLISHABLE|SITE_KEY|PUBLIC_KEY", re.IGNORECASE)
PUBLIC_VALUE_PREFIXES = ("sb_publishable_", "pk_live_", "pk_test_", "phc_", "AIza")
URL_NAME_LINE_RE = re.compile(r"[A-Za-z0-9_]*_URL\b\s*[:=]", re.IGNORECASE)
SOURCE_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"}
SERVICE_ROLE_RE = re.compile(r"\b[A-Za-z0-9_]*SERVICE_ROLE[A-Za-z0-9_]*\b")
ENV_ACCESS_RE = re.compile(r"\benv\b")
USE_SERVER_RE = re.compile(r"""\A(?:\s|//[^\n]*\n|/\*.*?\*/)*['"]use server['"]""", re.DOTALL)
SERVER_ONLY_RE = re.compile(r"""(?:import\s+['"]server-only['"]|from\s+['"]server-only['"])""")
ROUTE_RE = re.compile(r"(?:^|/)app/(?:.*/)?route\.(?:ts|js|tsx|jsx)$")
GITLEAKS_TIMEOUT = 60


def _is_env_named(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env.")


def _is_env_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return _is_env_named(rel) and not name.endswith(ENV_EXCLUDED_SUFFIXES)


def _read(ws: Workspace, rel: str) -> str | None:
    if rel not in ws.files:
        return None
    try:
        return (ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _in_frontend_scope(ws: Workspace, rel: str, cache: dict[str, bool]) -> bool:
    if rel in cache:
        return cache[rel]
    ok = True
    if rel.startswith("supabase/functions/") or ROUTE_RE.search(rel):
        ok = False
    elif Path(rel).suffix.lower() in SOURCE_EXTS:
        text = _read(ws, rel)
        if text is not None and (USE_SERVER_RE.search(text) or SERVER_ONLY_RE.search(text)):
            ok = False
    cache[rel] = ok
    return ok


def decode_jwt_payload(value: str) -> dict[str, Any] | None:
    """Decode the payload segment only. Never verifies, never raises."""
    try:
        parts = value.split(".")
        if len(parts) != 3 or not parts[0].startswith("eyJ"):
            return None
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError):
        return None
    return data if isinstance(data, dict) else None  # pyright: ignore[reportUnknownVariableType]


def _jwt_role(value: str) -> str | None:
    payload = decode_jwt_payload(value)
    role = payload.get("role") if payload else None
    return role if isinstance(role, str) else None


def _is_public_by_design(value: str) -> bool:
    if value.startswith(PUBLIC_VALUE_PREFIXES):
        return True
    if re.match(r"^https?://\S+$", value, re.IGNORECASE):
        return True
    return _jwt_role(value) == "anon"


def _preview(value: str) -> str:
    return value[: min(4, len(value) // 2)] + "..."


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _parse_env(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            out.append((i, name, value))
    return out


def _page_nodes(g: AppGraph, rel: str) -> list[str]:
    ids = [f"page:{rel}"]
    ids += [n.id for n in g.nodes if n.id.startswith(f"client:{rel}:")]
    present = {n.id for n in g.nodes}
    return [i for i in ids if i in present]


def _env_findings(
    ws: Workspace, scope: dict[str, bool]
) -> tuple[list[Finding], set[tuple[str, int]]]:
    findings: list[Finding] = []
    flagged: set[tuple[str, int]] = set()
    for rel in ws.files:
        if not _is_env_file(rel) or not _in_frontend_scope(ws, rel, scope):
            continue
        text = _read(ws, rel)
        if text is None:
            continue
        for line_no, name, value in _parse_env(text):
            if not name.startswith(FRONT_PREFIXES) or not value:
                continue
            ref = CodeRef(file=rel, start_line=line_no, end_line=line_no)
            evidence = {"var": name, "preview": _preview(value)}
            if "SERVICE_ROLE" in name.upper() or _jwt_role(value) == "service_role":
                findings.append(
                    Finding(
                        id=f"m2-{_slug(rel)}-{_slug(name)}",
                        mistake=2,
                        severity="critical",
                        status="confirmed",
                        title="Your Supabase admin key is in the browser code",
                        node_ids=[],
                        refs=[ref],
                        source="heist",
                        evidence=evidence,
                    )
                )
                flagged.add((rel, line_no))
                continue
            if (
                _is_public_by_design(value)
                or name.upper().endswith("_URL")
                or PUBLIC_NAME_RE.search(name)
            ):
                continue
            if not SECRET_NAME_RE.search(name):
                continue
            findings.append(
                Finding(
                    id=f"m1-{_slug(name)}",
                    mistake=1,
                    severity="critical",
                    status="confirmed",
                    title=_secret_title(name),
                    node_ids=[],
                    refs=[ref],
                    source="heist",
                    evidence=evidence,
                )
            )
            flagged.add((rel, line_no))
    return findings, flagged


def _secret_title(name: str) -> str:
    upper = name.upper()
    brands = {
        "OPENAI": "OpenAI",
        "STRIPE": "Stripe",
        "ANTHROPIC": "Anthropic",
        "RESEND": "Resend",
        "SENDGRID": "SendGrid",
        "TWILIO": "Twilio",
    }
    for key, label in brands.items():
        if key in upper:
            return f"Your {label} key is visible to every visitor"
    return "A secret key is visible to every visitor"


def _service_role_findings(ws: Workspace, g: AppGraph, scope: dict[str, bool]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in ws.files:
        if Path(rel).suffix.lower() not in SOURCE_EXTS or not _in_frontend_scope(ws, rel, scope):
            continue
        text = _read(ws, rel)
        if text is None or "SERVICE_ROLE" not in text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            m = SERVICE_ROLE_RE.search(line)
            if not m or not ENV_ACCESS_RE.search(line):
                continue
            findings.append(
                Finding(
                    id=f"m2-{_slug(rel)}",
                    mistake=2,
                    severity="critical",
                    status="confirmed",
                    title="Your Supabase admin key is in the browser code",
                    node_ids=_page_nodes(g, rel),
                    refs=[CodeRef(file=rel, start_line=line_no, end_line=line_no)],
                    source="heist",
                    evidence={"var": m.group(0)},
                )
            )
            break  # one finding per file
    return findings


def _public_name_on_line(ws: Workspace, rel: str, line_no: int) -> bool:
    text = _read(ws, rel)
    if text is None:
        return False
    lines = text.splitlines()
    if not 1 <= line_no <= len(lines):
        return False
    line = lines[line_no - 1]
    return bool(PUBLIC_NAME_RE.search(line) or URL_NAME_LINE_RE.search(line))


def _gitleaks_findings(
    ws: Workspace, scope: dict[str, bool], flagged: set[tuple[str, int]]
) -> list[Finding]:
    exe = shutil.which("gitleaks")
    if exe is None:
        log.warning("gitleaks not found on PATH, skipping hardcoded secret scan")
        return []
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        try:
            subprocess.run(
                [
                    exe,
                    "dir",
                    "--no-banner",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                    "--exit-code",
                    "0",
                    str(ws.app_root),
                ],
                check=False,
                capture_output=True,
                timeout=GITLEAKS_TIMEOUT,
            )
            raw = json.loads(report.read_text(encoding="utf-8"))
        except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
            log.warning("gitleaks scan failed: %s", exc)
            return []
    if not isinstance(raw, list):
        return []
    root = ws.app_root.resolve()
    files = set(ws.files)
    findings: list[Finding] = []
    for hit in raw:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(hit, dict):
            continue
        try:
            rel = Path(str(hit["File"])).resolve().relative_to(root).as_posix()  # pyright: ignore[reportUnknownArgumentType]
            line_no = int(hit["StartLine"])  # pyright: ignore[reportUnknownArgumentType]
            end = int(hit.get("EndLine", line_no))  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
            rule = str(hit.get("RuleID", "secret"))  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
            secret = str(hit.get("Secret", ""))  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        except (KeyError, ValueError, TypeError):
            continue
        if rel not in files or _is_env_named(rel):
            continue
        if not _in_frontend_scope(ws, rel, scope) or (rel, line_no) in flagged:
            continue
        if _is_public_by_design(secret) or _public_name_on_line(ws, rel, line_no):
            continue
        findings.append(
            Finding(
                id=f"m1-gitleaks-{_slug(rule)}-{_slug(rel)}-{line_no}",
                mistake=1,
                severity="critical",
                status="confirmed",
                title="A secret key is hardcoded in your browser code",
                node_ids=[],
                refs=[CodeRef(file=rel, start_line=line_no, end_line=max(line_no, end))],
                source="gitleaks",
                evidence={"rule": rule, "preview": _preview(secret)},
            )
        )
    return findings


def find_frontend_secrets(ws: Workspace, g: AppGraph) -> list[Finding]:
    scope: dict[str, bool] = {}
    env_f, flagged = _env_findings(ws, scope)
    out = [*env_f, *_service_role_findings(ws, g, scope), *_gitleaks_findings(ws, scope, flagged)]
    return out

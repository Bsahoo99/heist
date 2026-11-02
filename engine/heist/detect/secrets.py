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
from typing import Any, Literal

from heist.detect.browser import browser_files, is_server_path, is_test_file
from heist.fetch import Workspace
from heist.models import AppGraph, CodeRef, Finding

log = logging.getLogger(__name__)

FRONT_PREFIXES = ("VITE_", "NEXT_PUBLIC_")
SECRET_NAME_RE = re.compile(r"KEY|SECRET|TOKEN|PASSWORD|PASSWD", re.IGNORECASE)
ENV_EXCLUDED_SUFFIXES = (".example", ".sample", ".template")
PUBLIC_NAME_RE = re.compile(r"ANON|PUBLISHABLE|SITE_KEY|PUBLIC_KEY", re.IGNORECASE)
# Wider, for detection only: names that say the value is meant for the browser. Redaction keeps
# the narrow list above, so an oddly named real secret is still hidden from the model and page.
PUBLIC_DETECT_NAME_RE = re.compile(r"ANON|PUBLISHABLE|SITE_?KEY|PUBLIC_(?:API_)?KEY", re.IGNORECASE)
# Issuer of the well-known keys `supabase start` prints for local development.
SUPABASE_DEMO_ISS = "supabase-demo"
PUBLIC_VALUE_PREFIXES = ("sb_publishable_", "pk_live_", "pk_test_", "phc_", "AIza")
URL_NAME_LINE_RE = re.compile(r"[A-Za-z0-9_]*_URL\b\s*[:=]", re.IGNORECASE)
SERVICE_ROLE_RE = re.compile(r"\b[A-Za-z0-9_]*SERVICE_ROLE[A-Za-z0-9_]*\b")
ENV_ACCESS_RE = re.compile(r"\benv\b")
PROCESS_ENV_RE = re.compile(r"\bprocess\.env\b")
GITLEAKS_TIMEOUT = 60
# Evidence "location" for a secret in a committed file the front-end bundle never reaches.
PUBLIC_FILE = "public_file"
ADMIN_ROLES = ("service_role", "supabase_admin")
MIN_SIGNATURE_CHARS = 20
DISCARDED_RE = re.compile(r"(?:^|/)\.bolt/supabase_discarded_migrations/")
FUNCTIONS_PREFIX = "supabase/functions/"


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


def _env_in_scope(rel: str) -> bool:
    """Env files a front-end build can read: not Edge Function secrets, backends or tests."""
    return not rel.startswith("supabase/") and not is_server_path(rel) and not is_test_file(rel)


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


def is_public_by_design(value: str) -> bool:
    if value.startswith(PUBLIC_VALUE_PREFIXES):
        return True
    if re.match(r"^https?://\S+$", value, re.IGNORECASE):
        return True
    payload = decode_jwt_payload(value)
    if payload is None:
        return False
    # Anon keys, local demo keys, and signed storage URL tokens (no role, a url and an expiry).
    if payload.get("role") is None:
        return "exp" in payload and isinstance(payload.get("url"), str)
    return payload.get("role") == "anon" or is_demo_key(value)


def is_admin_key(value: str) -> bool:
    """A real-looking Supabase admin JWT (service_role or supabase_admin): not a local demo key,
    and with a full signature (HS256 is 43 characters), not a doc placeholder like `.x`."""
    parts = value.split(".")
    return (
        _jwt_role(value) in ADMIN_ROLES
        and not is_demo_key(value)
        and len(parts) == 3
        and len(parts[2]) >= MIN_SIGNATURE_CHARS
    )


def _committed_admin(
    rel: str,
    line_no: int,
    ref: CodeRef,
    source: Literal["heist", "gitleaks"],
    evidence: dict[str, Any],
) -> Finding:
    return Finding(
        id=f"m2-committed-{_slug(rel)}-{line_no}",
        mistake=2,
        severity="critical",
        status="confirmed",
        title="Your Supabase admin key is committed in a public file",
        node_ids=[],
        refs=[ref],
        source=source,
        evidence={**evidence, "location": PUBLIC_FILE},
    )


def is_demo_key(value: str) -> bool:
    payload = decode_jwt_payload(value)
    return payload is not None and payload.get("iss") == SUPABASE_DEMO_ISS


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


def _env_findings(ws: Workspace) -> tuple[list[Finding], set[tuple[str, int]]]:
    findings: list[Finding] = []
    flagged: set[tuple[str, int]] = set()
    for rel in ws.files:
        if not _is_env_file(rel):
            continue
        text = _read(ws, rel)
        if text is None:
            continue
        in_scope = _env_in_scope(rel)
        for line_no, name, value in _parse_env(text):
            if not value:
                continue
            if not (in_scope and name.startswith(FRONT_PREFIXES)):
                # Not a front-end value, but a committed admin key is a leak under any name.
                if is_admin_key(value):
                    ref = CodeRef(file=rel, start_line=line_no, end_line=line_no)
                    ev = {"var": name, "preview": _preview(value)}
                    findings.append(_committed_admin(rel, line_no, ref, "heist", ev))
                    flagged.add((rel, line_no))
                continue
            ref = CodeRef(file=rel, start_line=line_no, end_line=line_no)
            evidence = {"var": name, "preview": _preview(value)}
            if is_demo_key(value):
                continue
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
                is_public_by_design(value)
                or name.upper().endswith("_URL")
                or PUBLIC_DETECT_NAME_RE.search(name)
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


def _reads_env(line: str, stack: str) -> bool:
    if not ENV_ACCESS_RE.search(line):
        return False
    # Vite never exposes process.env to the browser, so a line whose only env access is
    # process.env is server-only. `import.meta.env` or a local alias (`env.X`) still counts.
    if stack == "vite_supabase":
        return bool(ENV_ACCESS_RE.search(PROCESS_ENV_RE.sub("", line)))
    return True


def _service_role_findings(ws: Workspace, g: AppGraph, browser: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in ws.files:
        if rel not in browser:
            continue
        text = _read(ws, rel)
        if text is None or "SERVICE_ROLE" not in text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            m = SERVICE_ROLE_RE.search(line)
            if not m or not _reads_env(line, g.stack):
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
    return bool(PUBLIC_DETECT_NAME_RE.search(line) or URL_NAME_LINE_RE.search(line))


def _gitleaks_findings(
    ws: Workspace, g: AppGraph, browser: set[str], flagged: set[tuple[str, int]]
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
        if rel not in files or _is_env_named(rel) or (rel, line_no) in flagged:
            continue
        admin = is_admin_key(secret)
        if not admin and (is_public_by_design(secret) or _public_name_on_line(ws, rel, line_no)):
            continue
        ref = CodeRef(file=rel, start_line=line_no, end_line=max(line_no, end))
        evidence: dict[str, Any] = {"rule": rule, "preview": _preview(secret)}
        if rel in browser and admin:
            # The master key itself ships to every visitor: mistake 2, like the env-var form.
            findings.append(
                Finding(
                    id=f"m2-gitleaks-{_slug(rel)}-{line_no}",
                    mistake=2,
                    severity="critical",
                    status="confirmed",
                    title="Your Supabase admin key is in the browser code",
                    node_ids=_page_nodes(g, rel),
                    refs=[ref],
                    source="gitleaks",
                    evidence=evidence,
                )
            )
        elif rel in browser:
            findings.append(
                Finding(
                    id=f"m1-gitleaks-{_slug(rule)}-{_slug(rel)}-{line_no}",
                    mistake=1,
                    severity="critical",
                    status="confirmed",
                    title="A secret key is hardcoded in your browser code",
                    node_ids=[],
                    refs=[ref],
                    source="gitleaks",
                    evidence=evidence,
                )
            )
        elif admin or not _skip_committed(rel):
            # An admin key is a leak wherever it is committed, tests and old migrations included.
            findings.append(_committed_finding(rule, rel, line_no, ref, secret, evidence))
    return findings


def _skip_committed(rel: str) -> bool:
    """Committed files whose hits are not worth reporting: tests and fixtures, Bolt's discarded
    migrations, and Edge Function code (the Edge Function checks cover it)."""
    return (
        is_test_file(rel)
        or DISCARDED_RE.search(rel) is not None
        or rel.startswith(FUNCTIONS_PREFIX)
    )


def _committed_finding(
    rule: str, rel: str, line_no: int, ref: CodeRef, secret: str, evidence: dict[str, Any]
) -> Finding:
    """A hit in a committed file the bundle never reaches. The repo is public, so it is still a
    leak, but only an admin key can be confirmed from the value alone."""
    evidence = {**evidence, "location": PUBLIC_FILE}
    if is_admin_key(secret):
        return _committed_admin(rel, line_no, ref, "gitleaks", evidence)
    return Finding(
        id=f"m1-gitleaks-{_slug(rule)}-{_slug(rel)}-{line_no}",
        mistake=1,
        severity="high",
        status="possible",
        title="A key may be committed in a public file (check it, then rotate it)",
        node_ids=[],
        refs=[ref],
        source="gitleaks",
        evidence=evidence,
    )


def find_frontend_secrets(ws: Workspace, g: AppGraph) -> list[Finding]:
    browser = browser_files(ws, g.stack)
    env_f, flagged = _env_findings(ws)
    out = [
        *env_f,
        *_service_role_findings(ws, g, browser),
        *_gitleaks_findings(ws, g, browser, flagged),
    ]
    return out

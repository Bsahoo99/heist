"""Hide secret values in repo text before it is sent to a model.

Works line by line and keeps the line count, so line numbers in the prompt stay real.
Over-redaction is fine here: a hidden value costs the model a little context, a leak costs the
user their key.
"""

import re
from pathlib import PurePosixPath

from heist.detect.secrets import PUBLIC_NAME_RE, is_public_by_design
from heist.models import Finding

__all__ = ["REDACTED", "redact_for_prompt"]

REDACTED = "<redacted>"
QUOTES = "'\"`"

SECRET_MIN_LEN = 20
TOKENISH_MIN_LEN = 32
# A path or URL segment of this length mixing letters and digits is treated as a key.
SEGMENT_MIN_LEN = 16
# On lines a mistake 1 or 2 finding points at, shorter mixed tokens are hidden too.
FLAGGED_TOKEN_MIN_LEN = 16
# How far a flagged line is widened to the multi-line string or statement it is part of.
WIDEN_MAX_LINES = 50

# Files of `name = value` lines (or `name: value`) where every value is hidden.
ASSIGNMENT_EXTS = {".toml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".properties"}
ASSIGNMENT_NAMES = {".npmrc", ".pypirc", ".netrc"}
CODE_EXTS = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".vue",
    ".svelte",
    ".py",
    ".go",
    ".rb",
    ".rs",
    ".java",
    ".kt",
    ".swift",
    ".php",
    ".cs",
    ".dart",
    ".sql",
}
FILE_EXTS = (
    "ts|tsx|js|jsx|mjs|cjs|mts|cts|json|sql|md|mdx|css|scss|html|svg|png|jpg|jpeg|gif|webp|"
    "ico|toml|yaml|yml|txt|py|vue|svelte|lock|sh|xml|csv|pdf|woff2?|ttf|map|wasm|php|rb|go"
)

_JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
# Runs of characters keys are made of. Scanned without regard to quotes, so a stray
# apostrophe in a comment or JSX text cannot hide a key.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=.]+")
_KEY_PREFIX_RE = re.compile(
    r"^(?:sk|rk|pk_live|sk_live|sk_test|ghp|gho|github_pat|xox[abpr]|AKIA|glpat|sbp|sb_secret)[-_]"
)
_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]{32,}")
_DOTTED_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+")
# One path word: a lowercase or CamelCase word with digits only at the end, or a version.
_WORD = r"(?:[A-Z]?[a-z]+(?:[A-Z][a-z]+)*\d*|v?\d+)"
_PATH_SEG_RE = re.compile(rf"\.{{0,2}}(?:{_WORD}(?:[-_.]{_WORD})*(?:\.(?:{FILE_EXTS}))?)?")
_URL_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://)([^\s'\"`<>]*)")
_USERINFO_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^\s:/@'\"`<>]*:)([^\s@'\"`<>]+)(@)")
# Names whose value is treated as a secret wherever it is assigned.
_SECRET_NAME_RE = re.compile(
    r"key|secret|token|passw(?:or)?d|pwd|credential|auth|private", re.IGNORECASE
)
_NAMED_RE = re.compile(
    r"(?P<q>[\"']?)(?P<name>[A-Za-z_$@][\w$.@-]*)(?P=q)\s*"
    r"(?P<sep>=>|:=|(?<![=!<>:])=(?!=)|(?<!:):(?!:))[ \t]*"
)
_BARE_VALUE_RE = re.compile(r"[^\s,;(){}\[\]'\"`&<>]+")
# Bare values that are code, not data.
_CODE_WORDS = {
    "true",
    "false",
    "null",
    "none",
    "nil",
    "undefined",
    "await",
    "new",
    "typeof",
    "function",
    "async",
    "this",
    "void",
    "yield",
    "return",
    "string",
    "number",
    "boolean",
    "any",
    "unknown",
    "never",
    "object",
    "str",
    "int",
    "bool",
}
_SECTION_RE = re.compile(r"\s*(?:\[\[?[^\]=]*\]\]?|---|\.\.\.)\s*")
_CONTINUES_AFTER = ("+", ",", "(", "[", "{", "=", ":", "|", "&", "?", "\\", "-", "*", "/", "%")
_CONTINUES_BEFORE = ("+", ".", "?", ":", "&&", "||", "-", "*", "/")


def is_assignment_file(rel: str) -> bool:
    """Env files and config files whose values are hidden wholesale."""
    name = rel.rsplit("/", 1)[-1]
    if name.startswith((".env", ".dev.vars")) or name in ASSIGNMENT_NAMES:
        return True
    if name.lower().startswith("secrets."):
        return True
    return PurePosixPath(name).suffix.lower() in ASSIGNMENT_EXTS


def _is_code_file(rel: str) -> bool:
    return PurePosixPath(rel).suffix.lower() in CODE_EXTS


# --- token level ------------------------------------------------------------------------


def _mixed(token: str) -> bool:
    return any(ch.isdigit() for ch in token) and any(ch.isalpha() for ch in token)


def _prefixed_key(token: str) -> bool:
    return len(token) >= SECRET_MIN_LEN and bool(
        _JWT_RE.fullmatch(token) or _KEY_PREFIX_RE.match(token)
    )


def _path_segment(seg: str) -> bool:
    return _PATH_SEG_RE.fullmatch(seg) is not None


def _looks_like_path(token: str) -> bool:
    """Every segment is path-like, as in /v1/chat/completions or src/pages/PetCard.tsx."""
    parts = [p for p in token.split("/") if p]
    return len(parts) > 1 and all(_path_segment(p) for p in parts)


def _long_run(token: str) -> bool:
    return bool(_ALNUM_RUN_RE.search(token)) and not _DOTTED_IDENT_RE.fullmatch(token)


def _secret_part(part: str) -> bool:
    """One URL path segment, query value or slash-free token part that looks like a key."""
    if not part or "${" in part or REDACTED in part:
        return False
    if _prefixed_key(part) or _long_run(part):
        return True
    return len(part) >= SEGMENT_MIN_LEN and _mixed(part) and not _path_segment(part)


def _token_hit(token: str, min_len: int | None) -> bool:
    if _prefixed_key(token) or _long_run(token):
        return True
    if min_len is not None and len(token) >= min_len and _mixed(token):
        return True
    if "/" in token:
        if _looks_like_path(token):
            return False
        segments = [p for p in token.split("/") if p]
        return any(_secret_part(p) for p in segments) or (
            len(token) >= SECRET_MIN_LEN and _mixed(token)
        )
    return len(token) >= TOKENISH_MIN_LEN and _mixed(token)


def _redact_tokens(line: str, min_len: int | None = None) -> str:
    def sub(m: re.Match[str]) -> str:
        return REDACTED if _token_hit(m.group(0), min_len) else m.group(0)

    return _TOKEN_RE.sub(sub, _JWT_RE.sub(REDACTED, line))


# --- URLs -------------------------------------------------------------------------------


def _redact_userinfo(line: str) -> str:
    """scheme://user:password@host keeps the user and hides the password, in any file."""
    return _USERINFO_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", line)


def _redact_query(query: str) -> str:
    pairs: list[str] = []
    for pair in query.split("&"):
        name, eq, value = pair.partition("=")
        if eq and value and (_secret_part(value) or _SECRET_NAME_RE.search(name)):
            value = REDACTED
        elif not eq and _secret_part(name):
            name = REDACTED
        pairs.append(name + eq + value)
    return "&".join(pairs)


def _redact_url(m: re.Match[str]) -> str:
    """Keep scheme and host; hide path segments and query values that look like keys."""
    scheme, rest = m.group(1), m.group(2)
    cut = len(rest)
    for ch in "/?#":
        at = rest.find(ch)
        if at != -1:
            cut = min(cut, at)
    host, tail = rest[:cut], rest[cut:]
    if "@" in host:
        user, _, where = host.rpartition("@")
        if ":" not in user and _secret_part(user):
            host = f"{REDACTED}@{where}"
    path, frag_mark, frag = tail.partition("#")
    path, query_mark, query = path.partition("?")
    path = "/".join(REDACTED if _secret_part(p) else p for p in path.split("/"))
    out = scheme + host + path
    if query_mark:
        out += "?" + _redact_query(query)
    if frag_mark:
        out += "#" + _redact_query(frag)
    return out


def _redact_urls(line: str) -> str:
    return _URL_RE.sub(_redact_url, _redact_userinfo(line))


# --- literals and named values ----------------------------------------------------------


def _close_of(line: str, start: int, quote: str) -> int:
    """Index of the quote closing a literal whose contents start at `start`, or -1."""
    j = start
    while j < len(line):
        if line[j] == "\\":
            j += 2
            continue
        if line[j] == quote:
            return j
        j += 1
    return -1


def _redact_literals(line: str, open_quote: str | None = None) -> tuple[str, str | None]:
    """Replace the contents of every string literal on one line.

    `open_quote` is a literal left open by an earlier line. Returns the line and the quote of
    a literal still open at its end (a multi-line template literal, or an apostrophe in prose).
    """
    out: list[str] = []
    i = 0
    if open_quote is not None:
        j = _close_of(line, 0, open_quote)
        if j == -1:
            return REDACTED, open_quote
        out.append(REDACTED + open_quote)
        i = j + 1
    while i < len(line):
        c = line[i]
        if c not in QUOTES:
            out.append(c)
            i += 1
            continue
        j = _close_of(line, i + 1, c)
        if j == -1:
            out.append(f"{c}{REDACTED}")
            return "".join(out), c
        out.append(f"{c}{REDACTED}{c}" if j > i + 1 else c + c)
        i = j + 1
    return "".join(out), None


def _public_value(name: str, value: str) -> bool:
    """The secrets detector's allowlist: public-by-design names holding their known values."""
    public_name = bool(PUBLIC_NAME_RE.search(name)) or name.upper().endswith("_URL")
    return public_name and is_public_by_design(value)


def _code_value(value: str) -> bool:
    return value.lower() in _CODE_WORDS or any(ch in value for ch in ".([")


def _redact_named(line: str, code: bool) -> tuple[str, str | None]:
    """Hide values assigned to secret-looking names via `=`, `:` or `=>`, in any file.

    Returns the line and the quote of a literal value left open at the end of the line.
    """
    out: list[str] = []
    i = 0
    while True:
        m = _NAMED_RE.search(line, i)
        if m is None:
            break
        end = m.end()
        out.append(line[i:end])
        i = end
        if not _SECRET_NAME_RE.search(m.group("name")) or end >= len(line):
            continue
        c = line[end]
        if c in QUOTES:
            j = _close_of(line, end + 1, c)
            if j == -1:
                out.append(f"{c}{REDACTED}")
                return "".join(out), c
            value = line[end + 1 : j]
            if value and not _public_value(m.group("name"), value):
                value = REDACTED
            out.append(f"{c}{value}{c}")
            i = j + 1
            continue
        bare = _BARE_VALUE_RE.match(line, end)
        if bare is None:
            continue
        value = bare.group(0)
        if _public_value(m.group("name"), value) or (code and _code_value(value)):
            continue
        out.append(REDACTED)
        i = bare.end()
    out.append(line[i:])
    return "".join(out), None


# --- files ------------------------------------------------------------------------------


def _redact_assignment_line(line: str) -> str:
    stripped = line.strip()
    comment = stripped.startswith(("#", ";", "//"))
    seps = [at for at in (line.find("="), line.find(":")) if at != -1]
    if seps:
        at = min(seps)
        value = line[at + 1 :].strip()
        if value and value.lower() not in ("true", "false"):
            line = line[: at + 1] + REDACTED
    elif stripped and not comment and not _SECTION_RE.fullmatch(line):
        line = REDACTED
    return _redact_tokens(_redact_urls(line))


def _redact_assignments(text: str) -> list[str]:
    """Every value after the first `=` or `:` is hidden, on every line, comments included."""
    return [_redact_assignment_line(line) for line in text.splitlines()]


def _flagged_lines(rel: str, findings: list[Finding]) -> set[int]:
    flagged: set[int] = set()
    for f in findings:
        if f.mistake not in (1, 2):
            continue
        for r in f.refs:
            if r.file == rel:
                flagged.update(range(r.start_line, max(r.start_line, r.end_line) + 1))
    return flagged


def _continues(out_line: str, next_line: str | None) -> bool:
    if next_line is None:
        return False
    return out_line.rstrip().endswith(_CONTINUES_AFTER) or next_line.lstrip().startswith(
        _CONTINUES_BEFORE
    )


def _redact_source(rel: str, text: str, findings: list[Finding]) -> list[str]:
    flagged = _flagged_lines(rel, findings)
    code = _is_code_file(rel)
    lines = text.splitlines()
    out: list[str] = []
    open_quote: str | None = None
    budget = 0  # lines left that a flagged line may still widen into
    hide_next = False
    for n, line in enumerate(lines, start=1):
        if n in flagged:
            budget = WIDEN_MAX_LINES
        hidden = n in flagged or hide_next or open_quote is not None
        line = _redact_urls(line)
        if hidden:
            line, open_quote = _redact_literals(line, open_quote)
            line, _ = _redact_named(line, code)
            line = _redact_tokens(line, FLAGGED_TOKEN_MIN_LEN)
        else:
            line, open_quote = _redact_named(line, code)
            line = _redact_tokens(line)
            if open_quote is not None:
                budget = WIDEN_MAX_LINES
        out.append(line)
        nxt = lines[n] if n < len(lines) else None
        wants_more = open_quote is not None or (hidden and _continues(line, nxt))
        hide_next = wants_more and budget > 0
        budget = budget - 1 if hide_next else 0
        if not hide_next:
            open_quote = None
    return out


def redact_for_prompt(rel: str, text: str, findings: list[Finding]) -> str:
    """Remove secret values before any text is sent to a model. Works line by line.

    Env and config files (.env*, .dev.vars, *.toml, *.yaml, secrets.*, ...) keep their names
    but lose every value, comments included; only bare true/false survive. In every other file:
    passwords in URLs, values assigned to secret-looking names, JWTs, prefixed keys, and long or
    letter-digit tokens that are not paths are hidden. On lines that a mistake 1 or 2 finding
    points at, widened to the multi-line string or statement they open, every string literal
    is hidden too.
    """
    if is_assignment_file(rel):
        out = _redact_assignments(text)
    else:
        out = _redact_source(rel, text, findings)
    if text.endswith("\n"):
        out.append("")
    return "\n".join(out)

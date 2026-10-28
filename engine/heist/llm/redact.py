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
# Words that make a whole line count as naming a secret. `key`/`keys` count when they end a
# compound name (apiKey, STRIPE_SECRET_KEY, x-api-key); on their own only in a few shapes.
_LINE_SECRET_WORDS = {
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "passwords",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "authorization",
    "apikey",
    "bearer",
}
_LINE_SECRET_SUBSTR_RE = re.compile(r"secret|passw(?:or)?d|credential|token|apikey", re.IGNORECASE)
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$-]*")
_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_SQL_KEY_RE = re.compile(r"\b(?:primary|foreign|unique)\s+key\b", re.IGNORECASE)
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_NAME_LITERAL_RE = re.compile(r"[A-Za-z][\w.-]*")
# A header value whose credential is a variable or already hidden: `Bearer ${apiKey}`.
_SAFE_AUTH_LITERAL_RE = re.compile(
    r"(?:Authorization:\s*)?(?:Bearer|Basic)\s+"
    r"(?:\$\{[\w$.]+(?:\(['\"][A-Z][A-Z0-9_]*['\"]\))?\}|<redacted>)",
    re.IGNORECASE,
)
_AUTH_SCHEME_RE = re.compile(r"\b(Bearer|Basic)([ \t]+)(?!\$\{)[^\s'\"`<>]+")
_DOCKER_ARG_RE = re.compile(r"^(\s*(?:ENV|ARG)\s+)(.*)$", re.IGNORECASE)
# Code identifiers: letters, digits, _ and $, starting with a letter, _ or $.
_CODE_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
# Identifier words with digits kept on the word before them: OAuth2, S3, Requests2, V2.
_IDENT_WORD_RE = re.compile(r"[A-Z]*[a-z]+\d*|[A-Z]+\d*(?![a-z])|\d+")
# The letters of one identifier word: Word, word, an acronym (S, HTML) or OAuth.
_IDENT_LETTERS_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]{1,5}|[A-Z]{2}[a-z]{2,}")
_VOWEL_RE = re.compile(r"[aeiouy]")
_CONSONANT_RUN_RE = re.compile(r"[b-df-hj-np-tv-xz]{5,}")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
# A template literal made only of interpolations and separators: `${clientId}:${secret}`.
_INTERPOLATIONS_RE = re.compile(r"(?:\$\{[\w$.]+\}[\s:._/@,|#-]*)+")
# Words that name a secret only as the last word of a compound (smtpPass, SMTP_PASS, db_pw)
# or, on their own, when assigned or quoted. `passport`, `bypass`, `compass` are one word.
_SHORT_SECRET_WORDS = ("key", "keys", "pass", "pw")
_LITERAL_TEXT_RE = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\])*)\1""")
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


def _pronounceable(words: list[str]) -> bool:
    """Real words have vowels and no long consonant runs.

    At most one odd word is allowed: an acronym (DB, S, OAuth), a lone digit run, or a short
    word without a vowel (Db, Js). Random keys have several.
    """
    odd = 0
    for w in words:
        if not w or len(w) == 1 or w[:2].isupper():
            odd += 1
            continue
        low = w.lower()
        if not _VOWEL_RE.search(low):
            if len(low) > 2:
                return False
            odd += 1
        elif _CONSONANT_RUN_RE.search(low):
            return False
    return odd <= 1


def _code_identifier(token: str) -> bool:
    """A camelCase or snake_case name made of real words, like useAdoptionRequests2ForUserId.

    Random keys split into short letter runs with digits everywhere, so they fail this.
    """
    if not _CODE_IDENT_RE.fullmatch(token):
        return False
    words = _IDENT_WORD_RE.findall(token)
    if len(words) < 2:
        return False
    letters = [ch for ch in token if ch.isalpha()]
    upper = sum(ch.isupper() for ch in letters)
    if any(ch.islower() for ch in letters) and upper * 5 > len(letters) * 2:
        return False  # random keys are about half upper case, real names mostly lower
    if not all(_IDENT_LETTERS_RE.fullmatch(w.rstrip("0123456789") or "a") for w in words):
        return False
    if not _pronounceable([w.rstrip("0123456789") for w in words]):
        return False
    runs = [len(r) for w in words for r in re.findall(r"[A-Za-z]+", w)]
    if not runs or sum(runs) / len(runs) < 3:
        return False
    with_digits = [w for w in words if any(ch.isdigit() for ch in w)]
    if len(with_digits) * 3 > len(words):
        return False
    mixed_heavy = (
        sum(ch.isdigit() for ch in w) > 2 and any(ch.isalpha() for ch in w) for w in words
    )
    return not any(mixed_heavy)


def _token_hit(
    token: str, min_len: int | None, *, idents_ok: bool = False, uuids_ok: bool = False
) -> bool:
    """Whether a token looks like a key. `min_len` hides shorter mixed tokens (flagged lines).

    `idents_ok` keeps code identifiers made of real words; `uuids_ok` keeps canonical UUIDs.
    """
    if _prefixed_key(token) or _long_run(token):
        return True
    if uuids_ok and _UUID_RE.fullmatch(token):
        return False
    if idents_ok and _code_identifier(token):
        return False
    if min_len is not None and len(token) >= min_len and _mixed(token):
        return True
    if "/" in token:
        if _looks_like_path(token):
            return False
        segments = [p for p in token.split("/") if p]
        return any(_secret_part(p) for p in segments) or (
            len(token) >= SECRET_MIN_LEN and _mixed(token)
        )
    # 20+ characters mixing letters and digits, unless shaped like a word or a dotted name.
    return (
        len(token) >= SECRET_MIN_LEN
        and _mixed(token)
        and not _path_segment(token)
        and not _DOTTED_IDENT_RE.fullmatch(token)
    )


def _redact_tokens(
    line: str, min_len: int | None = None, *, idents_ok: bool = False, uuids_ok: bool = False
) -> str:
    """Hide key-like tokens. `idents_ok` keeps code identifiers, but only outside string
    literals: a key sits in a string far more often than a function name does.
    """
    line = _JWT_RE.sub(REDACTED, line)
    quoted = [m.span() for m in _LITERAL_TEXT_RE.finditer(line)] if idents_ok else []

    def sub(m: re.Match[str]) -> str:
        t = m.group(0)
        in_string = any(a < m.start() < b for a, b in quoted)
        hit = _token_hit(t, min_len, idents_ok=idents_ok and not in_string, uuids_ok=uuids_ok)
        return REDACTED if hit else t

    return _TOKEN_RE.sub(sub, line)


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


def _redact_auth_schemes(line: str) -> str:
    """The credential after `Bearer` or `Basic`, in any file."""
    return _AUTH_SCHEME_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", line)


def _redact_urls(line: str) -> str:
    return _redact_auth_schemes(_URL_RE.sub(_redact_url, _redact_userinfo(line)))


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


def _redact_literals(
    line: str, open_quote: str | None = None, keep_names: bool = False
) -> tuple[str, str | None]:
    """Replace the contents of every string literal on one line.

    `open_quote` is a literal left open by an earlier line. Returns the line and the quote of
    a literal still open at its end (a multi-line template literal, or an apostrophe in prose).
    With `keep_names`, literals that are only a name (see `_name_literal`) stay visible.
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
        content = line[i + 1 : j]
        if not content or (keep_names and _name_literal(content)):
            out.append(f"{c}{content}{c}")
        else:
            out.append(f"{c}{REDACTED}{c}")
        i = j + 1
    return "".join(out), None


def _names_secret(ident: str) -> bool:
    """A compound name that says it holds a secret: apiKey, stripe_secret, Authorization."""
    if PUBLIC_NAME_RE.search(ident):
        return False
    words = [w.lower() for w in _WORD_RE.findall(ident)]
    if not words:
        return False
    if any(w in _LINE_SECRET_WORDS for w in words) or _LINE_SECRET_SUBSTR_RE.search(ident):
        return True
    return len(words) > 1 and words[-1] in _SHORT_SECRET_WORDS


def _name_literal(content: str) -> bool:
    """A literal that is just a name, kept readable on lines that name a secret.

    Env var names (STRIPE_KEY, OPENAI_API_KEY), secret-like names (Authorization, x-api-key,
    stripe_key) and `Bearer ${variable}`. Never anything that looks like a key itself.
    """
    if _SAFE_AUTH_LITERAL_RE.fullmatch(content) or _INTERPOLATIONS_RE.fullmatch(content):
        return True
    if _token_hit(content, FLAGGED_TOKEN_MIN_LEN):
        return False
    if _ENV_NAME_RE.fullmatch(content):
        return True
    return (
        len(content) <= 40
        and _NAME_LITERAL_RE.fullmatch(content) is not None
        and not any(ch.isdigit() for ch in content)
        and _names_secret(content)
    )


def _line_names_secret(line: str) -> bool:
    """The line names a secret anywhere: as an identifier, in a string, or in a comment."""
    line = _SQL_KEY_RE.sub(" ", line)
    for m in _IDENT_RE.finditer(line):
        if m.group(0).lower() in _SHORT_SECRET_WORDS:
            if _bare_key_names_secret(line, m):
                return True
        elif _names_secret(m.group(0)):
            return True
    return False


def _bare_key_names_secret(line: str, m: re.Match[str]) -> bool:
    """A lone `key`, `pass` or `pw`: assigned (`key = `, `pass:`), quoted ("keys"), or a <key>
    tag.

    Not a JSX `key={...}` prop, a `.keys()` call or a `keyof` type.
    """
    before = line[: m.start()].rstrip()[-1:]
    after = line[m.end() :].lstrip()
    if before in ("'", '"', "`", "<") or after[:1] in ("'", '"', "`", ">"):
        return True
    if before == ".":
        return False
    return (after.startswith(":") and not after.startswith("::")) or (
        after.startswith("=") and not after.startswith(("==", "={", "=>"))
    )


def _short_secret_name(name: str) -> bool:
    """`pass`, `smtpPass`, `SMTP_PASS`, `db_pw`: the name ends in the word pass or pw."""
    words = [w.lower() for w in _WORD_RE.findall(name)]
    return bool(words) and words[-1] in ("pass", "pw")


def _code_part(line: str) -> tuple[str, str]:
    """(code, trailing // or # comment). A rough split that ignores quotes."""
    for mark in (" //", " #"):
        at = line.find(mark)
        if at != -1:
            return line[:at], line[at:]
    return line, ""


def _value_follows(line: str) -> bool:
    """A comma-ended line whose secret name is a quoted string or a comment, as in
    `headers.set('x-api-key',` or `['password',`: the value is likely on the next line.
    """
    code, comment = _code_part(line)
    if not code.rstrip().endswith(","):
        return False
    quoted = " ".join(m.group(2) for m in _LITERAL_TEXT_RE.finditer(code))
    return _line_names_secret(quoted) or _line_names_secret(comment)


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
        name = m.group("name")
        secret_name = _SECRET_NAME_RE.search(name) or _short_secret_name(name)
        if not secret_name or end >= len(line):
            continue
        c = line[end]
        if c in QUOTES:
            j = _close_of(line, end + 1, c)
            if j == -1:
                out.append(f"{c}{REDACTED}")
                return "".join(out), c
            value = line[end + 1 : j]
            safe = _public_value(m.group("name"), value) or _SAFE_AUTH_LITERAL_RE.fullmatch(value)
            if value and not safe:
                value = REDACTED
            out.append(f"{c}{value}{c}")
            i = j + 1
            continue
        bare = _BARE_VALUE_RE.match(line, end)
        if bare is None:
            continue
        value = bare.group(0)
        if value in ("Bearer", "Basic"):
            continue  # the credential after it is hidden by _redact_auth_schemes
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


def _continues(out_line: str, next_line: str | None, strict: bool) -> bool:
    """The statement goes on to the next line. A line that only names a secret (not strict)
    does not continue past a trailing comma: its value is complete on that line.
    """
    if next_line is None:
        return False
    after = _CONTINUES_AFTER if strict else tuple(t for t in _CONTINUES_AFTER if t != ",")
    return out_line.rstrip().endswith(after) or next_line.lstrip().startswith(_CONTINUES_BEFORE)


def _is_dockerfile(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def _redact_docker_line(line: str) -> str:
    """`ENV name value`, `ENV a=b c=d` and `ARG name=value` are assignments: hide the values."""
    m = _DOCKER_ARG_RE.match(line)
    if m is None or not m.group(2).strip():
        return line
    head, rest = m.group(1), m.group(2)
    first = rest.split(None, 1)[0]
    if "=" in first:
        return head + re.sub(r"=(\"[^\"]*\"|'[^']*'|\S+)", f"={REDACTED}", rest)
    parts = rest.split(None, 1)
    return head + parts[0] + (f" {REDACTED}" if len(parts) > 1 else "")


def _redact_source(rel: str, text: str, findings: list[Finding]) -> list[str]:
    """Code and prose. Lines a mistake 1 or 2 finding points at are hidden strictly; lines that
    name a secret anywhere are hidden too, but keep literals that are only names (STRIPE_KEY,
    'Authorization') readable. Both widen to the multi-line string or statement they open.
    """
    flagged = _flagged_lines(rel, findings)
    code = _is_code_file(rel)
    docker = _is_dockerfile(rel)
    lines = text.splitlines()
    out: list[str] = []
    open_quote: str | None = None
    budget = 0  # lines left that a flagged line may still widen into
    hide_next = False
    strict = False  # the current widening started at a finding's line
    for n, line in enumerate(lines, start=1):
        if docker:
            line = _redact_docker_line(line)
        names = _line_names_secret(line)
        if n in flagged or names:
            budget = WIDEN_MAX_LINES
            strict = n in flagged or (strict and hide_next)
        elif not hide_next and open_quote is None:
            strict = False
        hidden = n in flagged or names or hide_next or open_quote is not None
        one_more = names and not strict and _value_follows(line)
        line = _redact_urls(line)
        if hidden:
            line, open_quote = _redact_literals(line, open_quote, keep_names=not strict)
            line, _ = _redact_named(line, code)
            line = _redact_tokens(line, FLAGGED_TOKEN_MIN_LEN, idents_ok=not strict)
        else:
            line, open_quote = _redact_named(line, code)
            line = _redact_tokens(line, idents_ok=True, uuids_ok=True)
            if open_quote is not None:
                budget = WIDEN_MAX_LINES
        out.append(line)
        nxt = lines[n] if n < len(lines) else None
        wants_more = (
            open_quote is not None or one_more or (hidden and _continues(line, nxt, strict))
        )
        hide_next = wants_more and budget > 0
        budget = budget - 1 if hide_next else 0
        if not hide_next:
            open_quote = None
    return out


def redact_for_prompt(rel: str, text: str, findings: list[Finding]) -> str:
    """Remove secret values before any text is sent to a model. Works line by line.

    Env and config files (.env*, .dev.vars, *.toml, *.yaml, secrets.*, ...) keep their names
    but lose every value, comments included; only bare true/false survive. In every other file:
    passwords in URLs, credentials after Bearer/Basic, values assigned to secret-looking names,
    JWTs, prefixed keys, and long or letter-digit tokens that are not paths are hidden. On lines
    that a mistake 1 or 2 finding points at, and on lines that name a secret anywhere, widened to
    the multi-line string or statement they open, string literals are hidden too.
    """
    if is_assignment_file(rel):
        out = _redact_assignments(text)
    else:
        out = _redact_source(rel, text, findings)
    if text.endswith("\n"):
        out.append("")
    return "\n".join(out)

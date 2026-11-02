"""Mistake 3: tables anyone (or any signed-in user) can read."""

import re
from typing import Literal

from heist.fetch import Workspace
from heist.models import AppGraph, Finding, Policy, Table

# Personal columns follow the plan's list (email, phone, address, message, note, body, ssn,
# dob, birth, secret, token, password, plus user_id-owned rows), matched as whole snake_case
# words anywhere in the name (`medical_notes`, `user_email`). A word does not count when a flag
# or count word follows it (`email_enabled`, `message_count`) or a system word comes right
# before it (`error_message`, `status_message`).
PERSONAL_WORDS = {
    "email", "emails", "phone", "phones", "address", "addresses", "ssn", "dob", "birth",
    "birthday", "birthdate", "secret", "secrets", "token", "tokens", "password", "passwords",
    "message", "messages", "note", "notes", "body",
}  # fmt: skip
FLAG_SUFFIXES = {
    "enabled", "disabled", "verified", "confirmed", "autoconfirm", "count", "sent", "type",
    "template", "at",
}  # fmt: skip
SYSTEM_PREFIXES = {
    "error", "status", "system", "commit", "log", "debug", "success", "failure", "warning",
    "validation",
}  # fmt: skip
OWNER_COLUMNS = {"user_id", "owner_id", "sender_id"}
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
READ_COMMANDS = {"select", "all"}
# Changing existing rows. An INSERT-only opening is judged on its own: it adds rows, never reads.
WRITE_COMMANDS = {"update", "delete", "all"}
INSERT_COMMANDS = {"insert"}
Reason = Literal["open_to_everyone", "open_to_any_user"]
REASONS: tuple[Reason, ...] = ("open_to_everyone", "open_to_any_user")
ANY_USER_USING_RE = re.compile(
    r"""^\(?
    (?:
        \(?auth\.uid\(\)\)?\s+IS\s+NOT\s+NULL
      | \(?auth\.role\(\)\)?\s*=\s*
        (?:'authenticated'(?:::text)?|CAST\('authenticated'\s+AS\s+text\))
    )
    \)?$""",
    re.IGNORECASE | re.VERBOSE,
)
SELECT_UID_RE = re.compile(r"\(\s*select\s+auth\.uid\(\)\s*\)", re.IGNORECASE)


def _roles(p: Policy) -> set[str]:
    return set(p.roles) - {"service_role"}  # service_role bypasses RLS anyway


def _gate(p: Policy) -> str | None:
    """The expression that decides which rows the policy lets through."""
    if p.command == "insert":
        return p.check
    if p.command == "update":
        return p.using if p.using is not None else p.check
    return p.using


def _opening(p: Policy) -> Reason | None:
    """Who a permissive policy lets through on every row: everyone, any signed-in user, or no
    one in particular (None)."""
    gate = _gate(p)
    if not p.permissive or gate is None:
        return None
    roles = _roles(p)
    if gate == "true":
        if {"public", "anon"} & roles:
            return "open_to_everyone"
        return "open_to_any_user" if roles == {"authenticated"} else None
    gate = SELECT_UID_RE.sub("auth.uid()", gate)
    return "open_to_any_user" if ANY_USER_USING_RE.match(gate.strip()) else None


def _closed_by_restrictive(t: Table, opener: Policy, commands: set[str]) -> bool:
    """A restrictive policy ANDs with permissive ones, so it can close the opening."""
    opening = _roles(opener)
    for r in t.policies:
        if r.permissive or r.command not in commands:
            continue
        gate = _gate(r)
        if gate is None or gate == "true":
            continue
        if "public" in r.roles or opening <= set(r.roles):
            return True
    return False


def _first_open(t: Table, commands: set[str], reason: Reason) -> Policy | None:
    """The first permissive policy that opens one of `commands` to `reason`'s audience. Each
    command is checked on its own: a `for all` opener stays open for DELETE when only UPDATE is
    closed by a restrictive policy."""
    for p in t.policies:
        if p.command not in commands or _opening(p) != reason:
            continue
        covered = commands - {"all"} if p.command == "all" else {p.command}
        if any(not _closed_by_restrictive(t, p, {c, "all"}) for c in covered):
            return p
    return None


def _open(t: Table, commands: set[str]) -> tuple[Reason, Policy] | None:
    """The widest audience (everyone, then any signed-in user) with an open policy."""
    for reason in REASONS:
        p = _first_open(t, commands, reason)
        if p is not None:
            return reason, p
    return None


def is_personal_column(name: str) -> bool:
    if name in OWNER_COLUMNS:
        return True
    words = [w for w in re.split(r"[^a-z0-9]+", _CAMEL_RE.sub("_", name).lower()) if w]
    for i, w in enumerate(words):
        if w not in PERSONAL_WORDS:
            continue
        if i + 1 < len(words) and words[i + 1] in FLAG_SUFFIXES:
            continue
        if i > 0 and words[i - 1] in SYSTEM_PREFIXES:
            continue
        return True
    return False


def _personal_columns(t: Table) -> list[str]:
    return [c.name for c in t.columns if is_personal_column(c.name)]


def _who(reason: str) -> str:
    return "Any signed-in user" if reason == "open_to_any_user" else "Anyone"


def _finding(
    t: Table,
    reason: str,
    policy: Policy | None,
    personal: list[str],
    *,
    reads: bool = True,
    writes: bool = True,
    insert_only: bool = False,
    read: tuple[Reason, Policy] | None = None,
) -> Finding:
    """Open updates, deletes and reads of personal data are critical. A SELECT-only read of a
    table with no personal columns is low ("check this is intended", plan Review Focus 2), and so
    is an INSERT-only opening: anyone can add rows (spam, say) but cannot read or change any.

    `read` is set when the read is open to a different audience than the write: `reason` and
    `policy` then describe the write, and the read is cited second."""
    name = t.name
    who = _who(reason)
    critical = not insert_only and (reason == "rls_off" or writes or bool(personal))
    if read is not None:
        title = f"{_who(read[0])} can read and {_who(reason).lower()} can change every row in {name}"
    elif insert_only:
        title = f"{who} can add rows to {name} (check this is intended)"
    elif reason == "rls_off":
        title = f"Anyone can read every row in {name}"
    elif not reads:
        title = f"{who} can change every row in {name}"
    elif writes and not personal:
        title = f"{who} can read and change every row in {name}"
    elif critical:
        title = (
            f"Any signed-in user can read everyone's {name}"
            if reason == "open_to_any_user"
            else f"Anyone can read every row in {name}"
        )
    elif reason == "open_to_any_user":
        title = f"Any signed-in user can read {name} (check this is meant to be shared)"
    else:
        title = f"Anyone can read {name} (check this is meant to be public)"
    if policy is None:
        refs, nodes = [t.ref], [f"table:{name}"]
    else:
        cited = [policy] if read is None else [policy, read[1]]
        refs = [c.ref for c in cited]
        nodes = [f"table:{name}", *(f"policy:{c.table}:{c.name}" for c in cited)]
    evidence: dict[str, object] = {"table": name, "reason": reason, "personal_columns": personal}
    if read is not None:
        evidence["read_reason"] = read[0]
    if insert_only:
        evidence["access"] = "insert"
    elif reason != "rls_off" and writes:
        # Read-only openings carry no "access" key, as before; readers default it to "read".
        evidence["access"] = "read_write" if reads else "write"
    severity: Literal["critical", "low"] = "critical" if critical else "low"
    return Finding(
        id=f"m3-{name}",
        mistake=3,
        severity=severity,
        status="confirmed" if critical else "possible",
        title=title,
        node_ids=nodes,
        refs=refs,
        source="heist",
        evidence=evidence,
    )


def _table_openings(t: Table, personal: list[str]) -> list[Finding]:
    """At most one finding per table. The open read and the open row change are found on their
    own, each the widest audience first (everyone, then any signed-in user), and judged together.
    An INSERT-only opening counts only when nothing else is open."""
    read = _open(t, READ_COMMANDS)
    write = _open(t, WRITE_COMMANDS)
    if read is not None and write is not None and read[0] != write[0]:
        return [_finding(t, write[0], write[1], personal, read=read)]
    opening = read or write
    if opening is not None:
        reason, opener = opening
        return [
            _finding(t, reason, opener, personal, reads=read is not None, writes=write is not None)
        ]
    insert = _open(t, INSERT_COMMANDS)
    if insert is not None:
        return [_finding(t, insert[0], insert[1], personal, insert_only=True)]
    return []


def find_rls_issues(ws: Workspace, g: AppGraph) -> list[Finding]:
    if not g.has_db_rules or g.db is None:
        return []
    out: list[Finding] = []
    for t in g.db.tables.values():
        if t.schema != "public":
            continue
        personal = _personal_columns(t)
        if not t.rls_enabled:
            out.append(_finding(t, "rls_off", None, personal))
            continue
        out.extend(_table_openings(t, personal))
    return out

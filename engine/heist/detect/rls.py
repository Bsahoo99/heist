"""Mistake 3: tables anyone (or any signed-in user) can read."""

import re
from typing import Literal

from heist.fetch import Workspace
from heist.models import AppGraph, Finding, Policy, Table

# Personal columns follow the plan's list (email, phone, address, message, note, body, ssn,
# dob, birth, secret, token, password, plus user_id-owned rows), matched as whole snake_case
# tokens. A strong word counts anywhere in the name unless a flag word follows it
# (`email_enabled`). A weak word counts only as the first word (`notes`, not `error_message`).
STRONG_PERSONAL = {
    "email", "emails", "phone", "phones", "address", "addresses", "ssn", "dob", "birth",
    "birthday", "birthdate", "secret", "secrets", "token", "tokens", "password", "passwords",
}  # fmt: skip
WEAK_PERSONAL = {"message", "messages", "note", "notes", "body"}
FLAG_WORDS = {
    "enabled",
    "verified",
    "confirmed",
    "autoconfirm",
    "count",
    "sent",
    "type",
    "template",
}
OWNER_COLUMNS = {"user_id", "owner_id", "sender_id"}
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
READ_COMMANDS = {"select", "all"}
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


def _is_read_policy(p: Policy) -> bool:
    return p.permissive and p.command in READ_COMMANDS


def _closed_by_restrictive(t: Table, opener: Policy) -> bool:
    """A restrictive read policy ANDs with permissive ones, so it can close the opening."""
    opening = _roles(opener)
    for r in t.policies:
        if r.permissive or r.command not in READ_COMMANDS:
            continue
        if r.using is None or r.using == "true":
            continue
        if "public" in r.roles or opening <= set(r.roles):
            return True
    return False


def _open_to_everyone(p: Policy) -> bool:
    return p.using == "true" and bool({"public", "anon"} & _roles(p))


def _open_to_any_user(p: Policy) -> bool:
    if p.using is None:
        return False
    if p.using == "true":
        return _roles(p) == {"authenticated"}
    using = SELECT_UID_RE.sub("auth.uid()", p.using)
    return bool(ANY_USER_USING_RE.match(using.strip()))


def is_personal_column(name: str) -> bool:
    if name in OWNER_COLUMNS:
        return True
    words = [w for w in re.split(r"[^a-z0-9]+", _CAMEL_RE.sub("_", name).lower()) if w]
    if words and words[0] in WEAK_PERSONAL:
        return True
    return any(
        w in STRONG_PERSONAL and (i + 1 == len(words) or words[i + 1] not in FLAG_WORDS)
        for i, w in enumerate(words)
    )


def _personal_columns(t: Table) -> list[str]:
    return [c.name for c in t.columns if is_personal_column(c.name)]


def _finding(t: Table, reason: str, policy: Policy | None, personal: list[str]) -> Finding:
    name = t.name
    severity: Literal["critical", "low"]
    if reason == "rls_off":
        severity, title = "critical", f"Anyone can read every row in {name}"
        refs, nodes = [t.ref], [f"table:{name}"]
    else:
        assert policy is not None
        refs = [policy.ref]
        nodes = [f"table:{name}", f"policy:{policy.table}:{policy.name}"]
        if reason == "open_to_any_user":
            # Same rule as open-to-everyone reads: no personal columns is often intended.
            if personal:
                severity = "critical"
                title = f"Any signed-in user can read everyone's {name}"
            else:
                severity = "low"
                title = f"Any signed-in user can read {name} (check this is meant to be shared)"
        elif personal:
            severity = "critical"
            title = f"Anyone can read every row in {name}"
        else:
            severity = "low"
            title = f"Anyone can read {name} (check this is meant to be public)"
    return Finding(
        id=f"m3-{name}",
        mistake=3,
        severity=severity,
        status="possible" if severity == "low" else "confirmed",
        title=title,
        node_ids=nodes,
        refs=refs,
        source="heist",
        evidence={"table": name, "reason": reason, "personal_columns": personal},
    )


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
        reads = [p for p in t.policies if _is_read_policy(p)]
        reads = [p for p in reads if not _closed_by_restrictive(t, p)]
        everyone = next((p for p in reads if _open_to_everyone(p)), None)
        if everyone is not None:
            out.append(_finding(t, "open_to_everyone", everyone, personal))
            continue
        any_user = next((p for p in reads if _open_to_any_user(p)), None)
        if any_user is not None:
            out.append(_finding(t, "open_to_any_user", any_user, personal))
    return out

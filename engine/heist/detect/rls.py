"""Mistake 3: tables anyone (or any signed-in user) can read."""

import re

from heist.fetch import Workspace
from heist.models import AppGraph, Finding, Policy, Table

PERSONAL_NAME_RE = re.compile(
    r"email|phone|address|message|note|body|ssn|dob|birth|secret|token|password", re.IGNORECASE
)
OWNER_COLUMNS = {"user_id", "owner_id", "sender_id"}
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


def _is_read_policy(p: Policy) -> bool:
    return p.permissive and p.command in READ_COMMANDS


def _open_to_everyone(p: Policy) -> bool:
    return p.using == "true" and bool({"public", "anon"} & set(p.roles))


def _open_to_any_user(p: Policy) -> bool:
    if p.using is None:
        return False
    if p.using == "true":
        return set(p.roles) == {"authenticated"}
    using = SELECT_UID_RE.sub("auth.uid()", p.using)
    return bool(ANY_USER_USING_RE.match(using.strip()))


def _personal_columns(t: Table) -> list[str]:
    return [c.name for c in t.columns if PERSONAL_NAME_RE.search(c.name) or c.name in OWNER_COLUMNS]


def _finding(t: Table, reason: str, policy: Policy | None, personal: list[str]) -> Finding:
    name = t.name
    if reason == "rls_off":
        severity, title = "critical", f"Anyone can read every row in {name}"
        refs, nodes = [t.ref], [f"table:{name}"]
    else:
        assert policy is not None
        refs = [policy.ref]
        nodes = [f"table:{name}", f"policy:{policy.table}:{policy.name}"]
        if reason == "open_to_any_user":
            severity = "critical"
            title = f"Any signed-in user can read everyone's {name}"
        elif personal:
            severity = "critical"
            title = f"Anyone can read every row in {name}"
        else:
            severity = "low"
            title = f"Anyone can read {name} (check this is meant to be public)"
    return Finding(
        id=f"m3-{name}",
        mistake=3,
        severity=severity,  # pyright: ignore[reportArgumentType]
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
        everyone = next((p for p in reads if _open_to_everyone(p)), None)
        if everyone is not None:
            out.append(_finding(t, "open_to_everyone", everyone, personal))
            continue
        any_user = next((p for p in reads if _open_to_any_user(p)), None)
        if any_user is not None:
            out.append(_finding(t, "open_to_any_user", any_user, personal))
    return out

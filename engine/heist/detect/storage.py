"""Mistake 4: storage buckets with no access rules, or sensitive buckets open to the web."""

import re

from heist.fetch import Workspace
from heist.models import AppGraph, Bucket, Finding

SENSITIVE_TOKENS = {"id", "doc", "passport", "private", "invoice", "avatar"}


def _is_sensitive(bucket_id: str) -> bool:
    tokens = re.split(r"[-_]+", bucket_id.lower())
    return any(t in SENSITIVE_TOKENS for t in tokens)


def _finding(b: Bucket, severity: str, reason: str, title: str) -> Finding:
    return Finding(
        id=f"m4-{b.id}",
        mistake=4,
        severity=severity,  # pyright: ignore[reportArgumentType]
        status="possible" if severity == "low" else "confirmed",
        title=title,
        node_ids=[f"bucket:{b.id}"],
        refs=[b.ref],
        source="heist",
        evidence={"bucket": b.id, "public": b.public, "reason": reason},
    )


def find_storage_issues(ws: Workspace, g: AppGraph) -> list[Finding]:
    if not g.has_db_rules or g.db is None:
        return []
    out: list[Finding] = []
    for b in g.db.buckets.values():
        literal = f"'{b.id}'"
        has_policy = any(
            literal in (p.using or "") or literal in (p.check or "") for p in g.db.storage_policies
        )
        if has_policy:
            continue
        if b.public and _is_sensitive(b.id):
            out.append(
                _finding(
                    b,
                    "high",
                    "public_sensitive_no_policy",
                    f"Files in {b.id} look private but anyone with the link can open them",
                )
            )
        elif b.public:
            out.append(
                _finding(
                    b,
                    "low",
                    "public_no_policy",
                    f"Anyone can open files in {b.id} (check this is meant to be public)",
                )
            )
        else:
            out.append(
                _finding(
                    b,
                    "high",
                    "private_no_policy",
                    f"{b.id} has no access rules, so it is not set up as you expect",
                )
            )
    return out

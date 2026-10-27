"""Assemble the AppGraph from code-derived and Supabase-derived pieces."""

from heist.fetch import Workspace
from heist.graph.js import scan_js
from heist.graph.supabase import list_edge_functions, replay_migrations
from heist.models import AppGraph, CodeRef, Node, Stack

ENV_EXCLUDED_SUFFIXES = (".example", ".sample", ".template")
SERVER_ENV_PREFIX = "supabase/"


def is_frontend_env_file(rel: str) -> bool:
    """A real .env or .env.* file that front-end builds read (not examples, not function secrets)."""
    name = rel.rsplit("/", 1)[-1]
    if not (name == ".env" or name.startswith(".env.")) or name.endswith(ENV_EXCLUDED_SUFFIXES):
        return False
    return not rel.startswith(SERVER_ENV_PREFIX)


def _line_count(ws: Workspace, rel: str) -> int:
    try:
        text = (ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return len(text.splitlines())


def build_app_graph(ws: Workspace, stack: Stack) -> AppGraph:
    db = replay_migrations(ws)
    code_nodes, edges = scan_js(ws)

    derived: list[Node] = []
    if db is not None:
        for t in db.tables.values():
            derived.append(
                Node(id=f"table:{t.name}", kind="table", name=t.name, zone="vault", ref=t.ref)
            )
            for p in t.policies:
                derived.append(
                    Node(
                        id=f"policy:{p.table}:{p.name}",
                        kind="policy",
                        name=p.name,
                        zone="vault",
                        ref=p.ref,
                    )
                )
        for p in db.storage_policies:
            derived.append(
                Node(
                    id=f"policy:{p.table}:{p.name}",
                    kind="policy",
                    name=p.name,
                    zone="vault",
                    ref=p.ref,
                )
            )
        for b in db.buckets.values():
            derived.append(
                Node(id=f"bucket:{b.id}", kind="bucket", name=b.id, zone="warehouse", ref=b.ref)
            )
    for name, entry in list_edge_functions(ws).items():
        n_lines = _line_count(ws, entry)
        derived.append(
            Node(
                id=f"fn:{name}",
                kind="function",
                name=name,
                zone="side_doors",
                ref=CodeRef(file=entry, start_line=1, end_line=max(1, n_lines)),
            )
        )
    derived.append(Node(id="auth:supabase", kind="auth", name="Supabase Auth", zone="guard_desk"))
    derived.append(Node(id="visitor", kind="visitor", name="Visitor", zone="street"))
    for rel in ws.files:
        if is_frontend_env_file(rel):
            derived.append(
                Node(
                    id=f"env:{rel}",
                    kind="env_file",
                    name=rel,
                    zone="shop_window",
                    ref=CodeRef(file=rel, start_line=1, end_line=max(1, _line_count(ws, rel))),
                )
            )

    merged: dict[str, Node] = {}
    for n in [*derived, *code_nodes]:
        cur = merged.get(n.id)
        if cur is None or (cur.ref is None and n.ref is not None):
            merged[n.id] = n
    kept = []
    for e in edges:
        for end in (e.src, e.dst):
            if end not in merged and end.startswith("fn:"):
                name = end[3:]
                merged[end] = Node(id=end, kind="function", name=name, zone="side_doors", ref=None)
        if e.src in merged and e.dst in merged:
            kept.append(e)
    return AppGraph(
        stack=stack,
        nodes=list(merged.values()),
        edges=kept,
        has_db_rules=db is not None,
        db=db,
    )

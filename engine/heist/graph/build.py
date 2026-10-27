"""Assemble the AppGraph from code-derived and Supabase-derived pieces."""

from heist.fetch import Workspace
from heist.graph.js import scan_js
from heist.graph.supabase import list_edge_functions, replay_migrations
from heist.models import AppGraph, CodeRef, Node, Stack


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
        n_lines = len(
            (ws.app_root / entry).read_text(encoding="utf-8", errors="replace").splitlines()
        )
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

    merged: dict[str, Node] = {}
    for n in [*derived, *code_nodes]:
        cur = merged.get(n.id)
        if cur is None or (cur.ref is None and n.ref is not None):
            merged[n.id] = n
    return AppGraph(
        stack=stack,
        nodes=list(merged.values()),
        edges=edges,
        has_db_rules=db is not None,
        db=db,
    )

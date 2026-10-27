"""Tree-sitter scan of JS/TS sources into page, client, function and route graph pieces."""

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlparse

import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser

from heist.fetch import Workspace
from heist.models import CodeRef, Edge, Node

FUNCTIONS_DIR = "supabase/functions/"
SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx")
_ROUTE_RE = re.compile(r"^(?:src/)?app/(?:(.*)/)?route\.(?:ts|js)$")

_TS = Parser(Language(tsts.language_typescript()))
_TSX = Parser(Language(tsts.language_tsx()))


def _walk(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace")


def _literal(node: Any) -> str | None:
    """Value of a plain string or substitution-free template literal, else None."""
    if node is None:
        return None
    if node.type == "string":
        if any(c.type == "escape_sequence" for c in node.children):
            return None
        return "".join(_text(c) for c in node.children if c.type == "string_fragment")
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return _text(node)[1:-1]
    return None


def _chain_props(node: Any) -> list[str]:
    """Property names along a receiver chain, e.g. a.storage.from(x) -> ['storage', ...]."""
    props: list[str] = []
    while node is not None:
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None:
                props.append(_text(prop))
            node = node.child_by_field_name("object")
        elif node.type in ("call_expression", "await_expression", "parenthesized_expression"):
            node = node.child_by_field_name("function") or (
                node.children[-1] if node.children else None
            )
        else:
            break
    return props


def _route_path(rel: str) -> str | None:
    m = _ROUTE_RE.match(rel)
    if not m:
        return None
    segs = [s for s in (m.group(1) or "").split("/") if s and not re.fullmatch(r"\(.*\)", s)]
    return "/" + "/".join(segs)


def _is_use_server(root: Any) -> bool:
    for child in root.children:
        if child.type == "comment":
            continue
        if child.type != "expression_statement" or not child.children:
            return False
        return _literal(child.children[0]) == "use server"
    return False


def _ref(rel: str, n_lines: int) -> CodeRef:
    return CodeRef(file=rel, start_line=1, end_line=max(1, n_lines))


def _calls(root: Any) -> Iterator[tuple[str, str, Any, Any]]:
    """Yield (kind, value, call node, property node) for each recognised literal call."""
    for n in _walk(root):
        if n.type != "call_expression":
            continue
        fn = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        first = args.named_children[0] if args is not None and args.named_children else None
        value = _literal(first)
        if fn is None or not value:
            continue
        if fn.type == "identifier" and _text(fn) == "fetch":
            if value.lower().startswith("https://"):
                host = urlparse(value).hostname
                if host:
                    yield "fetch", host.lower(), n, fn
            continue
        if fn.type != "member_expression":
            continue
        prop = fn.child_by_field_name("property")
        if prop is None:
            continue
        props = _chain_props(fn.child_by_field_name("object"))
        name = _text(prop)
        if name == "from":
            kind = "bucket" if "storage" in props else "table"
            yield kind, value, n, prop
        elif name == "invoke" and props[:1] == ["functions"]:
            yield "fn", value, n, prop


def _edge_kind(kind: str) -> tuple[str, str]:
    return {
        "table": ("table", "queries"),
        "bucket": ("bucket", "uploads"),
        "fn": ("fn", "invokes"),
        "fetch": ("ext", "calls_external"),
    }[kind]


def scan_js(ws: Workspace) -> tuple[list[Node], list[Edge]]:
    nodes: dict[str, Node] = {}
    edges: dict[tuple[str, str, str], Edge] = {}

    def add(node: Node) -> None:
        nodes.setdefault(node.id, node)

    for rel in ws.files:
        if not rel.endswith(SOURCE_EXTS):
            continue
        try:
            text = (ws.app_root / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        parser = _TSX if rel.endswith((".tsx", ".jsx")) else _TS
        root = parser.parse(text.encode("utf-8")).root_node
        n_lines = len(text.splitlines())

        fn_name: str | None = None
        route_id: str | None = None
        if rel.startswith(FUNCTIONS_DIR):
            fn_name = rel[len(FUNCTIONS_DIR) :].split("/")[0]
            if "/" not in rel[len(FUNCTIONS_DIR) :] or fn_name.startswith("_"):
                continue
            src = f"fn:{fn_name}"
        elif (path := _route_path(rel)) is not None:
            route_id = f"route:{path}"
            src = route_id
            add(Node(id=src, kind="route", name=path, zone="side_doors", ref=_ref(rel, n_lines)))
        elif _is_use_server(root):
            route_id = f"route:action:{rel}"
            src = route_id
            name = rel.rsplit("/", 1)[-1]
            add(Node(id=src, kind="route", name=name, zone="side_doors", ref=_ref(rel, n_lines)))
        else:
            src = f"page:{rel}"

        found = list(_calls(root))
        if not found:
            if route_id is None:
                continue
        elif fn_name is None and route_id is None:
            add(
                Node(
                    id=src,
                    kind="page",
                    name=rel.rsplit("/", 1)[-1],
                    zone="shop_window",
                    ref=_ref(rel, n_lines),
                )
            )

        for kind, value, call, prop in found:
            prefix, ekind = _edge_kind(kind)
            dst = f"{prefix}:{value}"
            zone = {"table": "vault", "bucket": "warehouse", "fn": "side_doors"}.get(
                prefix, "across_road"
            )
            nkind = {"table": "table", "bucket": "bucket", "fn": "function"}.get(
                prefix, "external_api"
            )
            if prefix != "fn":  # fn nodes come from the edge function listing
                add(Node(id=dst, kind=nkind, name=value, zone=zone))  # type: ignore[arg-type]
            edges.setdefault((src, dst, ekind), Edge(src=src, dst=dst, kind=ekind))  # type: ignore[arg-type]
            if fn_name is None and kind != "fetch":
                line = prop.start_point[0] + 1
                method = "invoke" if kind == "fn" else "from"
                add(
                    Node(
                        id=f"client:{rel}:{line}",
                        kind="client_call",
                        name=f"{method}('{value}')",
                        zone="shop_window",
                        ref=CodeRef(file=rel, start_line=line, end_line=line),
                    )
                )
    return list(nodes.values()), list(edges.values())

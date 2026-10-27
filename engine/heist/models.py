from typing import Any, Literal

from pydantic import BaseModel, Field

ZoneId = Literal[
    "street", "shop_window", "guard_desk", "side_doors", "vault", "warehouse", "across_road"
]
Stack = Literal["vite_supabase", "next_supabase"]


class DbSchema(BaseModel):
    """Placeholder. Task 5 replaces this with the real schema fields."""


class CodeRef(BaseModel):
    file: str  # relative to the app root, POSIX separators
    start_line: int
    end_line: int
    symbol: str | None = None


class Node(BaseModel):
    id: str
    kind: Literal[
        "page",
        "client_call",
        "function",
        "route",
        "table",
        "policy",
        "bucket",
        "external_api",
        "auth",
    ]
    name: str
    zone: ZoneId
    ref: CodeRef | None = None


class Edge(BaseModel):
    src: str
    dst: str
    kind: Literal["imports", "queries", "invokes", "uploads", "calls_external"]


class AppGraph(BaseModel):
    stack: Stack
    nodes: list[Node]
    edges: list[Edge]
    has_db_rules: bool
    db: DbSchema | None = None

    def node(self, id: str) -> Node:
        for n in self.nodes:
            if n.id == id:
                return n
        raise KeyError(id)


class Finding(BaseModel):
    id: str
    mistake: int
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["confirmed", "proved", "possible"]
    title: str
    node_ids: list[str]
    refs: list[CodeRef]
    source: Literal["heist", "gitleaks", "semgrep_community"]
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProgressEvent(BaseModel):
    kind: Literal["stage", "node_found", "finding", "done", "error"]
    message: str
    data: dict[str, Any] = Field(default_factory=dict)

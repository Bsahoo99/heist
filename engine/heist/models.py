import warnings
from typing import Any, Literal

from pydantic import BaseModel, Field

ZoneId = Literal[
    "street", "shop_window", "guard_desk", "side_doors", "vault", "warehouse", "across_road"
]
Stack = Literal["vite_supabase", "next_supabase"]


class CodeRef(BaseModel):
    file: str  # relative to the app root, POSIX separators
    start_line: int
    end_line: int
    symbol: str | None = None


class Policy(BaseModel):
    name: str
    table: str
    command: Literal["select", "insert", "update", "delete", "all"]
    roles: list[str]
    using: str | None
    check: str | None
    ref: CodeRef
    permissive: bool = True


class Column(BaseModel):
    name: str
    type: str


with warnings.catch_warnings():
    # The brief names this field `schema`, which shadows a deprecated BaseModel attribute.
    warnings.simplefilter("ignore", UserWarning)

    class Table(BaseModel):
        name: str
        schema: str  # type: ignore[assignment]
        columns: list[Column]
        rls_enabled: bool
        policies: list[Policy]
        ref: CodeRef


class Bucket(BaseModel):
    id: str
    public: bool
    ref: CodeRef


class DbSchema(BaseModel):
    tables: dict[str, Table]
    buckets: dict[str, Bucket]
    storage_policies: list[Policy]
    migration_files: list[str]


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
        "visitor",
        "env_file",
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


class StepOut(BaseModel):
    """One stop on a traced path. file/line are None only for stops with no code (visitor, auth)."""

    node_id: str
    zone: ZoneId
    file: str | None
    line: int | None
    data: str
    story: str
    why: str
    code: str


class FixOut(BaseModel):
    explanation: str
    diff: str
    prompt: str


class TraceOut(BaseModel):
    ghost_path: list[StepOut]
    attack_path: list[StepOut]
    fix: FixOut

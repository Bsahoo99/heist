import tomllib
from typing import Any, cast

from pglast import parse_sql
from pglast.enums import AlterTableType, ObjectType
from pglast.parser import ParseError
from pglast.stream import RawStream

from heist.fetch import Workspace
from heist.models import Bucket, CodeRef, Column, DbSchema, Policy, Table

MIGRATIONS_DIR = "supabase/migrations/"
FUNCTIONS_DIR = "supabase/functions/"
CONFIG_PATH = "supabase/config.toml"


def _deparse(node: Any) -> str:
    return RawStream()(node)


def _encloses_whole(sql: str) -> bool:
    """True when sql starts with "(" whose matching ")" is the last character."""
    if not (sql.startswith("(") and sql.endswith(")")):
        return False
    depth = 0
    in_str = False
    for i, ch in enumerate(sql):
        if ch == "'":
            in_str = not in_str
        elif not in_str:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i == len(sql) - 1
    return False


def _normalize_expr(sql: str) -> str:
    """Match pg_policies style: bare booleans lowercase, everything else in one outer pair."""
    s = sql.strip()
    if s.upper() in ("TRUE", "FALSE"):
        return s.lower()
    if _encloses_whole(s):
        return s
    return f"({s})"


def _expr(node: Any) -> str | None:
    return None if node is None else _normalize_expr(_deparse(node))


def _roles(specs: Any) -> list[str]:
    out = []
    for r in specs or ():
        name = r.rolename if r.rolename else "public"
        out.append(name.lower())
    return out


def _qualified(rel: Any) -> tuple[str, str]:
    return (rel.schemaname or "public"), rel.relname


def _key(schema: str, name: str) -> str:
    return name if schema == "public" else f"{schema}.{name}"


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _skip_noise(text: str, pos: int) -> int:
    """Advance past whitespace and SQL comments so pos points at the statement keyword."""
    n = len(text)
    while pos < n:
        if text[pos].isspace():
            pos += 1
        elif text.startswith("--", pos):
            nl = text.find("\n", pos)
            pos = n if nl == -1 else nl + 1
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            pos = n if end == -1 else end + 2
        else:
            break
    return pos


def _bool_value(node: Any) -> bool:
    val = getattr(node, "val", None)
    if val is None:
        return False
    if hasattr(val, "boolval"):
        return bool(val.boolval)
    if hasattr(val, "sval"):
        return str(val.sval).lower() in ("true", "t", "yes", "on", "1")
    return False


def _str_value(node: Any) -> str | None:
    val = getattr(node, "val", None)
    return getattr(val, "sval", None)


class _Replay:
    def __init__(self) -> None:
        self.tables: dict[str, Table] = {}
        self.buckets: dict[str, Bucket] = {}
        self.storage_policies: list[Policy] = []

    def apply(self, stmt: Any, ref: CodeRef) -> None:
        handler = getattr(self, f"_on_{type(stmt).__name__}", None)
        if handler is not None:
            handler(stmt, ref)

    def _on_CreateStmt(self, s: Any, ref: CodeRef) -> None:
        schema, name = _qualified(s.relation)
        cols = [
            Column(name=e.colname, type=_deparse(e.typeName).lower())
            for e in (s.tableElts or ())
            if type(e).__name__ == "ColumnDef"
        ]
        key = _key(schema, name)
        if s.if_not_exists and key in self.tables:
            return
        self.tables[key] = Table(
            name=name, schema=schema, columns=cols, rls_enabled=False, policies=[], ref=ref
        )

    def _on_AlterTableStmt(self, s: Any, ref: CodeRef) -> None:
        table = self.tables.get(_key(*_qualified(s.relation)))
        if table is None:
            return
        for cmd in s.cmds or ():
            if cmd.subtype in (
                AlterTableType.AT_EnableRowSecurity,
                AlterTableType.AT_ForceRowSecurity,
            ):
                table.rls_enabled = True
            elif cmd.subtype == AlterTableType.AT_DisableRowSecurity:
                table.rls_enabled = False
            elif cmd.subtype == AlterTableType.AT_AddColumn and cmd.def_ is not None:
                col = cmd.def_
                if all(c.name != col.colname for c in table.columns):
                    table.columns.append(
                        Column(name=col.colname, type=_deparse(col.typeName).lower())
                    )

    def _on_CreatePolicyStmt(self, s: Any, ref: CodeRef) -> None:
        schema, name = _qualified(s.table)
        policy = Policy(
            name=s.policy_name,
            table=name,
            command=cast(Any, (s.cmd_name or "all").lower()),
            roles=_roles(s.roles) or ["public"],
            using=_expr(s.qual),
            check=_expr(s.with_check),
            ref=ref,
        )
        if (schema, name) == ("storage", "objects"):
            self.storage_policies.append(policy)
            return
        table = self.tables.get(_key(schema, name))
        if table is not None:
            table.policies.append(policy)

    def _find_policy(self, schema: str, tname: str, name: str) -> tuple[list[Policy], int] | None:
        if (schema, tname) == ("storage", "objects"):
            pols = self.storage_policies
        else:
            table = self.tables.get(_key(schema, tname))
            if table is None:
                return None
            pols = table.policies
        for i, p in enumerate(pols):
            if p.name == name:
                return pols, i
        return None

    def _on_AlterPolicyStmt(self, s: Any, ref: CodeRef) -> None:
        found = self._find_policy(*_qualified(s.table), s.policy_name)
        if found is None:
            return
        pols, i = found
        p = pols[i]
        if s.roles:
            p.roles = _roles(s.roles)
        if s.qual is not None:
            p.using = _expr(s.qual)
        if s.with_check is not None:
            p.check = _expr(s.with_check)

    def _on_DropStmt(self, s: Any, ref: CodeRef) -> None:
        if s.removeType == ObjectType.OBJECT_POLICY:
            for obj in s.objects or ():
                parts = [x.sval for x in obj]
                if len(parts) < 2:
                    continue
                *rel, pname = parts
                schema = rel[-2] if len(rel) > 1 else "public"
                found = self._find_policy(schema, rel[-1], pname)
                if found is not None:
                    found[0].pop(found[1])
        elif s.removeType == ObjectType.OBJECT_TABLE:
            for obj in s.objects or ():
                parts = [x.sval for x in obj]
                schema = parts[-2] if len(parts) > 1 else "public"
                self.tables.pop(_key(schema, parts[-1]), None)

    def _on_InsertStmt(self, s: Any, ref: CodeRef) -> None:
        if _qualified(s.relation) != ("storage", "buckets") or not s.cols:
            return
        sel = s.selectStmt
        rows = getattr(sel, "valuesLists", None) or ()
        names = [c.name for c in s.cols]
        if "id" not in names:
            return
        for row in rows:
            if len(row) < len(names):
                continue
            id_val = _str_value(row[names.index("id")])
            if id_val is None:
                continue
            public = _bool_value(row[names.index("public")]) if "public" in names else False
            self.buckets[id_val] = Bucket(id=id_val, public=public, ref=ref)


def replay_migrations(ws: Workspace) -> DbSchema | None:
    files = sorted(
        f
        for f in ws.files
        if f.startswith(MIGRATIONS_DIR)
        and f.endswith(".sql")
        and "/" not in f[len(MIGRATIONS_DIR) :]
    )
    if not files:
        return None
    state = _Replay()
    recorded: list[str] = []
    for rel in files:
        data = (ws.app_root / rel).read_bytes()
        text = data.decode("utf-8", errors="replace")
        try:
            stmts = parse_sql(text)
        except ParseError:
            recorded.append(f"!{rel}")
            continue
        recorded.append(rel)
        # pglast stmt_location/stmt_len are character offsets into the str
        for raw in stmts:
            loc = raw.stmt_location or 0
            end = loc + raw.stmt_len if raw.stmt_len else len(text)
            start = _skip_noise(text, loc)
            ref = CodeRef(
                file=rel,
                start_line=_line_at(text, start),
                end_line=_line_at(text, max(start, end - 1)),
            )
            try:
                state.apply(raw.stmt, ref)
            except Exception:  # noqa: BLE001, S112 - untrusted SQL must never fail the analysis
                continue
    return DbSchema(
        tables=state.tables,
        buckets=state.buckets,
        storage_policies=state.storage_policies,
        migration_files=recorded,
    )


def read_function_config(ws: Workspace) -> dict[str, dict[str, Any]]:
    if CONFIG_PATH not in ws.files:
        return {}
    try:
        data = tomllib.loads((ws.app_root / CONFIG_PATH).read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError):
        return {}
    funcs = data.get("functions")
    if not isinstance(funcs, dict):
        return {}
    return {name: dict(cfg) for name, cfg in funcs.items() if isinstance(cfg, dict)}


def list_edge_functions(ws: Workspace) -> dict[str, str]:
    present = set(ws.files)
    out: dict[str, str] = {}
    for rel in sorted(present):
        if not rel.startswith(FUNCTIONS_DIR):
            continue
        parts = rel[len(FUNCTIONS_DIR) :].split("/")
        if len(parts) != 2 or parts[0].startswith("_"):
            continue
        if parts[1] not in ("index.ts", "index.js"):
            continue
        name = parts[0]
        # index.ts wins when both entry files exist
        if name not in out or parts[1] == "index.ts":
            out[name] = rel
    return out

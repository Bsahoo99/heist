"""The RLS proof inside a throwaway Postgres: apply the repo's migrations, seed fake rows, read
them back as an anonymous visitor and as another signed-in user.

The repo's SQL is hostile. It only ever runs in a database this module creates and drops, on a
server that lives in a sandbox (or a test container), and it runs as `heist_migrator`, a role
without superuser. Statements that reach outside the database are skipped before that.

This module also runs inside the sandbox (`python -m heist.prove.runner`), where only psycopg and
pglast are installed, so it imports nothing else from the engine at module level.

Logs name statement kinds, stages and exception types only, never SQL text or row values.
"""

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from datetime import time as dtime
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from uuid import UUID

import psycopg
from pglast import enums, parse_sql, split
from pglast.parser import ParseError, scan
from psycopg import sql
from psycopg.conninfo import make_conninfo

if TYPE_CHECKING:
    from heist.scene import ProofRow

log = logging.getLogger(__name__)

STUB_PATH = Path(__file__).with_name("stub.sql")
MIGRATOR = "heist_migrator"
PROBER = "heist_prober"

# The only people and personal values a proof ever writes.
ALICE_ID = "00000000-0000-4000-8000-00000000a11c"
BOB_ID = "00000000-0000-4000-8000-000000000b0b"
ALICE = {"id": ALICE_ID, "name": "Test Alice", "email": "alice@example.test"}
BOB = {"id": BOB_ID, "name": "Test Bob", "email": "bob@example.test"}
FAKE_PHONE = "555-0100"
FAKE_NOTE = "Fake note for testing"
# An owner uuid is shown as whose id it is, so the proof says whose row leaked without
# pretending the column held a name.
SHOWN_AS = {ALICE_ID: f"{ALICE['name']} (user id)", BOB_ID: f"{BOB['name']} (user id)"}

STATEMENT_TIMEOUT_MS = 5000
CONNECT_TIMEOUT_S = 10
PROOF_BUDGET_S = 90.0
SEED_ROWS = 2
MAX_ROWS = 3  # per table, per actor
MAX_COLUMNS = 6
MAX_VALUE_CHARS = 80

ALLOWED_EXTENSIONS = frozenset({"pgcrypto", "uuid-ossp", "citext"})
TRUSTED_LANGUAGES = frozenset({"sql", "plpgsql"})
OWNER_COLUMNS = frozenset(
    {"user_id", "owner_id", "sender_id", "created_by", "author_id", "profile_id"}
)
PERSONAL_RE = re.compile(
    r"email|phone|mobile|name|address|message|note|body|content|comment|description|title"
    r"|ssn|dob|birth|secret|token|password",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"e_?mail", re.IGNORECASE)
PHONE_RE = re.compile(r"phone|mobile|(^|_)tel($|_)", re.IGNORECASE)
NAME_RE = re.compile(r"name", re.IGNORECASE)
OWNER_TYPES = frozenset({"uuid", "text", "varchar", "bpchar", "citext"})

# Statement kinds that reach outside the database or the server, change roles, or fight the
# per-file transaction. They are skipped, never run.
SKIP_NODES: dict[str, str] = {
    "CopyStmt": "copy",
    "AlterSystemStmt": "server",
    "LoadStmt": "server",
    "CreateEventTrigStmt": "server",
    "AlterEventTrigStmt": "server",
    "CreateTableSpaceStmt": "server",
    "DropTableSpaceStmt": "server",
    "AlterTableSpaceOptionsStmt": "server",
    "CreatedbStmt": "server",
    "DropdbStmt": "server",
    "AlterDatabaseStmt": "server",
    "AlterDatabaseSetStmt": "server",
    "AlterDatabaseRefreshCollStmt": "server",
    "CheckPointStmt": "server",
    "VacuumStmt": "server",
    "ClusterStmt": "server",
    "CreateRoleStmt": "role",
    "AlterRoleStmt": "role",
    "AlterRoleSetStmt": "role",
    "DropRoleStmt": "role",
    "GrantRoleStmt": "role",
    "CreatePLangStmt": "language",
    "CreateFdwStmt": "foreign",
    "AlterFdwStmt": "foreign",
    "CreateForeignServerStmt": "foreign",
    "AlterForeignServerStmt": "foreign",
    "CreateUserMappingStmt": "foreign",
    "AlterUserMappingStmt": "foreign",
    "DropUserMappingStmt": "foreign",
    "ImportForeignSchemaStmt": "foreign",
    "CreateForeignTableStmt": "foreign",
    "CreatePublicationStmt": "publication",
    "AlterPublicationStmt": "publication",
    "CreateSubscriptionStmt": "publication",
    "AlterSubscriptionStmt": "publication",
    "DropSubscriptionStmt": "publication",
    "TransactionStmt": "transaction",
    "AlterOwnerStmt": "owner",
    "ReassignOwnedStmt": "owner",
}
SKIP_SETTINGS = frozenset(
    {
        "role",
        "session_authorization",
        "statement_timeout",
        "lock_timeout",
        "idle_in_transaction_session_timeout",
        "transaction_timeout",
        "session_replication_role",
    }
)

AsWho = Literal["anonymous", "another_user"]


class RawRow(TypedDict):
    as_who: AsWho
    table: str
    row: dict[str, Any]


class ProofFailed(Exception):
    """The proof could not run. `stage` is one of connect, stub, apply, seed, query, timeout."""

    def __init__(self, stage: str, detail: str):
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


# ---------------------------------------------------------------------------------------------
# Statements


def split_statements(text: str) -> list[str]:
    """One string per statement. Falls back to the scanner when the parser rejects the file."""
    try:
        return [s for s in split(text, with_parser=True) if s.strip()]
    except ParseError:
        pass
    parts: list[str] = []
    start = 0
    try:
        tokens = scan(text)
    except Exception:  # noqa: BLE001 - an unscannable file applies nothing
        log.info("a migration file could not be scanned, skipping it")
        return []
    for tok in tokens:
        if tok.name == "ASCII_59":  # ;
            parts.append(text[start : tok.start])
            start = tok.end + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _defel(options: Any, name: str) -> str | None:
    for opt in options or ():
        if getattr(opt, "defname", None) == name:
            arg = opt.arg
            return str(getattr(arg, "sval", arg))
    return None


def skip_reason(stmt: str) -> str | None:
    """Why this statement must not run in the proof database, or None when it may."""
    try:
        parsed = parse_sql(stmt)
    except ParseError:
        return "unparsable"
    if len(parsed) != 1:
        return "unparsable" if parsed else "empty"
    node: Any = parsed[0].stmt
    kind = type(node).__name__
    if kind in SKIP_NODES:
        return SKIP_NODES[kind]
    if kind == "CreateExtensionStmt":
        return None if node.extname in ALLOWED_EXTENSIONS else "extension"
    if kind == "CreateFunctionStmt":
        language = _defel(node.options, "language") or "sql"
        return None if language.lower() in TRUSTED_LANGUAGES else "language"
    if kind == "DoStmt":
        language = _defel(node.args, "language") or "plpgsql"
        return None if language.lower() in TRUSTED_LANGUAGES else "language"
    if kind == "VariableSetStmt":
        if node.name is None or node.name.lower() in SKIP_SETTINGS:
            return "setting"
        return None
    if kind == "AlterTableStmt":
        for cmd in node.cmds or ():
            if getattr(cmd, "subtype", None) == enums.AlterTableType.AT_ChangeOwner:
                return "owner"
    return None


# ---------------------------------------------------------------------------------------------
# Connections


def _connect(conninfo: str, stage: str) -> psycopg.Connection[Any]:
    try:
        return psycopg.connect(
            conninfo,
            connect_timeout=CONNECT_TIMEOUT_S,
            options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
            application_name="heist-proof",
        )
    except psycopg.Error as exc:
        raise ProofFailed(stage, type(exc).__name__) from None


def _check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise ProofFailed("timeout", "the proof ran out of time")


def _bound(conn: psycopg.Connection[Any]) -> None:
    """Re-assert the statement timeout: a migration may have switched it off."""
    conn.execute("select set_config('statement_timeout', %s, true)", [str(STATEMENT_TIMEOUT_MS)])


# ---------------------------------------------------------------------------------------------
# Migrations


def _apply_stub(conn: psycopg.Connection[Any], passwords: dict[str, str]) -> None:
    try:
        with conn.transaction():
            conn.execute(
                "select set_config('heist.migrator_password', %s, true),"
                " set_config('heist.prober_password', %s, true)",
                [passwords[MIGRATOR], passwords[PROBER]],
            )
            conn.execute(STUB_PATH.read_bytes())
    except psycopg.Error as exc:
        raise ProofFailed("stub", type(exc).__name__) from None


def _apply_migrations(conn: psycopg.Connection[Any], files: list[str], deadline: float) -> None:
    """Each file in its own transaction, in order. A failing statement rolls back its file."""
    for i, text in enumerate(files):
        kept: list[str] = []
        for stmt in split_statements(text):
            reason = skip_reason(stmt)
            if reason is None:
                kept.append(stmt)
            else:
                log.info("migration %d: skipped a statement (%s)", i, reason)
        try:
            with conn.transaction():
                for stmt in kept:
                    _check_deadline(deadline)
                    _bound(conn)
                    conn.execute(stmt.encode())
        except psycopg.Error as exc:
            log.info("migration %d did not apply and was rolled back (%s)", i, type(exc).__name__)


# ---------------------------------------------------------------------------------------------
# Catalog


@dataclass(frozen=True)
class Column:
    name: str
    typname: str  # base type name (domains resolved)
    category: str  # pg_type.typcategory of the base type
    not_null: bool
    has_default: bool
    generated: bool
    max_len: int | None
    first_label: str | None  # enums only


@dataclass(frozen=True)
class ForeignKey:
    columns: tuple[str, ...]
    ref_oid: int
    ref_columns: tuple[str, ...]


@dataclass(frozen=True)
class TableInfo:
    oid: int
    schema: str
    name: str
    columns: tuple[Column, ...]
    fks: tuple[ForeignKey, ...]

    @property
    def ident(self) -> sql.Identifier:
        return sql.Identifier(self.schema, self.name)

    def column(self, name: str) -> Column:
        return next(c for c in self.columns if c.name == name)


_COLUMNS_SQL = """
select a.attname, b.typname, b.typcategory, a.attnotnull,
       a.atthasdef or a.attidentity <> '' as has_default, a.attgenerated <> '' as generated,
       case when b.typcategory = 'S' and a.atttypmod > 4 then a.atttypmod - 4 end as max_len,
       (select e.enumlabel from pg_enum e where e.enumtypid = b.oid
        order by e.enumsortorder limit 1) as first_label
from pg_attribute a
join pg_type t on t.oid = a.atttypid
join pg_type b on b.oid = case when t.typtype = 'd' then t.typbasetype else t.oid end
where a.attrelid = %s and a.attnum > 0 and not a.attisdropped
order by a.attnum
"""

_FKS_SQL = """
select c.confrelid,
       array(select a.attname from unnest(c.conkey) with ordinality k(n, i)
             join pg_attribute a on a.attrelid = c.conrelid and a.attnum = k.n order by k.i),
       array(select a.attname from unnest(c.confkey) with ordinality k(n, i)
             join pg_attribute a on a.attrelid = c.confrelid and a.attnum = k.n order by k.i)
from pg_constraint c
where c.conrelid = %s and c.contype = 'f'
order by c.conname
"""


def _split_name(table: str) -> tuple[str, str]:
    schema, _, name = table.rpartition(".")
    return (schema or "public"), name


def _find_table(conn: psycopg.Connection[Any], schema: str, name: str) -> int | None:
    row = conn.execute(
        "select c.oid from pg_class c join pg_namespace n on n.oid = c.relnamespace"
        " where n.nspname = %s and c.relname = %s and c.relkind in ('r', 'p')",
        [schema, name],
    ).fetchone()
    return int(row[0]) if row else None


def _table_info(conn: psycopg.Connection[Any], oid: int) -> TableInfo:
    names = conn.execute(
        "select n.nspname, c.relname from pg_class c"
        " join pg_namespace n on n.oid = c.relnamespace where c.oid = %s",
        [oid],
    ).fetchone()
    assert names is not None
    cols = tuple(
        Column(
            name=r[0],
            typname=r[1],
            category=r[2],
            not_null=bool(r[3]),
            has_default=bool(r[4]),
            generated=bool(r[5]),
            max_len=r[6],
            first_label=r[7],
        )
        for r in conn.execute(_COLUMNS_SQL, [oid]).fetchall()
    )
    fks = tuple(
        ForeignKey(columns=tuple(r[1]), ref_oid=int(r[0]), ref_columns=tuple(r[2]))
        for r in conn.execute(_FKS_SQL, [oid]).fetchall()
    )
    return TableInfo(oid=oid, schema=names[0], name=names[1], columns=cols, fks=fks)


# ---------------------------------------------------------------------------------------------
# Seeding


# A seed value: text Postgres coerces to the column type, NULL, or a constant SQL expression.
Value = str | None | sql.Composable
GEN_UUID = sql.SQL("gen_random_uuid()")


def _param(v: Any) -> str | None:
    """A value read back from the database, as text Postgres can coerce to the column type."""
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, datetime | date | dtime):
        return v.isoformat()
    if isinstance(v, dict | list):
        return json.dumps(v)
    return str(v)


def _fit(value: str, c: Column) -> str | None:
    if c.max_len is None or len(value) <= c.max_len:
        return value
    if EMAIL_RE.search(c.name):
        return None  # a cut email is no longer a fake one
    return value[: c.max_len]


def _fake_text(c: Column) -> str | None:
    if EMAIL_RE.search(c.name):
        return _fit(ALICE["email"], c)
    if PHONE_RE.search(c.name):
        return _fit(FAKE_PHONE, c)
    if NAME_RE.search(c.name):
        return _fit(ALICE["name"], c)
    return _fit(FAKE_NOTE, c)


def _fake_value(c: Column, idx: int) -> Value:
    if c.category == "A":
        return "{}"
    if c.category == "E":
        return c.first_label
    if c.typname == "uuid":
        return GEN_UUID
    if c.typname in ("json", "jsonb"):
        return "{}"
    if c.category == "S":
        return _fake_text(c)
    if c.category == "N":
        return str(idx + 1)
    if c.category == "B":
        return "false"
    if c.category == "D":
        return "now"
    if c.category == "T":
        return "1 day"
    if c.typname == "bytea":
        return "\\x"
    if c.category == "I":
        return "192.0.2.1"  # TEST-NET-1, never routed
    return None


class _Seeder:
    """Inserts fake rows owned by Test Alice. Runs as the migrator, which may bypass RLS."""

    def __init__(self, conn: psycopg.Connection[Any], deadline: float):
        self.conn = conn
        self.deadline = deadline
        self.infos: dict[int, TableInfo] = {}
        self.parents: dict[int, dict[str, Any] | None] = {}
        self.visiting: set[int] = set()
        self.ctids: dict[int, list[str]] = {}
        users = _find_table(conn, "auth", "users")
        if users is None:
            raise ProofFailed("seed", "auth.users is missing")
        self.users_oid = users
        self.people: dict[str, dict[str, Any]] = {}

    def info(self, oid: int) -> TableInfo:
        if oid not in self.infos:
            self.infos[oid] = _table_info(self.conn, oid)
        return self.infos[oid]

    def add_people(self) -> None:
        for person in (ALICE, BOB):
            meta = json.dumps({"full_name": person["name"], "name": person["name"]})
            values: dict[str, Value] = {
                "id": person["id"],
                "aud": "authenticated",
                "role": "authenticated",
                "email": person["email"],
                "raw_user_meta_data": meta,
                "raw_app_meta_data": '{"provider": "email"}',
                "email_confirmed_at": "now",
            }
            got = self._insert(self.info(self.users_oid), [values, {"id": person["id"]}])
            if got is None:
                raise ProofFailed("seed", "could not add the fake users")
            self.people[person["id"]] = got[1]
        self.parents[self.users_oid] = self.people[ALICE_ID]

    def seed_target(self, oid: int) -> None:
        for idx in range(SEED_ROWS):
            self._check()
            self.visiting.add(oid)
            try:
                got = self._row(oid, idx)
            finally:
                self.visiting.discard(oid)
            if got is None:
                return
            self.ctids.setdefault(oid, []).append(got[0])
            self.parents.setdefault(oid, got[1])

    def _parent(self, oid: int) -> dict[str, Any] | None:
        if oid in self.parents:
            return self.parents[oid]
        if oid in self.visiting:
            return None  # a foreign key cycle
        self._check()
        self.visiting.add(oid)
        try:
            got = self._row(oid, 0)
        finally:
            self.visiting.discard(oid)
        self.parents[oid] = got[1] if got else None
        if got:
            self.ctids.setdefault(oid, []).append(got[0])
        return self.parents[oid]

    def _row(self, oid: int, idx: int) -> tuple[str, dict[str, Any]] | None:
        t = self.info(oid)
        fixed: dict[str, Value] = {}
        for fk in t.fks:
            parent = self._parent(fk.ref_oid)
            if parent is None:
                if all(not t.column(c).not_null for c in fk.columns):
                    fixed.update({c: None for c in fk.columns})
                    continue
                log.info("skipped a table that needs a parent it could not seed (cycle?)")
                return None
            for c, rc in zip(fk.columns, fk.ref_columns, strict=True):
                fixed[c] = _param(parent.get(rc))
        full: dict[str, Value] = {}
        required: dict[str, Value] = {}
        for c in t.columns:
            if c.generated:
                continue
            if c.name in fixed:
                full[c.name] = required[c.name] = fixed[c.name]
            elif c.name in OWNER_COLUMNS and c.typname in OWNER_TYPES:
                full[c.name] = required[c.name] = ALICE_ID
            elif not c.has_default:
                v = _fake_value(c, idx)
                if v is None:
                    continue
                full[c.name] = v
                if c.not_null:
                    required[c.name] = v
        return self._insert(t, [full, required])

    def _insert(
        self, t: TableInfo, attempts: list[dict[str, Value]]
    ) -> tuple[str, dict[str, Any]] | None:
        """Try each set of values, then again with the table's own triggers off."""
        for triggers_off in (False, True):
            for values in attempts:
                self._check()
                try:
                    with self.conn.transaction():
                        _bound(self.conn)
                        if triggers_off:
                            self.conn.execute(
                                sql.SQL("alter table {} disable trigger user").format(t.ident)
                            )
                        got = self._insert_once(t, values)
                        if triggers_off:
                            self.conn.execute(
                                sql.SQL("alter table {} enable trigger user").format(t.ident)
                            )
                        return got
                except psycopg.Error as exc:
                    log.info("a seed insert failed (%s)", type(exc).__name__)
        return None

    def _insert_once(self, t: TableInfo, values: dict[str, Value]) -> tuple[str, dict[str, Any]]:
        params: list[str | None] = []
        exprs: list[sql.Composable] = []
        for v in values.values():
            if isinstance(v, sql.Composable):
                exprs.append(v)
            else:
                exprs.append(sql.Placeholder())
                params.append(v)
        if values:
            q = sql.SQL("insert into {} ({}) values ({}) returning ctid::text, *").format(
                t.ident,
                sql.SQL(", ").join(sql.Identifier(c) for c in values),
                sql.SQL(", ").join(exprs),
            )
        else:
            q = sql.SQL("insert into {} default values returning ctid::text, *").format(t.ident)
        cur = self.conn.execute(q, params)
        row = cur.fetchone()
        assert row is not None and cur.description is not None
        names = [d.name for d in cur.description]
        return str(row[0]), dict(zip(names[1:], row[1:], strict=True))

    def _check(self) -> None:
        _check_deadline(self.deadline)


# ---------------------------------------------------------------------------------------------
# Reading back


def _owner_columns(t: TableInfo, users_oid: int) -> list[str]:
    owners = [c.name for c in t.columns if c.name in OWNER_COLUMNS and c.typname in OWNER_TYPES]
    for fk in t.fks:
        if fk.ref_oid == users_oid and len(fk.columns) == 1 and fk.columns[0] not in owners:
            owners.append(fk.columns[0])
    return owners


def _show(v: Any) -> Any:
    if v is None or isinstance(v, bool | int | float):
        return v
    if isinstance(v, UUID | str) and str(v) in SHOWN_AS:
        return SHOWN_AS[str(v)]
    if isinstance(v, dict | list):
        text = json.dumps(v)
    elif isinstance(v, Decimal | datetime | date | dtime):
        text = v.isoformat() if not isinstance(v, Decimal) else str(v)
    else:
        text = str(v)
    return text[:MAX_VALUE_CHARS]


def _shape(row: dict[str, Any], owners: list[str]) -> dict[str, Any]:
    """At most MAX_COLUMNS columns: owners first, then personal ones, then the rest, id last."""
    names = list(row)
    personal = [n for n in names if n not in owners and PERSONAL_RE.search(n)]
    rest = [n for n in names if n not in owners and n not in personal and n != "id"]
    order = [*owners, *personal, *rest, *(["id"] if "id" in names else [])]
    return {n: _show(row[n]) for n in order[:MAX_COLUMNS]}


_ACTORS: tuple[tuple[AsWho, str, dict[str, str]], ...] = (
    # What Supabase sets for a request with the anon key: a role, no subject.
    ("anonymous", "anon", {"role": "anon"}),
    (
        "another_user",
        "authenticated",
        {"sub": BOB_ID, "role": "authenticated", "email": BOB["email"]},
    ),
)


def _read_back(
    conn: psycopg.Connection[Any],
    table: str,
    t: TableInfo,
    owners: list[str],
    ctids: list[str],
    deadline: float,
) -> list[RawRow]:
    """Alice's rows as each actor sees them, through the table's own RLS and grants."""
    match: list[sql.Composable] = [sql.SQL("ctid = any(%s::text[]::tid[])")]
    params: list[Any] = [ctids]
    for o in owners:
        match.append(sql.SQL("{}::text = %s").format(sql.Identifier(o)))
        params.append(ALICE_ID)
    q = sql.SQL("select * from {} where {} limit {}").format(
        t.ident, sql.SQL(" or ").join(match), sql.Literal(MAX_ROWS)
    )
    out: list[RawRow] = []
    for as_who, role, claims in _ACTORS:
        _check_deadline(deadline)
        try:
            with conn.transaction(force_rollback=True):
                conn.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
                conn.execute(
                    "select set_config('request.jwt.claims', %s, true),"
                    " set_config('request.jwt.claim.sub', %s, true),"
                    " set_config('request.jwt.claim.role', %s, true)",
                    [
                        json.dumps(claims) if claims else "",
                        claims.get("sub", ""),
                        claims.get("role", ""),
                    ],
                )
                _bound(conn)
                cur = conn.execute(q, params)
                assert cur.description is not None
                names = [d.name for d in cur.description]
                rows = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        except psycopg.Error as exc:
            log.info("reading back as %s was refused (%s)", as_who, type(exc).__name__)
            continue
        out.extend(
            RawRow(as_who=as_who, table=table, row=_shape(r, owners)) for r in rows[:MAX_ROWS]
        )
    return out


# ---------------------------------------------------------------------------------------------
# The proof


def prove_tables(
    dsn: str, migration_sql: list[str], tables: list[str], *, budget_s: float = PROOF_BUDGET_S
) -> dict[str, list[RawRow]]:
    """`run_proof` with plain dicts, for the sandbox, which has no pydantic."""
    deadline = time.monotonic() + budget_s
    dbname = f"heist_proof_{secrets.token_hex(6)}"
    passwords = {MIGRATOR: secrets.token_urlsafe(18), PROBER: secrets.token_urlsafe(18)}
    try:
        admin = psycopg.connect(dsn, autocommit=True, connect_timeout=CONNECT_TIMEOUT_S)
    except psycopg.Error as exc:
        raise ProofFailed("connect", type(exc).__name__) from None
    with admin:
        try:
            admin.execute(sql.SQL("create database {}").format(sql.Identifier(dbname)))
        except psycopg.Error as exc:
            raise ProofFailed("connect", type(exc).__name__) from None
        try:
            return _prove_in(dsn, dbname, passwords, migration_sql, tables, deadline)
        finally:
            try:
                admin.execute(
                    sql.SQL("drop database if exists {} with (force)").format(
                        sql.Identifier(dbname)
                    )
                )
            except psycopg.Error as exc:
                log.warning("could not drop the proof database (%s)", type(exc).__name__)


def _prove_in(
    dsn: str,
    dbname: str,
    passwords: dict[str, str],
    migration_sql: list[str],
    tables: list[str],
    deadline: float,
) -> dict[str, list[RawRow]]:
    with _connect(make_conninfo(dsn, dbname=dbname), "connect") as su:
        _apply_stub(su, passwords)

    def as_role(role: str) -> str:
        return make_conninfo(dsn, dbname=dbname, user=role, password=passwords[role])

    with _connect(as_role(MIGRATOR), "connect") as mig:
        _apply_migrations(mig, migration_sql, deadline)
        oids: dict[str, int] = {}
        for table in tables:
            oid = _find_table(mig, *_split_name(table))
            if oid is None:
                raise ProofFailed("apply", "a target table is missing after the migrations")
            oids[table] = oid
        try:
            with mig.transaction():
                seeder = _Seeder(mig, deadline)
                seeder.add_people()
                for oid in oids.values():
                    seeder.seed_target(oid)
        except psycopg.Error as exc:
            raise ProofFailed("seed", type(exc).__name__) from None
        infos = {table: seeder.info(oid) for table, oid in oids.items()}
        owners = {table: _owner_columns(t, seeder.users_oid) for table, t in infos.items()}
        ctids = {table: seeder.ctids.get(oid, []) for table, oid in oids.items()}

    with _connect(as_role(PROBER), "connect") as pr:
        try:
            return {
                table: _read_back(pr, table, infos[table], owners[table], ctids[table], deadline)
                for table in tables
            }
        except psycopg.Error as exc:
            raise ProofFailed("query", type(exc).__name__) from None


def run_proof(dsn: str, migration_sql: list[str], tables: list[str]) -> dict[str, list["ProofRow"]]:
    """Prove which `tables` leak Test Alice's rows. Runs inside any Postgres at `dsn` (a superuser
    connection to a server that is thrown away afterwards); raises `ProofFailed`.

    A table neither actor can read Alice's rows from maps to `[]`.
    """
    from heist.scene import ProofRow  # here, so the sandbox can import this module bare

    raw = prove_tables(dsn, migration_sql, tables)
    return {t: [ProofRow.model_validate(r) for r in rows] for t, rows in raw.items()}


# ---------------------------------------------------------------------------------------------
# Inside the sandbox


def _pg_bin() -> Path:
    found = shutil.which("initdb")
    if found:
        return Path(found).parent
    candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin/initdb"))
    if not candidates:
        raise FileNotFoundError("initdb")
    return candidates[-1].parent


@contextmanager
def private_postgres() -> Iterator[str]:
    """Start Postgres on a local socket only (no TCP), yield its DSN, and stop it afterwards."""
    base = Path(tempfile.mkdtemp(prefix="heist-pg-"))
    data, sock = base / "data", base / "sock"
    sock.mkdir()
    as_postgres: list[str] = []
    if os.geteuid() == 0:  # Modal runs the sandbox as root; Postgres refuses to
        for p in (base, sock):
            shutil.chown(p, "postgres", "postgres")
        as_postgres = [shutil.which("gosu") or "gosu", "postgres"]
    # Password auth even on the socket, so the role passwords mean something in here too.
    password = secrets.token_urlsafe(24)
    pwfile = base / "pw"
    pwfile.write_text(password, encoding="utf-8")
    pwfile.chmod(0o600)
    if as_postgres:
        shutil.chown(pwfile, "postgres", "postgres")
    bin_dir = _pg_bin()
    initdb = [str(bin_dir / "initdb"), "-D", str(data), "-U", "postgres", f"--pwfile={pwfile}"]
    initdb += ["--auth-local=scram-sha-256", "--auth-host=scram-sha-256"]
    initdb += ["-E", "UTF8", "--locale=C", "--no-sync", "--no-instructions"]
    try:
        subprocess.run([*as_postgres, *initdb], capture_output=True, check=True, timeout=60)
    finally:
        pwfile.unlink(missing_ok=True)
    opts = f"-c listen_addresses='' -k {sock} -c fsync=off -c full_page_writes=off"
    start = [str(bin_dir / "pg_ctl"), "-D", str(data), "-l", str(base / "pg.log")]
    start += ["-w", "-t", "30", "-o", opts, "start"]
    subprocess.run([*as_postgres, *start], capture_output=True, check=True, timeout=60)
    try:
        yield make_conninfo(host=str(sock), user="postgres", password=password, dbname="postgres")
    finally:
        subprocess.run(
            [*as_postgres, str(bin_dir / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"],
            capture_output=True,
            check=False,
            timeout=30,
        )


def main() -> int:
    """Read {"migrations": [...], "tables": [...]} on stdin and print one JSON line:
    {"ok": true, "rows": {table: [row, ...]}} or {"ok": false, "stage": ..., "error": ...}.
    """
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    try:
        payload = json.loads(sys.stdin.read())
        migrations = [str(m) for m in payload["migrations"]]
        tables = [str(t) for t in payload["tables"]]
    except (ValueError, KeyError, TypeError) as exc:
        answer: dict[str, Any] = {"ok": False, "stage": "input", "error": type(exc).__name__}
    else:
        try:
            with private_postgres() as dsn:
                answer = {"ok": True, "rows": prove_tables(dsn, migrations, tables)}
        except ProofFailed as exc:
            answer = {"ok": False, "stage": exc.stage, "error": "ProofFailed"}
        except Exception as exc:  # noqa: BLE001 - the caller only needs the type
            answer = {"ok": False, "stage": "sandbox", "error": type(exc).__name__}
    sys.stdout.write("\n" + json.dumps(answer) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

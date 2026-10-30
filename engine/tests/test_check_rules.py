"""shared/check_rules.sql: the read-only query the web asks a user to paste when Heist has no migrations.

The engine never runs it. This test runs it the way a user would, on a database shaped by the vuln
fixture's migrations, inside a read-only transaction. Needs Docker (testcontainers Postgres 16).
"""

from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from heist.prove.runner import STUB_PATH

CHECK_RULES = Path(__file__).resolve().parents[2] / "shared" / "check_rules.sql"
DB = "heist_check_rules"


def test_the_query_only_reads():
    sql = CHECK_RULES.read_text(encoding="utf-8")
    for word in ("insert", "update", "delete", "drop", "alter", "create", "truncate", "grant", "revoke"):
        assert word not in sql.lower(), word


@pytest.fixture
def migrated_dsn(pg_dsn: str, vuln_app_path: Path) -> Iterator[str]:
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f"drop database if exists {DB} with (force)")
        admin.execute(f"create database {DB}")
    dsn = make_conninfo(pg_dsn, dbname=DB)
    try:
        with psycopg.connect(dsn) as conn:
            conn.execute("select set_config('heist.migrator_password', 'x', true)")
            conn.execute("select set_config('heist.prober_password', 'y', true)")
            conn.execute(STUB_PATH.read_bytes())
            for f in sorted((vuln_app_path / "supabase/migrations").glob("*.sql")):
                conn.execute(f.read_bytes())
        yield dsn
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f"drop database if exists {DB} with (force)")


@pytest.mark.docker
def test_lists_tables_policies_and_buckets_read_only(migrated_dsn: str):
    with psycopg.connect(migrated_dsn, autocommit=True) as conn:
        conn.execute("begin transaction read only")
        cur = conn.execute(CHECK_RULES.read_bytes())
        assert cur.description is not None
        cols = [c.name for c in cur.description]
        rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
        conn.execute("rollback")

    assert cols[:3] == ["kind", "name", "status"]
    kinds = [r["kind"] for r in rows]
    # Tables first, then buckets.
    assert kinds == sorted(kinds, key=lambda k: k != "table")

    tables = {(r["name"], r["status"], r["policy"]) for r in rows if r["kind"] == "table"}
    assert ("messages", "RLS off", None) in tables
    assert ("adoption_requests", "RLS on", "requests_select_authed") in tables
    assert ("pets", "RLS on", "pets_select_all") in tables
    assert ("profiles", "RLS on", "profiles_own") in tables
    # Only the final state: the later migration dropped notes_select_all.
    assert ("notes", "RLS on", "notes_select_own") in tables
    assert not any(p == "notes_select_all" for _, _, p in tables)

    open_read = next(r for r in rows if r["policy"] == "pets_select_all")
    assert open_read["command"] == "SELECT"
    assert open_read["using_rule"] == "true"

    buckets = {(r["name"], r["status"]) for r in rows if r["kind"] == "bucket"}
    assert buckets == {("pet-photos", "public"), ("id-documents", "private")}

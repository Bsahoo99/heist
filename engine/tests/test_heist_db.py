"""Heist's own database (supabase/migrations/): only the service role gets in.

0001 holds the tables, 0002 the private `exports` bucket for the exported replays.

Applied the way Supabase applies it: on top of Heist's stub of what Supabase provides, as the
migration role whose default privileges hand every new table to anon and authenticated.
"""

import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any, LiteralString

import psycopg
import pytest
from psycopg import sql

from heist.prove.runner import STUB_PATH

MIGRATIONS = Path(__file__).resolve().parents[2] / "supabase/migrations"
MIGRATION = MIGRATIONS / "0001_heist.sql"
EXPORTS_MIGRATION = MIGRATIONS / "0002_exports_bucket.sql"
OUTSIDERS = ("anon", "authenticated")

pytestmark = pytest.mark.docker


@pytest.fixture
def heist_db(pg_container: Any) -> Iterator[psycopg.Connection[Any]]:
    """A fresh database with the stub and Heist's migration; yields a superuser connection."""
    admin_dsn = pg_container.get_connection_url()
    name = f"heist_self_{secrets.token_hex(4)}"
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(name)))
    dsn = admin_dsn.rsplit("/", 1)[0] + f"/{name}"
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.transaction():
            conn.execute(
                "select set_config('heist.migrator_password', %s, true),"
                " set_config('heist.prober_password', %s, true)",
                [secrets.token_urlsafe(12), secrets.token_urlsafe(12)],
            )
            conn.execute(STUB_PATH.read_bytes())
            # As on Supabase: the service role skips RLS (the stub leaves it out; no proof uses it).
            conn.execute("alter role service_role bypassrls")
        with conn.transaction():
            conn.execute("set local role heist_migrator")
            conn.execute(MIGRATION.read_bytes())
            conn.execute(EXPORTS_MIGRATION.read_bytes())
        yield conn


def _one(conn: psycopg.Connection[Any], query: LiteralString) -> float:
    row = conn.execute(query).fetchone()
    assert row is not None
    return float(row[0])


ATTEMPTS = [
    "select * from public.analyses",
    "insert into public.analyses (id, repo, sha, status) values ('x', 'r', 's', 'running')",
    "update public.analyses set status = 'done'",
    "delete from public.analyses",
    "select * from public.spend_daily",
    "insert into public.spend_daily (day, usd) values (current_date, 1)",
    "select public.add_spend(current_date, 1)",
]


@pytest.mark.parametrize("role", OUTSIDERS)
@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_outsiders_cannot_touch_heists_tables(heist_db, role: str, attempt: str):
    with pytest.raises(psycopg.errors.InsufficientPrivilege), heist_db.transaction():
        heist_db.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
        heist_db.execute(attempt)


def test_rls_is_on_with_no_policies(heist_db):
    rows = heist_db.execute(
        "select c.relname, c.relrowsecurity,"
        " (select count(*) from pg_policies p where p.tablename = c.relname)"
        " from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r'"
        " order by 1"
    ).fetchall()
    assert rows == [("analyses", True, 0), ("spend_daily", True, 0)]


def test_service_role_adds_spend_atomically(heist_db):
    with heist_db.transaction():
        heist_db.execute("set local role service_role")
        assert _one(heist_db, "select public.add_spend('2026-11-03', 1.25)") == 1.25
        assert _one(heist_db, "select public.add_spend('2026-11-03', 2.5)") == 3.75
        assert _one(heist_db, "select usd from public.spend_daily where day = '2026-11-03'") == 3.75


def test_only_one_finished_row_per_repo_and_commit(heist_db):
    with heist_db.transaction():
        heist_db.execute("set local role service_role")
        for aid, status in (("a", "done"), ("b", "error"), ("c", "running")):
            heist_db.execute(
                "insert into public.analyses (id, repo, sha, status) values (%s, 'r', 's', %s)",
                [aid, status],
            )
    with pytest.raises(psycopg.errors.UniqueViolation), heist_db.transaction():
        heist_db.execute("set local role service_role")
        heist_db.execute(
            "insert into public.analyses (id, repo, sha, status) values ('d', 'r', 's', 'done')"
        )


def test_service_role_reads_and_updates_analyses(heist_db):
    # What the engine's `get`, `fail` upsert and finish cleanup need.
    with heist_db.transaction():
        heist_db.execute("set local role service_role")
        heist_db.execute(
            "insert into public.analyses (id, repo, sha, status) values ('a', 'r', 's', 'running')"
        )
        heist_db.execute(
            "insert into public.analyses (id, repo, sha, status, error) values"
            " ('a', 'r', 's', 'error', 'nope')"
            " on conflict (id) do update set status = excluded.status, error = excluded.error"
        )
        row = heist_db.execute("select status, error from public.analyses where id = 'a'").fetchone()
        assert row == ("error", "nope")
        heist_db.execute("update public.analyses set status = 'done' where id = 'a'")
        heist_db.execute("delete from public.analyses where id = 'a' and status <> 'done'")
        assert heist_db.execute("select count(*) from public.analyses").fetchone() == (1,)


def test_exports_bucket_is_private_and_small(heist_db):
    row = heist_db.execute(
        "select public, file_size_limit, allowed_mime_types from storage.buckets where id = 'exports'"
    ).fetchone()
    assert row == (False, 50 * 1024 * 1024, ["video/mp4", "image/gif", "image/png"])


def test_exports_bucket_migration_runs_twice(heist_db):
    with heist_db.transaction():
        heist_db.execute("set local role heist_migrator")
        heist_db.execute(EXPORTS_MIGRATION.read_bytes())
    assert heist_db.execute("select count(*) from storage.buckets").fetchone() == (1,)


def test_exports_bucket_adds_no_storage_policies(heist_db):
    # No policy at all: only the service role (which skips RLS) reaches the files.
    assert heist_db.execute(
        "select count(*) from pg_policies where schemaname = 'storage'"
    ).fetchone() == (0,)
    assert "create policy" not in EXPORTS_MIGRATION.read_text().lower()

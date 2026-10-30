"""The RLS proof: the repo's migrations in a throwaway Postgres, fake rows, read back as strangers.

Tests marked `docker` need a running Docker daemon (testcontainers Postgres 16) and skip without it.
"""

import json
import logging
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from heist.fetch import load_workspace
from heist.graph.supabase import replay_migrations
from heist.pipeline import run_analysis
from heist.prove import sandbox
from heist.prove.runner import (
    ALICE_ID,
    BOB_ID,
    STUB_PATH,
    ProofFailed,
    run_proof,
    skip_reason,
    split_statements,
)
from heist.prove.sandbox import prove_local, prove_rls
from heist.scene import ProofRow

MARKER = "/tmp/heist-pwned"


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0


@pytest.fixture(scope="session")
def pg_container() -> Iterator[Any]:
    if not _docker_up():
        pytest.skip("Docker is not running")
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16", driver=None) as pg:
        yield pg


@pytest.fixture(scope="session")
def pg_dsn(pg_container: Any) -> str:
    return pg_container.get_connection_url()


@pytest.fixture
def vuln_migrations(vuln_app_path: Path) -> list[str]:
    files = sorted((vuln_app_path / "supabase/migrations").glob("*.sql"))
    return [f.read_text(encoding="utf-8") for f in files]


def _marker_absent(pg_container: Any) -> bool:
    code, _ = pg_container.exec(["test", "-e", MARKER])
    return code != 0


# ---------------------------------------------------------------------------------------------
# Statement filtering (no database needed)


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("copy t from program 'id'", "copy"),
        ("copy (select 1) to program 'touch /tmp/x'", "copy"),
        ("copy t to '/tmp/t.csv'", "copy"),
        ("copy t from '/etc/passwd'", "copy"),
        ("create extension pg_net", "extension"),
        ("create extension if not exists dblink", "extension"),
        ("create extension postgres_fdw", "extension"),
        ("alter system set shared_preload_libraries = 'x'", "server"),
        ("load 'auto_explain'", "server"),
        ("create role evil superuser login", "role"),
        ("alter role anon superuser", "role"),
        ("alter role authenticated bypassrls", "role"),
        ("grant postgres to anon", "role"),
        ("create language plperlu", "extension"),  # parsed as create extension
        ("create function f() returns int language c as '/tmp/x.so', 'f'", "language"),
        ("create function f() returns int language plpython3u as $$ return 1 $$", "language"),
        ("do language plperlu $$ system('id') $$", "language"),
        ("create server s foreign data wrapper postgres_fdw", "foreign"),
        ("create user mapping for public server s", "foreign"),
        ("import foreign schema public from server s into public", "foreign"),
        ("begin", "transaction"),
        ("commit", "transaction"),
        ("set statement_timeout = 0", "setting"),
        ("set role postgres", "setting"),
        ("alter table t owner to postgres", "owner"),
        ("alter function f() owner to postgres", "owner"),
        ("alter publication supabase_realtime add table messages", "publication"),
        ("create subscription s connection 'host=x' publication p", "publication"),
        ("create event trigger e on ddl_command_start execute function f()", "server"),
    ],
)
def test_skips_statements_that_reach_outside(sql: str, reason: str):
    assert skip_reason(sql) == reason


@pytest.mark.parametrize(
    "sql",
    [
        "create table t (id uuid primary key default gen_random_uuid())",
        'create extension if not exists "uuid-ossp" with schema extensions',
        "create extension pgcrypto",
        "create extension citext",
        "alter table t enable row level security",
        "create policy p on t for select using (auth.uid() = user_id)",
        "create function f() returns int language sql as $$ select 1 $$",
        "create function g() returns trigger language plpgsql as $$ begin return new; end $$",
        "do $$ begin perform 1; end $$",
        "grant select on t to anon",
        "insert into storage.buckets (id, name, public) values ('a', 'a', true)",
        "set search_path = public",
    ],
)
def test_keeps_ordinary_migration_statements(sql: str):
    assert skip_reason(sql) is None


def test_unparsable_statement_is_skipped():
    assert skip_reason("create tabel nope (") == "unparsable"


def test_split_keeps_dollar_quoted_bodies_whole():
    sql = (
        "create function f() returns int language plpgsql as $$ begin; return 1; end $$;\nselect 2;"
    )
    parts = split_statements(sql)
    assert len(parts) == 2
    assert parts[0].startswith("create function") and parts[1] == "select 2"


def test_split_survives_a_file_pglast_cannot_parse():
    parts = split_statements("create table a (id int);\ncreate tabel nope (;\nselect 1;")
    assert parts[0] == "create table a (id int)"
    assert "select 1" in parts


# ---------------------------------------------------------------------------------------------
# The proof inside a real Postgres 16


@pytest.mark.docker
def test_proves_open_tables(pg_dsn: str, vuln_migrations: list[str]):
    rows = run_proof(pg_dsn, vuln_migrations, ["messages", "adoption_requests", "profiles"])
    assert any(r.as_who == "anonymous" for r in rows["messages"])
    assert any(
        r.as_who == "another_user" and "Test Alice" in str(r.row) for r in rows["adoption_requests"]
    )
    assert rows["profiles"] == []
    # adoption_requests is open to any signed-in user, not to visitors.
    assert all(r.as_who == "another_user" for r in rows["adoption_requests"])


@pytest.mark.docker
def test_only_fake_data(pg_dsn: str, vuln_migrations: list[str]):
    rows = run_proof(pg_dsn, vuln_migrations, ["adoption_requests"])
    assert rows["adoption_requests"]
    for r in rows["adoption_requests"]:
        assert all(str(v).endswith("@example.test") for k, v in r.row.items() if "email" in k)
        assert r.row.get("phone") == "555-0100"
        assert r.row.get("message") == "Fake note for testing"


@pytest.mark.docker
def test_rows_are_bounded(pg_dsn: str, vuln_migrations: list[str]):
    rows = run_proof(pg_dsn, vuln_migrations, ["messages", "adoption_requests"])
    for table, got in rows.items():
        for who in ("anonymous", "another_user"):
            assert len([r for r in got if r.as_who == who]) <= 3
        for r in got:
            assert r.table == table
            assert len(r.row) <= 6
            assert all(len(str(v)) <= 80 for v in r.row.values())


@pytest.mark.docker
def test_missing_target_table_raises_proof_failed(pg_dsn: str):
    with pytest.raises(ProofFailed) as e:
        run_proof(pg_dsn, ["create table t (id int references nowhere (id));"], ["t"])
    assert e.value.stage == "apply"


@pytest.mark.docker
def test_unavailable_extension_is_skipped_not_failed(pg_dsn: str):
    rows = run_proof(pg_dsn, ["create extension pg_net;", "create table t (id int);"], ["t"])
    assert rows["t"] and all(r.as_who in ("anonymous", "another_user") for r in rows["t"])
    one_file = (
        'create extension if not exists pg_net;\ncreate extension "uuid-ossp";\n'
        "create table t (id uuid default uuid_generate_v4(), note text);"
    )
    rows = run_proof(pg_dsn, [one_file], ["t"])
    assert rows["t"]


@pytest.mark.docker
def test_copy_program_is_skipped(pg_container: Any, pg_dsn: str):
    sql = f"create table t (id int);\ncopy (select 1) to program 'touch {MARKER}';\n"
    rows = run_proof(pg_dsn, [sql], ["t"])
    assert rows["t"]
    assert _marker_absent(pg_container)


@pytest.mark.docker
def test_hostile_dynamic_sql_runs_without_superuser(pg_container: Any, pg_dsn: str):
    # Static filtering cannot see inside EXECUTE; the migrations run as a role without superuser.
    evil = (
        "do $$ begin execute 'copy (select 1) to program ''touch "
        + MARKER
        + "'''; end $$;\ncreate table lost (id int);"
    )
    fine = "create table kept (id int, user_id uuid references auth.users (id), note text);"
    rows = run_proof(pg_dsn, [evil, fine], ["kept"])
    assert rows["kept"]
    assert _marker_absent(pg_container)
    with pytest.raises(ProofFailed) as e:
        run_proof(pg_dsn, [evil], ["lost"])
    assert e.value.stage == "apply"
    assert _marker_absent(pg_container)


@pytest.mark.docker
def test_a_migration_cannot_switch_off_the_statement_timeout(pg_dsn: str):
    sql = (
        "select set_config('statement_timeout', '0', false);\n"
        "create table t (id int);\n"
        "do $$ begin perform pg_sleep(30); end $$;\n"
    )
    with pytest.raises(ProofFailed) as e:
        run_proof(pg_dsn, [sql], ["t"])
    # The sleep hit the 5 s timeout, which rolled back the file, so t is missing.
    assert e.value.stage == "apply"


@pytest.mark.docker
def test_seeding_fills_real_schemas(pg_dsn: str):
    sql = """
    create type public.req_status as enum ('new', 'seen');
    create table public.shelters (
      id bigint generated always as identity primary key,
      name varchar(40) not null,
      opened date not null,
      tags text[] not null,
      settings jsonb not null,
      rating numeric not null,
      active boolean not null
    );
    create table public.applications (
      id uuid primary key default gen_random_uuid(),
      author_id uuid not null references auth.users (id),
      shelter_id bigint not null references public.shelters (id),
      status public.req_status not null,
      contact_email text not null,
      mobile_phone varchar(20),
      full_name text,
      notes text,
      code char(3) not null,
      submitted_at timestamptz not null,
      score int not null
    );
    """
    rows = run_proof(pg_dsn, [sql], ["applications", "shelters"])
    got = rows["applications"]
    assert got and all(r.as_who == "anonymous" for r in got[:1])
    row = got[0].row
    assert row["author_id"] == "Test Alice"
    assert row["contact_email"] == "alice@example.test"
    assert row["mobile_phone"] == "555-0100"
    assert row["full_name"] == "Test Alice"
    assert len(row) <= 6
    assert rows["shelters"]


@pytest.mark.docker
def test_fk_cycle_skips_the_table_without_failing(pg_dsn: str):
    sql = """
    create table public.a (id int primary key, b_id int not null);
    create table public.b (id int primary key, a_id int not null references public.a (id));
    alter table public.a add constraint a_b foreign key (b_id) references public.b (id);
    create table public.c (id int primary key, note text);
    """
    rows = run_proof(pg_dsn, [sql], ["a", "c"])
    assert rows["a"] == []
    assert rows["c"]


@pytest.mark.docker
def test_signup_trigger_and_repo_seed_rows(pg_dsn: str):
    sql = """
    create table public.profiles (
      id uuid primary key references auth.users (id),
      full_name text,
      email text
    );
    create function public.handle_new_user() returns trigger
    language plpgsql security definer set search_path = public as $$
    begin
      insert into public.profiles (id, full_name, email)
      values (new.id, new.raw_user_meta_data ->> 'full_name', new.email);
      return new;
    end $$;
    create trigger on_auth_user_created after insert on auth.users
      for each row execute function public.handle_new_user();
    create table public.pets (id serial primary key, name text);
    insert into public.pets (name) values ('Rex from the repo seed');
    """
    rows = run_proof(pg_dsn, [sql], ["profiles", "pets"])
    profiles = [r.row for r in rows["profiles"] if r.as_who == "anonymous"]
    assert profiles and profiles[0]["full_name"] == "Test Alice"
    assert profiles[0]["email"] == "alice@example.test"
    # Rows the repo itself inserted are never read back.
    assert "Rex" not in json.dumps([r.row for r in rows["pets"]])
    assert rows["pets"]


@pytest.mark.docker
def test_storage_and_wrapped_transactions(pg_dsn: str, vuln_migrations: list[str]):
    extra = """
    begin;
    create table public.docs (id uuid primary key default gen_random_uuid(),
      owner_id uuid default auth.uid(), body text);
    alter table public.docs enable row level security;
    create policy docs_any on public.docs for select to authenticated using (true);
    create policy objects_own on storage.objects for select
      using (bucket_id = 'id-documents' and (storage.foldername(name))[1] = auth.uid()::text);
    alter publication supabase_realtime add table public.docs;
    commit;
    """
    rows = run_proof(pg_dsn, [*vuln_migrations, extra], ["docs"])
    assert rows["docs"] and all(r.as_who == "another_user" for r in rows["docs"])
    assert rows["docs"][0].row["owner_id"] == "Test Alice"


@pytest.mark.docker
def test_stub_reads_both_jwt_claim_settings(pg_dsn: str):
    stub = STUB_PATH.read_text(encoding="utf-8")
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute("drop database if exists heist_stub_check with (force)")
        admin.execute("create database heist_stub_check")
    dsn = make_conninfo(pg_dsn, dbname="heist_stub_check")
    try:
        with psycopg.connect(dsn) as conn:
            conn.execute("select set_config('heist.migrator_password', 'x', true)")
            conn.execute("select set_config('heist.prober_password', 'y', true)")
            conn.execute(stub.encode())
            conn.execute("select set_config('request.jwt.claim.sub', %s, true)", [ALICE_ID])
            assert str(conn.execute("select auth.uid()").fetchone()[0]) == ALICE_ID  # pyright: ignore[reportOptionalSubscript]
            conn.execute("select set_config('request.jwt.claim.sub', '', true)")
            claims = json.dumps({"sub": BOB_ID, "role": "authenticated"})
            conn.execute("select set_config('request.jwt.claims', %s, true)", [claims])
            got = conn.execute("select auth.uid(), auth.role(), auth.jwt() ->> 'sub'").fetchone()
            assert got is not None
            assert (str(got[0]), got[1], got[2]) == (BOB_ID, "authenticated", BOB_ID)
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute("drop database if exists heist_stub_check with (force)")


@pytest.mark.docker
def test_run_proof_leaves_no_database_behind(pg_dsn: str, vuln_migrations: list[str]):
    run_proof(pg_dsn, vuln_migrations, ["messages"])
    with pytest.raises(ProofFailed):
        run_proof(pg_dsn, ["create table t (id int references nowhere (id));"], ["t"])
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        left = admin.execute("select datname from pg_database where datname like 'heist_proof_%'")
        assert left.fetchall() == []


# ---------------------------------------------------------------------------------------------
# The sandboxes


@pytest.mark.docker
def test_prove_local_through_the_pipeline(vuln_app_path: Path):
    s = run_analysis(str(vuln_app_path), lambda e: None, None, prove=prove_local)
    proved = [f for f in s.findings if f.status == "proved"]
    assert proved
    assert {f.id for f in proved} <= {"m3-messages", "m3-adoption_requests"}
    assert any("Test Alice" in str(r.row) for f in proved for r in f.proof_rows)
    for f in proved:
        for r in f.proof_rows:
            for k, v in r.row.items():
                if "email" in k:
                    assert str(v).endswith("@example.test")
    pets = next(f for f in s.findings if f.id == "m3-pets")
    assert pets.status == "possible" and pets.proof_rows == []


def _db_and_ws(vuln_app_path: Path):
    ws = load_workspace(vuln_app_path)
    db = replay_migrations(ws)
    assert db is not None
    return db, ws


def test_prove_rls_returns_empty_and_logs_only_the_type(
    vuln_app_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    def broken(payload: str) -> str:
        raise RuntimeError("create table secret_sql_text (x int) -- Test Alice")

    monkeypatch.setattr(sandbox, "_run_in_modal", broken)
    db, ws = _db_and_ws(vuln_app_path)
    with caplog.at_level(logging.DEBUG):
        assert prove_rls(db, ws, ["messages"]) == {}
    assert "RuntimeError" in caplog.text
    assert "secret_sql_text" not in caplog.text and "Test Alice" not in caplog.text


def test_prove_rls_maps_the_sandbox_answer(vuln_app_path: Path, monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, Any] = {}

    def fake(payload: str) -> str:
        seen.update(json.loads(payload))
        row = {"as_who": "anonymous", "table": "messages", "row": {"body": "Fake note for testing"}}
        stray = {"as_who": "anonymous", "table": "other", "row": {"x": 1}}
        return "noise\n" + json.dumps({"ok": True, "rows": {"messages": [row], "other": [stray]}})

    monkeypatch.setattr(sandbox, "_run_in_modal", fake)
    db, ws = _db_and_ws(vuln_app_path)
    got = prove_rls(db, ws, ["messages"])
    assert got == {
        "messages": [
            ProofRow(as_who="anonymous", table="messages", row={"body": "Fake note for testing"})
        ]
    }
    assert seen["tables"] == ["messages"]
    assert len(seen["migrations"]) == 3 and "create table public.messages" in seen["migrations"][0]


def test_prove_rls_reports_a_failed_stage(
    vuln_app_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(
        sandbox,
        "_run_in_modal",
        lambda payload: json.dumps({"ok": False, "stage": "apply", "error": "ProofFailed"}),
    )
    db, ws = _db_and_ws(vuln_app_path)
    with caplog.at_level(logging.INFO):
        assert prove_rls(db, ws, ["messages"]) == {}
    assert "apply" in caplog.text


def test_modal_image_ships_only_the_runner():
    image = sandbox._modal_image()  # pyright: ignore[reportPrivateUsage]
    assert image is not None
    assert all((sandbox.HEIST_DIR / rel).is_file() for rel in sandbox.SHIPPED_FILES)
    assert not any(rel.endswith(".env") or "llm" in rel for rel in sandbox.SHIPPED_FILES)

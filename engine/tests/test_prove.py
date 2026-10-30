"""The RLS proof: the repo's migrations in a throwaway Postgres, fake rows, read back as strangers.

Tests marked `docker` need a running Docker daemon (testcontainers Postgres 16) and skip without it.
"""

import json
import logging
import shutil
import subprocess
import threading
import time
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


def _fails_to_apply(pg_dsn: str, attempt: str) -> None:
    """`attempt` runs in a migration file that then creates `reached`. If the attempt fails,
    the file rolls back and the proof stops at apply because `reached` is missing."""
    with pytest.raises(ProofFailed) as e:
        run_proof(pg_dsn, [f"{attempt}\ncreate table reached (id int);"], ["reached"])
    assert e.value.stage == "apply"


C_FUNCTION = "create function f() returns int language c as ''x'', ''y''"


@pytest.mark.docker
@pytest.mark.parametrize(
    "attempt",
    [
        "do $$ begin execute 'create extension dblink'; end $$;",
        "do $$ begin execute 'create extension postgres_fdw'; end $$;",
        "do $$ begin execute 'alter role heist_migrator superuser'; end $$;",
        "do $$ begin execute 'grant pg_execute_server_program to heist_migrator'; end $$;",
        "do $$ begin execute 'grant pg_read_server_files to heist_migrator'; end $$;",
        "do $$ begin execute 'set role postgres'; end $$;",
        f"do $$ begin execute '{C_FUNCTION}'; end $$;",
    ],
)
def test_dynamic_escalation_fails_inside_a_migration(pg_dsn: str, attempt: str):
    _fails_to_apply(pg_dsn, attempt)


@pytest.mark.docker
def test_role_escalation_never_sticks(pg_dsn: str):
    # Run statically, these are skipped; run dynamically, they fail. Either way nothing changes.
    sql = (
        "alter role heist_migrator superuser;\n"
        "grant pg_execute_server_program to heist_migrator;\n"
        "create table t (id int);"
    )
    run_proof(pg_dsn, [sql], ["t"])
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        row = admin.execute(
            "select rolsuper, pg_has_role('heist_migrator', 'pg_execute_server_program', 'member')"
            " from pg_roles where rolname = 'heist_migrator'"
        ).fetchone()
    assert row == (False, False)


@pytest.mark.docker
def test_security_definer_functions_belong_to_the_migrator(pg_dsn: str):
    sql = """
    create function public.whoami() returns text language sql security definer as $$
      select current_user || ':' || (select rolsuper::text from pg_roles where rolname = current_user)
    $$;
    create table public.t (id int, who text default public.whoami());
    """
    rows = run_proof(pg_dsn, [sql], ["t"])
    assert rows["t"] and {r.row["who"] for r in rows["t"]} == {"heist_migrator:false"}


@pytest.mark.docker
def test_anon_carries_the_anon_role_claim(pg_dsn: str):
    sql = """
    create table public.t (id int, user_id uuid references auth.users (id), note text);
    alter table public.t enable row level security;
    create policy anon_only on public.t for select using (auth.jwt() ->> 'role' = 'anon');
    create table public.u (id int, user_id uuid references auth.users (id), note text);
    alter table public.u enable row level security;
    create policy role_anon on public.u for select
      using (auth.role() = 'anon' and auth.uid() is null);
    """
    rows = run_proof(pg_dsn, [sql], ["t", "u"])
    for table in ("t", "u"):
        assert rows[table] and {r.as_who for r in rows[table]} == {"anonymous"}


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
    assert row["author_id"] == "Test Alice (user id)"
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
    assert rows["docs"][0].row["owner_id"] == "Test Alice (user id)"


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
    sandbox.warm_local()  # images are built ahead of an analysis, never inside one
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


def _ws_with_big_migration(tmp_copy: Any, vuln_app_path: Path):
    root = tmp_copy(vuln_app_path)
    big = "-- filler\n" * (sandbox.MAX_PAYLOAD_BYTES // 10 + 1)
    (root / "supabase/migrations/0004_big.sql").write_text(big, encoding="utf-8")
    ws = load_workspace(root)
    db = replay_migrations(ws)
    assert db is not None
    return db, ws


def test_too_much_migration_sql_skips_the_proof(
    tmp_copy: Any,
    vuln_app_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    called: list[str] = []

    def run(payload: str) -> str:
        called.append(payload)
        return ""

    monkeypatch.setattr(sandbox, "_run_in_modal", run)
    db, ws = _ws_with_big_migration(tmp_copy, vuln_app_path)
    with caplog.at_level(logging.INFO):
        assert prove_rls(db, ws, ["messages"]) == {}
    assert called == []
    assert "migrations_too_large" in caplog.text


def test_modal_is_skipped_until_warm(
    vuln_app_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(sandbox, "_modal_ready", None)

    def no_modal(*a: Any, **k: Any) -> Any:
        raise AssertionError("an analysis must never build or create on Modal before warmup")

    monkeypatch.setattr(sandbox.modal.Sandbox, "create", no_modal)
    db, ws = _db_and_ws(vuln_app_path)
    with caplog.at_level(logging.INFO):
        assert prove_rls(db, ws, ["messages"]) == {}
    assert "modal_not_warm" in caplog.text


def test_docker_is_skipped_until_the_image_exists(
    vuln_app_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(sandbox, "_local_image_ready", lambda: False)

    def no_docker(*a: Any, **k: Any) -> Any:
        raise AssertionError("an analysis must never build the image")

    monkeypatch.setattr(sandbox.subprocess, "run", no_docker)
    db, ws = _db_and_ws(vuln_app_path)
    with caplog.at_level(logging.INFO):
        assert prove_local(db, ws, ["messages"]) == {}
    assert "docker_image_not_ready" in caplog.text


class _FakeStream:
    def write(self, data: Any) -> None:
        pass

    def write_eof(self) -> None:
        pass

    def drain(self) -> None:
        pass

    def read(self) -> str:
        return ""


class _HangingSandbox:
    """A sandbox that never finishes until someone terminates it."""

    def __init__(self) -> None:
        self.stopped = threading.Event()
        self.stdin = _FakeStream()
        self.stdout = _FakeStream()

    def wait(self, raise_on_termination: bool = True) -> None:
        self.stopped.wait(30)

    def terminate(self) -> None:
        self.stopped.set()


def test_a_hanging_modal_sandbox_is_terminated_at_the_deadline(
    vuln_app_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    box = _HangingSandbox()
    ready: Any = sandbox._ModalReady(app=object(), image=object())  # pyright: ignore[reportPrivateUsage, reportArgumentType]
    monkeypatch.setattr(sandbox, "_modal_ready", ready)
    monkeypatch.setattr(sandbox.modal.Sandbox, "create", lambda *a, **k: box)
    monkeypatch.setattr(sandbox, "PROOF_DEADLINE_S", 0.5)
    db, ws = _db_and_ws(vuln_app_path)
    started = time.monotonic()
    with caplog.at_level(logging.INFO):
        assert prove_rls(db, ws, ["messages"]) == {}
    assert time.monotonic() - started < 5
    assert box.stopped.wait(5)
    assert "stage timeout" in caplog.text


def test_warmup_command_builds_the_chosen_image(monkeypatch: pytest.MonkeyPatch):
    built: list[str] = []
    monkeypatch.setattr(sandbox, "warm_local", lambda: built.append("docker"))
    monkeypatch.setattr(sandbox, "warm_modal", lambda: built.append("modal"))
    assert sandbox.main(["warmup", "--docker"]) == 0
    assert sandbox.main(["warmup", "--modal"]) == 0
    assert built == ["docker", "modal"]
    with pytest.raises(SystemExit):
        sandbox.main(["warmup"])

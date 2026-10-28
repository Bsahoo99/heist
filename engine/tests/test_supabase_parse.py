import shutil

from heist.fetch import load_workspace
from heist.graph.supabase import (
    _normalize_expr,
    list_edge_functions,
    read_function_config,
    replay_migrations,
)


def _db(ws):
    db = replay_migrations(ws)
    assert db is not None
    return db


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_tables_and_rls(vuln_app_path):
    db = _db(load_workspace(vuln_app_path))
    assert set(db.tables) >= {"profiles", "pets", "adoption_requests", "messages", "notes"}
    assert db.tables["messages"].rls_enabled is False
    assert db.tables["pets"].policies[0].using == "true"
    assert db.tables["adoption_requests"].policies[0].using == "(auth.uid() IS NOT NULL)"


def test_later_migration_wins(vuln_app_path):
    db = _db(load_workspace(vuln_app_path))
    usings = [p.using for p in db.tables["notes"].policies]
    assert usings == ["(auth.uid() = user_id)"]


def test_policy_ref_points_at_create_policy_line(vuln_app_path):
    db = _db(load_workspace(vuln_app_path))
    ref = db.tables["pets"].policies[0].ref
    line = (vuln_app_path / ref.file).read_text().splitlines()[ref.start_line - 1]
    assert "create policy" in line.lower()


def test_buckets(vuln_app_path):
    db = _db(load_workspace(vuln_app_path))
    assert db.buckets["pet-photos"].public is True
    assert db.buckets["id-documents"].public is False


def test_no_migrations_returns_none(vuln_app_path, tmp_copy):
    root = tmp_copy(vuln_app_path)
    shutil.rmtree(root / "supabase/migrations")
    assert replay_migrations(load_workspace(root)) is None


def test_function_config_and_list(vuln_app_path):
    ws = load_workspace(vuln_app_path)
    assert read_function_config(ws)["send-email"]["verify_jwt"] is False
    assert set(list_edge_functions(ws)) == {"send-email", "update-request", "ai-describe"}


def test_normalize_expr():
    assert _normalize_expr("TRUE") == "true"
    assert _normalize_expr("FALSE") == "false"
    assert _normalize_expr("auth.uid() = user_id") == "(auth.uid() = user_id)"
    assert _normalize_expr("(auth.uid() = user_id)") == "(auth.uid() = user_id)"
    assert _normalize_expr("(a = 1) OR (b = 2)") == "((a = 1) OR (b = 2))"


def test_policy_defaults_and_columns(vuln_app_path):
    db = _db(load_workspace(vuln_app_path))
    p = db.tables["pets"].policies[0]
    assert p.command == "select" and p.roles == ["public"] and p.check is None
    assert [c.name for c in db.tables["pets"].columns] == ["id", "name", "species", "photo_url"]
    assert db.tables["pets"].columns[0].type == "uuid"
    assert db.migration_files == [
        "supabase/migrations/0001_init.sql",
        "supabase/migrations/0002_storage.sql",
        "supabase/migrations/0003_tighten.sql",
    ]


def test_add_column_and_alter_policy_and_force(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "create table t (id int);\n"
        "alter table t force row level security;\n"
        "create policy p on t to Authenticated, anon using (true);\n",
    )
    _write(
        tmp_path,
        "supabase/migrations/002.sql",
        "alter table t add column owner_email text;\n"
        "alter policy p on t using (owner_email = 'x') with check (false);\n",
    )
    db = _db(load_workspace(tmp_path))
    t = db.tables["t"]
    assert t.rls_enabled is True
    assert [(c.name, c.type) for c in t.columns] == [("id", "integer"), ("owner_email", "text")]
    p = t.policies[0]
    assert p.command == "all" and p.roles == ["authenticated", "anon"]
    assert p.using == "(owner_email = 'x')" and p.check == "false"


def test_other_schema_and_drop_table(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "create table private.secrets (id int);\ncreate table gone (id int);\n"
        "drop table if exists gone;\n",
    )
    db = _db(load_workspace(tmp_path))
    assert set(db.tables) == {"private.secrets"}
    assert db.tables["private.secrets"].schema == "private"


def test_unparseable_migration_recorded(tmp_path):
    _write(tmp_path, "supabase/migrations/001.sql", "create table a (id int);\n")
    _write(tmp_path, "supabase/migrations/002.sql", "this is not sql at all;;;(\n")
    db = _db(load_workspace(tmp_path))
    assert "a" in db.tables
    assert db.migration_files == ["supabase/migrations/001.sql", "!supabase/migrations/002.sql"]
    assert db.unparsed_migrations == ["supabase/migrations/002.sql"]


def test_parsed_migrations_leave_unparsed_empty(vuln_app_path):
    assert _db(load_workspace(vuln_app_path)).unparsed_migrations == []


def test_storage_objects_policies_and_bucket_column_order(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "insert into storage.buckets (public, id) values ('true', 'b1'), (false, 'b2');\n"
        "insert into storage.buckets (id) values ('b3');\n"
        "create policy \"read\" on storage.objects for select using (bucket_id = 'b1');\n",
    )
    db = _db(load_workspace(tmp_path))
    assert {k: b.public for k, b in db.buckets.items()} == {"b1": True, "b2": False, "b3": False}
    assert db.tables == {}
    assert [p.name for p in db.storage_policies] == ["read"]
    assert db.storage_policies[0].using == "(bucket_id = 'b1')"


def test_line_refs_after_non_ascii_prefix(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "-- \U0001f600\U0001f600\U0001f600 é é\n-- ünï\n\n"
        "create table t (id int);\n\n"
        "create policy p on t using (true);\n",
    )
    db = _db(load_workspace(tmp_path))
    assert db.tables["t"].ref.start_line == 4
    ref = db.tables["t"].policies[0].ref
    assert ref.start_line == 6 and ref.end_line == 6


def test_create_table_if_not_exists_is_noop(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "create table t (id int);\nalter table t enable row level security;\n"
        "create policy p on t using (true);\n",
    )
    _write(tmp_path, "supabase/migrations/002.sql", "create table if not exists t (id int);\n")
    t = _db(load_workspace(tmp_path)).tables["t"]
    assert t.rls_enabled is True and len(t.policies) == 1


def test_short_bucket_row_does_not_raise(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "insert into storage.buckets (id, public) values ('a');\n"
        "insert into storage.buckets (id, public) values ('b', true);\n",
    )
    assert set(_db(load_workspace(tmp_path)).buckets) == {"b"}


def test_handler_exception_skips_only_that_statement(tmp_path, monkeypatch):
    from heist.graph import supabase as mod

    def boom(self, s, ref):
        raise RuntimeError("boom")

    monkeypatch.setattr(mod._Replay, "_on_AlterTableStmt", boom)
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "create table t (id int);\nalter table t enable row level security;\n"
        "create table u (id int);\n",
    )
    db = _db(load_workspace(tmp_path))
    assert set(db.tables) == {"t", "u"} and db.tables["t"].rls_enabled is False


def test_restrictive_policy_flag(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "create table t (id int);\n"
        "create policy a on t as restrictive for select using (true);\n"
        "create policy b on t for select using (true);\n",
    )
    pols = {p.name: p for p in _db(load_workspace(tmp_path)).tables["t"].policies}
    assert pols["a"].permissive is False
    assert pols["b"].permissive is True


def test_cast_boolean_in_bucket_insert(tmp_path):
    _write(
        tmp_path,
        "supabase/migrations/001.sql",
        "insert into storage.buckets (id, public) values ('a', 'true'::boolean);\n"
        "insert into storage.buckets (id, public) values ('b', true::bool);\n"
        "insert into storage.buckets (id, public) values ('c', 'false'::boolean);\n",
    )
    db = _db(load_workspace(tmp_path))
    assert {k: b.public for k, b in db.buckets.items()} == {"a": True, "b": True, "c": False}

import shutil

from heist.detect.rls import find_rls_issues
from tests.helpers import findings_for


def _sql(tmp_copy, vuln_app_path, sql):
    root = tmp_copy(vuln_app_path)
    (root / "supabase/migrations/0004_x.sql").write_text(sql)
    return {x.evidence["table"]: x for x in findings_for(root, find_rls_issues)}


def test_rls_findings(vuln_app_path):
    f = {x.evidence["table"]: x for x in findings_for(vuln_app_path, find_rls_issues)}
    assert f["messages"].evidence["reason"] == "rls_off" and f["messages"].severity == "critical"
    assert f["adoption_requests"].evidence["reason"] == "open_to_any_user"
    assert f["adoption_requests"].severity == "critical"
    assert f["pets"].evidence["reason"] == "open_to_everyone" and f["pets"].severity == "low"
    assert "profiles" not in f and "notes" not in f


def test_finding_shape(vuln_app_path):
    f = {x.evidence["table"]: x for x in findings_for(vuln_app_path, find_rls_issues)}
    assert f["pets"].status == "possible" and f["pets"].id == "m3-pets"
    assert f["pets"].node_ids == ["table:pets", "policy:pets:pets_select_all"]
    assert f["pets"].refs[0].start_line == 20
    assert f["messages"].status == "confirmed"
    assert f["messages"].node_ids == ["table:messages"]
    assert f["messages"].refs[0].start_line == 37
    assert f["messages"].evidence["personal_columns"] == ["sender_id", "body"]
    assert f["adoption_requests"].status == "confirmed"
    assert f["adoption_requests"].evidence["personal_columns"] == [
        "user_id",
        "email",
        "phone",
        "message",
    ]
    assert "\u2014" not in f["pets"].title


def test_personal_columns_make_open_table_critical(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    p = root / "supabase/migrations/0004_x.sql"
    p.write_text("alter table pets add column owner_email text;")
    f = {x.evidence["table"]: x for x in findings_for(root, find_rls_issues)}
    assert f["pets"].severity == "critical"
    assert f["pets"].status == "confirmed"
    assert f["pets"].evidence["personal_columns"] == ["owner_email"]


def test_no_rules_yields_no_rls_findings(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    shutil.rmtree(root / "supabase/migrations")
    assert findings_for(root, find_rls_issues) == []


def test_restrictive_true_alone_does_not_open(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table r (id int);\nalter table r enable row level security;\n"
        "create policy x on r as restrictive for select using (true);\n",
    )
    assert "r" not in f


def test_authenticated_role_forms_open_to_any_user(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table a (id int);\nalter table a enable row level security;\n"
        "create policy x on a for select using (auth.role() = 'authenticated');\n"
        "create table b (id int);\nalter table b enable row level security;\n"
        "create policy x on b for select using (auth.role() = 'authenticated'::text);\n"
        "create table c (id int);\nalter table c enable row level security;\n"
        "create policy x on c for select to authenticated using (true);\n",
    )
    for t in "abc":
        assert f[t].evidence["reason"] == "open_to_any_user", t
        assert f[t].severity == "critical"


def test_everyone_wins_over_any_user(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table a (id int);\nalter table a enable row level security;\n"
        "create policy x on a for select using (auth.uid() is not null);\n"
        "create policy y on a for select to anon using (true);\n",
    )
    assert f["a"].evidence["reason"] == "open_to_everyone"


def test_write_only_and_scoped_policies_do_not_open(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table a (id int);\nalter table a enable row level security;\n"
        "create policy x on a for insert with check (true);\n"
        "create table b (id int);\nalter table b enable row level security;\n"
        "create table c (id int);\nalter table c enable row level security;\n"
        "create policy x on c for select using (auth.uid() is not null and id = 1);\n"
        "create table private.d (id int);\n",
    )
    assert not ({"a", "b", "c", "d", "private.d"} & set(f))


_BASE = "create table {t} (id int, user_id uuid);\nalter table {t} enable row level security;\n"


def test_restrictive_owner_check_closes_open_policy(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _BASE.format(t="c")
        + "create policy p on c for select using (true);\n"
        + "create policy r on c as restrictive for select using (auth.uid() = user_id);\n",
    )
    assert "c" not in f


def test_restrictive_for_other_role_does_not_close(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _BASE.format(t="c")
        + "create policy p on c for select using (true);\n"
        + "create policy r on c as restrictive for select to authenticated "
        + "using (auth.uid() = user_id);\n",
    )
    assert f["c"].evidence["reason"] == "open_to_everyone"


def test_service_role_ignored_in_roles(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _BASE.format(t="c")
        + "create policy p on c for select to authenticated, service_role using (true);\n",
    )
    assert f["c"].evidence["reason"] == "open_to_any_user"

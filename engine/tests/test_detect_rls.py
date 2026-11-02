import shutil

import pytest

from heist.detect.rls import find_rls_issues, is_personal_column
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
        "create table a (id int, email text);\nalter table a enable row level security;\n"
        "create policy x on a for select using (auth.role() = 'authenticated');\n"
        "create table b (id int, email text);\nalter table b enable row level security;\n"
        "create policy x on b for select using (auth.role() = 'authenticated'::text);\n"
        "create table c (id int, email text);\nalter table c enable row level security;\n"
        "create policy x on c for select to authenticated using (true);\n",
    )
    for t in "abc":
        assert f[t].evidence["reason"] == "open_to_any_user", t
        assert f[t].severity == "critical"


def test_any_user_read_of_a_table_with_no_personal_columns_is_low(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table lessons (id int, title text, error_message text);\n"
        "alter table lessons enable row level security;\n"
        "create policy x on lessons for select to authenticated using (true);\n",
    )
    assert f["lessons"].evidence["reason"] == "open_to_any_user"
    assert f["lessons"].severity == "low" and f["lessons"].status == "possible"
    assert f["lessons"].evidence["personal_columns"] == []
    assert "check this is meant to be shared" in f["lessons"].title


def test_rls_off_stays_critical_without_personal_columns(tmp_copy, vuln_app_path):
    f = _sql(tmp_copy, vuln_app_path, "create table colors (id int, name text);\n")
    assert f["colors"].evidence["reason"] == "rls_off"
    assert f["colors"].severity == "critical" and f["colors"].status == "confirmed"


def test_everyone_read_with_only_flag_and_content_columns_is_low(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table settings (id int, email_enabled bool, application_note text,"
        " phonetic_transcription text);\nalter table settings enable row level security;\n"
        "create policy x on settings for select using (true);\n",
    )
    assert f["settings"].severity == "low"
    assert f["settings"].evidence["personal_columns"] == []


@pytest.mark.parametrize(
    "name",
    [
        "email", "user_email", "contact_email", "phone", "phone_number", "parent1_phone",
        "address", "address_line1", "notes", "note", "message", "messages", "body",
        "date_of_birth", "dob", "password_hash", "confirmation_token", "user_id",
        "owner_id", "sender_id", "userEmail", "phoneNumber",
    ],
)  # fmt: skip
def test_personal_column_names(name):
    assert is_personal_column(name)


@pytest.mark.parametrize(
    "name",
    [
        "email_enabled", "email_autoconfirm", "email_confirmed_at", "phone_verified",
        "error_message", "last_message_at", "application_note", "analysis_notes",
        "phonetic_transcription", "title", "notebook", "addressed", "id", "created_at",
    ],
)  # fmt: skip
def test_non_personal_column_names(name):
    assert not is_personal_column(name)


def test_everyone_wins_over_any_user(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create table a (id int);\nalter table a enable row level security;\n"
        "create policy x on a for select using (auth.uid() is not null);\n"
        "create policy y on a for select to anon using (true);\n",
    )
    assert f["a"].evidence["reason"] == "open_to_everyone"


def test_scoped_policies_do_not_open(tmp_copy, vuln_app_path):
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
    # An insert open to everyone is an open write: critical (fix round 2, item 3).
    assert f["a"].severity == "critical" and f["a"].evidence["access"] == "write"
    assert not ({"b", "c", "d", "private.d"} & set(f))


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


_T = "create table {t} (id int, title text);\nalter table {t} enable row level security;\n"


@pytest.mark.parametrize(
    "policy, reason, access",
    [
        ("for all using (true)", "open_to_everyone", "read_write"),
        ("for all to authenticated using (true)", "open_to_any_user", "read_write"),
        ("for insert with check (true)", "open_to_everyone", "write"),
        ("for update using (true)", "open_to_everyone", "write"),
        ("for delete to anon using (true)", "open_to_everyone", "write"),
        ("for update to authenticated using (true)", "open_to_any_user", "write"),
        ("for delete using (auth.uid() is not null)", "open_to_any_user", "write"),
        ("for insert to authenticated with check (true)", "open_to_any_user", "write"),
    ],
)
def test_open_writes_are_critical_without_personal_columns(
    tmp_copy, vuln_app_path, policy, reason, access
):
    f = _sql(tmp_copy, vuln_app_path, _T.format(t="w") + f"create policy p on w {policy};\n")
    assert f["w"].evidence["reason"] == reason
    assert f["w"].evidence["access"] == access
    assert f["w"].severity == "critical" and f["w"].status == "confirmed"
    assert "change" in f["w"].title


def test_select_only_read_plus_open_write_is_critical(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _T.format(t="w")
        + "create policy r on w for select using (true);\n"
        + "create policy i on w for insert with check (true);\n",
    )
    assert f["w"].severity == "critical" and f["w"].evidence["access"] == "read_write"
    assert f["w"].title == "Anyone can read and change every row in w"


def test_select_only_read_without_personal_columns_stays_low(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _T.format(t="w") + "create policy r on w for select using (true);\n",
    )
    assert f["w"].severity == "low" and "access" not in f["w"].evidence


def test_owner_scoped_writes_do_not_open(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _BASE.format(t="w")
        + "create policy i on w for insert with check (auth.uid() = user_id);\n"
        + "create policy u on w for update using (auth.uid() = user_id);\n"
        + "create policy d on w for delete using (auth.uid() = user_id);\n",
    )
    assert "w" not in f


def test_restrictive_policy_closes_an_open_write(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        _BASE.format(t="w")
        + "create policy i on w for insert with check (true);\n"
        + "create policy r on w as restrictive for insert with check (auth.uid() = user_id);\n",
    )
    assert "w" not in f

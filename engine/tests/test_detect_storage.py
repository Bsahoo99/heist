import shutil

from heist.detect.storage import find_storage_issues
from tests.helpers import findings_for


def _sql(tmp_copy, vuln_app_path, sql):
    root = tmp_copy(vuln_app_path)
    (root / "supabase/migrations/0004_x.sql").write_text(sql)
    return {x.evidence["bucket"]: x for x in findings_for(root, find_storage_issues)}


def test_storage_findings(vuln_app_path):
    f = {x.evidence["bucket"]: x for x in findings_for(vuln_app_path, find_storage_issues)}
    assert f["id-documents"].severity == "high"
    assert f["pet-photos"].severity == "low"


def test_storage_finding_shape(vuln_app_path):
    f = {x.evidence["bucket"]: x for x in findings_for(vuln_app_path, find_storage_issues)}
    d = f["id-documents"]
    assert d.mistake == 4 and d.status == "confirmed" and d.id == "m4-id-documents"
    assert d.node_ids == ["bucket:id-documents"] and d.refs[0].start_line == 5
    assert d.evidence["public"] is False and d.evidence["reason"]
    p = f["pet-photos"]
    assert p.status == "possible" and p.refs[0].start_line == 2 and p.evidence["public"] is True


def test_clean_app_has_no_storage_findings(clean_app_path):
    assert findings_for(clean_app_path, find_storage_issues) == []


def test_whole_token_match(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "insert into storage.buckets (id, public) values ('video', true), ('user_avatar', true), "
        "('Passport-scans', true), ('paid', true);\n",
    )
    assert f["video"].severity == "low"
    assert f["paid"].severity == "low"
    assert f["user_avatar"].severity == "high" and f["user_avatar"].status == "confirmed"
    assert f["Passport-scans"].severity == "high"


def test_policy_must_quote_bucket_id(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "create policy z on storage.objects for select using (bucket_id = 'pet-photos-2');\n",
    )
    assert "pet-photos" in f


def test_cast_boolean_public_bucket(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "insert into storage.buckets (id, public) values ('x', 'true'::boolean);\n",
    )
    assert f["x"].evidence["public"] is True


def test_no_rules_no_findings(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    shutil.rmtree(root / "supabase/migrations")
    assert findings_for(root, find_storage_issues) == []


def test_plural_tokens(tmp_copy, vuln_app_path):
    f = _sql(
        tmp_copy,
        vuln_app_path,
        "insert into storage.buckets (id, public) values "
        "('avatars', true), ('user-documents', true), ('videos', true), ('invoices', true);\n",
    )
    assert f["avatars"].severity == "high"
    assert f["user-documents"].severity == "high"
    assert f["invoices"].severity == "high"
    assert f["videos"].severity == "low"

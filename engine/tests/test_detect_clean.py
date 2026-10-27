from tests.helpers import all_findings


def test_clean_app_has_no_confirmed_findings(clean_app_path):
    assert [f for f in all_findings(clean_app_path) if f.status != "possible"] == []

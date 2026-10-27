import shutil

import pytest

from heist.detect.secrets import find_frontend_secrets
from tests.helpers import findings_for

HAS_GITLEAKS = shutil.which("gitleaks") is not None
AWS_LIT = "AKIAIOSFODNN7EXAMPLE"
GH_LIT = "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xYz"


def test_flags_openai_key_in_vite_env(vuln_app_path):
    f = findings_for(vuln_app_path, find_frontend_secrets)
    m1 = [x for x in f if x.mistake == 1]
    assert [x.evidence["var"] for x in m1] == ["VITE_OPENAI_API_KEY"]
    assert m1[0].severity == "critical" and m1[0].status == "confirmed"
    assert m1[0].refs[0].file == ".env" and m1[0].refs[0].start_line == 4
    assert "sk-heist-fake" not in m1[0].model_dump_json()


@pytest.mark.parametrize(
    "line",
    [
        "VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
        "VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_abc123",
        "VITE_SUPABASE_URL=https://xyz.supabase.co",
    ],
)
def test_public_supabase_values_never_flagged(tmp_copy, vuln_app_path, line):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text(line + "\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []


def test_flags_service_role_in_frontend(vuln_app_path):
    m2 = [x for x in findings_for(vuln_app_path, find_frontend_secrets) if x.mistake == 2]
    assert m2[0].refs[0].file == "src/lib/admin.ts"
    assert m2[0].severity == "critical" and m2[0].status == "confirmed"


def test_service_role_jwt_value_flagged_even_if_named_anon(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text(
        "VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.x\n"
    )
    m2 = [x for x in findings_for(root, find_frontend_secrets) if x.mistake == 2]
    assert any(x.refs[0].file == ".env" and x.refs[0].start_line == 1 for x in m2)


def test_export_prefix_and_quotes(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text('# c\n\nexport VITE_STRIPE_SECRET_KEY="sk_live_abcdef123456"\n')
    m1 = [x for x in findings_for(root, find_frontend_secrets) if x.mistake == 1]
    assert [x.evidence["var"] for x in m1] == ["VITE_STRIPE_SECRET_KEY"]
    assert m1[0].evidence["preview"] == "sk_l..."


def test_server_only_env_vars_not_flagged(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text("OPENAI_API_KEY=sk-abcdef123456\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []


def test_env_example_ignored(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text("")
    (root / ".env.example").write_text("VITE_OPENAI_API_KEY=sk-abcdef123456\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_gitleaks_flags_hardcoded_literal_in_frontend(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/gh.ts").write_text(f'export const token = "{GH_LIT}"\n')
    f = findings_for(root, find_frontend_secrets)
    gl = [x for x in f if x.source == "gitleaks"]
    assert gl and gl[0].mistake == 1 and gl[0].refs[0].file == "src/lib/gh.ts"
    assert GH_LIT not in gl[0].model_dump_json()
    # the anon JWT in .env is allowlisted and the env var is not double reported
    assert all(x.refs[0].file != ".env" for x in gl)


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_gitleaks_literal_in_edge_function_not_flagged(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "supabase/functions/ai-describe/secret.ts").write_text(
        f'export const token = "{GH_LIT}"\n'
    )
    f = findings_for(root, find_frontend_secrets)
    assert [x for x in f if x.source == "gitleaks"] == []


def test_missing_gitleaks_is_not_fatal(tmp_copy, vuln_app_path, monkeypatch):
    monkeypatch.setattr("heist.detect.secrets.shutil.which", lambda _n: None)
    f = findings_for(vuln_app_path, find_frontend_secrets)
    assert any(x.mistake == 1 for x in f)


@pytest.mark.parametrize(
    "line",
    [
        "VITE_SUPABASE_ANON_KEY=changeme",
        "VITE_STRIPE_PUBLISHABLE_KEY=pk_live_abc123",
        "NEXT_PUBLIC_FIREBASE_API_KEY=AIzaSyFake",
        "VITE_RECAPTCHA_SITE_KEY=abcdefghij",
    ],
)
def test_public_browser_keys_not_flagged(tmp_copy, vuln_app_path, line):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text(line + "\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []


def test_env_local_example_ignored(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text("")
    (root / ".env.local.example").write_text("VITE_OPENAI_API_KEY=sk-abcdef123456\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_nested_env_example_not_scanned_by_gitleaks(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "src/.env.example").write_text(f"X={GH_LIT}\n")
    f = findings_for(root, find_frontend_secrets)
    assert [x for x in f if x.source == "gitleaks"] == []


def test_preview_does_not_reveal_short_values(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text("VITE_A_KEY=abc\n")
    (root / "src/lib/admin.ts").unlink()
    m1 = findings_for(root, find_frontend_secrets)
    assert m1[0].evidence["preview"] == "a..."

import base64
import json
import shutil

import pytest

from heist.detect.secrets import PUBLIC_NAME_RE, find_frontend_secrets, is_public_by_design
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


SEED_LINE = "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n"
BROWSER_LINE = "const admin = createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)\n"


def _m2_files(root) -> list[str]:
    return [x.refs[0].file for x in findings_for(root, find_frontend_secrets) if x.mistake == 2]


@pytest.mark.parametrize(
    "rel",
    [
        "scripts/seed.ts",
        "scripts/db/backfill.mjs",
        "seed.ts",
        "supabase/seed.ts",
        "supabase/seeds/users.js",
        "packages/admin/scripts/seed.ts",
    ],
)
def test_server_only_node_scripts_are_not_browser_code(tmp_copy, vuln_app_path, rel):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    if rel.startswith("packages/admin/"):
        (root / "packages/admin").mkdir(parents=True)
        (root / "packages/admin/package.json").write_text('{"name": "admin"}\n')
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(SEED_LINE)
    assert _m2_files(root) == []


def test_a_node_shebang_file_is_not_browser_code(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / "tools").mkdir()
    (root / "tools/reset.js").write_text("#!/usr/bin/env node\n" + SEED_LINE)
    assert _m2_files(root) == []


@pytest.mark.parametrize(
    "rel",
    ["src/scripts/admin.ts", "src/seed.ts", "src/lib/scripts.ts", "app/scripts/page.tsx"],
)
def test_app_code_named_like_scripts_is_still_caught(tmp_copy, vuln_app_path, rel):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(BROWSER_LINE)
    assert _m2_files(root) == [rel]


def test_a_shebang_without_node_is_still_caught(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / "src/lib/x.ts").write_text("#!/usr/bin/env deno\n" + BROWSER_LINE)
    assert _m2_files(root) == ["src/lib/x.ts"]


# --- browser code is what the front-end bundle reaches ---------------------------------------

INDEX_HTML = '<html><body><script type="module" src="/src/main.tsx"></script></body></html>\n'


def _vite_app(tmp_copy, vuln_app_path):
    """vuln_app with a real entry: index.html -> src/main.tsx -> src/App.tsx -> pages."""
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / "index.html").write_text(INDEX_HTML)
    (root / "src/main.tsx").write_text("import App from './App'\nimport './index.css'\n")
    (root / "src/App.tsx").write_text(
        "import Pets from '@/pages/Pets'\nimport { lazy } from 'react'\n"
        "const Upload = lazy(() => import('./pages/Upload'))\n"
    )
    return root


def test_vite_service_role_in_reachable_file_is_caught(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "src/lib/admin.ts").write_text(BROWSER_LINE)
    (root / "src/pages/Upload.tsx").write_text("import { admin } from '../lib/admin'\n")
    assert _m2_files(root) == ["src/lib/admin.ts"]


def test_vite_service_role_in_unreachable_file_is_not_browser_code(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "src/lib/unused.ts").write_text(BROWSER_LINE)
    assert _m2_files(root) == []


def test_vite_process_env_is_server_only(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").write_text(
        "if (!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('missing')\n"
    )
    assert _m2_files(root) == []


def test_root_script_imported_from_src_is_browser_code(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "scripts").mkdir()
    (root / "scripts/seed.ts").write_text(BROWSER_LINE)
    (root / "seed.ts").write_text(BROWSER_LINE)
    (root / "src/pages/Upload.tsx").write_text("import '../../scripts/seed'\nimport '../../seed'\n")
    assert sorted(_m2_files(root)) == ["scripts/seed.ts", "seed.ts"]


def test_root_script_imported_from_src_without_entry_is_browser_code(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").write_text("import '../../scripts/seed'\n")
    (root / "scripts").mkdir()
    (root / "scripts/seed.ts").write_text(BROWSER_LINE)
    assert _m2_files(root) == ["scripts/seed.ts"]


def test_import_meta_glob_reaches_its_folder(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "src/main.tsx").write_text("const pages = import.meta.glob('./routes/**/*.tsx')\n")
    (root / "src/routes/admin").mkdir(parents=True)
    (root / "src/routes/admin/Users.tsx").write_text(BROWSER_LINE)
    assert _m2_files(root) == ["src/routes/admin/Users.tsx"]


@pytest.mark.parametrize(
    "rel",
    [
        "tests/browser/smoke.spec.mjs",
        "src/lib/admin.test.ts",
        "cypress/e2e/flow.cy.ts",
        "backend/src/config/supabase.js",
        "backend/supabase/functions/list-users/index.ts",
        ".supabase/functions/user-management/index.ts",
        "_backup/pages/api/analyze.ts",
        "exportProjects.mjs",
        "_ptest.mjs",
        "create-tables.js",
    ],
)
def test_server_tests_and_root_scripts_are_not_browser_code(tmp_copy, vuln_app_path, rel):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(BROWSER_LINE)
    assert _m2_files(root) == []


def _next_app(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    shutil.rmtree(root / "src")
    (root / "package.json").write_text(
        '{"name": "n", "dependencies": {"@supabase/supabase-js": "^2", "next": "^15"}}\n'
    )
    (root / "app/api/admin").mkdir(parents=True)
    (root / "lib").mkdir()
    return root


NEXT_LINE = "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n"


def test_next_page_reaching_service_role_is_caught(tmp_copy, vuln_app_path):
    root = _next_app(tmp_copy, vuln_app_path)
    (root / "app/page.tsx").write_text("import { admin } from '@/lib/admin'\n")
    (root / "lib/admin.ts").write_text(NEXT_LINE)
    assert _m2_files(root) == ["lib/admin.ts"]


def test_next_route_handlers_and_unreached_lib_are_not_browser_code(tmp_copy, vuln_app_path):
    root = _next_app(tmp_copy, vuln_app_path)
    (root / "app/page.tsx").write_text("export default function P() { return null }\n")
    (root / "app/api/admin/route.ts").write_text(NEXT_LINE)
    (root / "lib/admin.ts").write_text(NEXT_LINE)
    (root / "pages/api").mkdir(parents=True)
    (root / "pages/api/x.ts").write_text(NEXT_LINE)
    assert _m2_files(root) == []


# --- public-by-design values ------------------------------------------------------------------


def _jwt(payload: dict[str, object]) -> str:
    def seg(d: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.c2lnbmF0dXJlLW5vdC1yZWFs"


ROLELESS_JWT = _jwt({"url": "storage/v1/object/sign/audio/a.mp3", "iat": 1, "exp": 2})
DEMO_ANON = _jwt({"iss": "supabase-demo", "role": "anon", "exp": 1983812996})
DEMO_SERVICE = _jwt({"iss": "supabase-demo", "role": "service_role", "exp": 1983812996})
REAL_SERVICE = _jwt({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "service_role"})


@pytest.mark.parametrize(
    "value, public",
    [
        (ROLELESS_JWT, True),
        (DEMO_ANON, True),
        (DEMO_SERVICE, True),
        (REAL_SERVICE, False),
        (_jwt({"role": "authenticated", "sub": "u"}), False),
        (_jwt({"application": "a", "iss": "vendor", "jti": "j", "iat": 1}), False),
        (_jwt({"url": "audio/a.mp3", "iat": 1}), False),
        (_jwt({"sub": "svc", "exp": 2}), False),
    ],
)
def test_public_by_design_jwts(value, public):
    assert is_public_by_design(value) is public


@pytest.mark.parametrize(
    "line",
    [
        "VITE_HCAPTCHA_SITEKEY=10000000-ffff-ffff-ffff-000000000001",
        "VITE_COPILOTKIT_PUBLIC_API_KEY=ck_pub_abcdef1234567890",
        f"VITE_SUPABASE_SERVICE_ROLE_KEY={DEMO_SERVICE}",
        f"VITE_SOME_TOKEN={ROLELESS_JWT}",
    ],
)
def test_more_public_browser_values_not_flagged(tmp_copy, vuln_app_path, line):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text(line + "\n")
    (root / "src/lib/admin.ts").unlink()
    assert findings_for(root, find_frontend_secrets) == []


def test_real_service_role_jwt_value_still_flagged(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / ".env").write_text(f"VITE_SUPABASE_KEY={REAL_SERVICE}\n")
    (root / "src/lib/admin.ts").unlink()
    f = findings_for(root, find_frontend_secrets)
    assert [(x.mistake, x.severity, x.status) for x in f] == [(2, "critical", "confirmed")]


def test_redaction_keeps_the_narrow_public_names():
    assert PUBLIC_NAME_RE.search("VITE_HCAPTCHA_SITEKEY") is None
    assert PUBLIC_NAME_RE.search("VITE_COPILOTKIT_PUBLIC_API_KEY") is None


# --- secrets committed outside the browser code ------------------------------------------------


def _gitleaks(root):
    return [x for x in findings_for(root, find_frontend_secrets) if x.source == "gitleaks"]


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
@pytest.mark.parametrize("rel", ["docs/SETUP.md", "deploy.ps1", "n8n-workflows/flow.json"])
def test_admin_key_committed_in_a_public_file_is_confirmed(tmp_copy, vuln_app_path, rel):
    root = tmp_copy(vuln_app_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(f'service key: "{REAL_SERVICE}"\n')
    gl = _gitleaks(root)
    assert [(x.mistake, x.severity, x.status) for x in gl] == [(2, "critical", "confirmed")]
    assert gl[0].title == "Your Supabase admin key is committed in a public file"
    assert gl[0].evidence["location"] == "public_file" and gl[0].refs[0].file == rel
    assert REAL_SERVICE not in gl[0].model_dump_json()


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
@pytest.mark.parametrize(
    "rel", ["README.md", "docs/env.txt", ".cursor/mcp.json", "supabase/config.toml"]
)
def test_other_key_committed_in_a_public_file_is_possible(tmp_copy, vuln_app_path, rel):
    root = tmp_copy(vuln_app_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(f'token = "{GH_LIT}"\n')
    gl = _gitleaks(root)
    assert [(x.mistake, x.severity, x.status) for x in gl] == [(1, "high", "possible")]
    assert "committed in a public file" in gl[0].title
    assert "browser" not in gl[0].title
    assert gl[0].evidence["location"] == "public_file"


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_key_in_unreachable_source_file_is_possible_not_browser(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "src/lib/unused.ts").write_text(f'export const token = "{GH_LIT}"\n')
    gl = _gitleaks(root)
    assert [(x.mistake, x.status, x.refs[0].file) for x in gl] == [
        (1, "possible", "src/lib/unused.ts")
    ]


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_key_in_reachable_source_file_is_confirmed_browser_code(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "src/pages/Upload.tsx").write_text(f'export const token = "{GH_LIT}"\n')
    gl = _gitleaks(root)
    assert [(x.mistake, x.severity, x.status) for x in gl] == [(1, "critical", "confirmed")]
    assert gl[0].title == "A secret key is hardcoded in your browser code"
    assert "location" not in gl[0].evidence


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
@pytest.mark.parametrize(
    "rel, value",
    [
        ("tests/fixtures/keys.ts", GH_LIT),
        ("cypress/e2e/flow.cy.ts", GH_LIT),
        (".bolt/supabase_discarded_migrations/0001_x.sql", GH_LIT),
        ("supabase/migrations/0009_songs.sql", ROLELESS_JWT),
        ("docs/LOCAL.md", DEMO_SERVICE),
    ],
)
def test_tests_discarded_migrations_and_public_tokens_are_skipped(
    tmp_copy, vuln_app_path, rel, value
):
    root = tmp_copy(vuln_app_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(f"-- '{value}'\n")
    assert _gitleaks(root) == []


# --- fix round 2 ---------------------------------------------------------------------------------


@pytest.mark.parametrize("rel", ["src/pages/tests/Quiz.tsx", "src/fixtures/data.ts"])
def test_test_named_folder_the_bundle_imports_is_browser_code(tmp_copy, vuln_app_path, rel):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(BROWSER_LINE)
    spec = "../" + rel.removeprefix("src/").rsplit(".", 1)[0]
    (root / "src/pages/Upload.tsx").write_text(f"import '{spec}'\n")
    assert _m2_files(root) == [rel]


def test_test_named_folder_nothing_imports_is_not_browser_code(tmp_copy, vuln_app_path):
    root = _vite_app(tmp_copy, vuln_app_path)
    (root / "src/pages/tests").mkdir(parents=True)
    (root / "src/pages/tests/Quiz.tsx").write_text(BROWSER_LINE)
    assert _m2_files(root) == []


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
@pytest.mark.parametrize(
    "rel",
    [
        "tests/setup.ts",
        ".bolt/supabase_discarded_migrations/0001_x.sql",
        "supabase/functions/admin/index.ts",
    ],
)
def test_admin_key_in_a_skipped_file_is_still_reported(tmp_copy, vuln_app_path, rel):
    root = tmp_copy(vuln_app_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(f"const key = '{REAL_SERVICE}'\n")
    gl = _gitleaks(root)
    assert [(x.mistake, x.severity, x.status, x.refs[0].file) for x in gl] == [
        (2, "critical", "confirmed", rel)
    ]
    assert gl[0].title == "Your Supabase admin key is committed in a public file"


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_admin_key_on_a_line_named_anon_is_still_reported(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    (root / "docs").mkdir()
    (root / "docs/SETUP.md").write_text(f"SUPABASE_ANON_KEY: {REAL_SERVICE}\n")
    assert [(x.mistake, x.status) for x in _gitleaks(root)] == [(2, "confirmed")]


@pytest.mark.parametrize(
    "rel, line",
    [
        (".env", f"SUPABASE_SERVICE_ROLE_KEY={REAL_SERVICE}"),
        (".env.local", f"DB_KEY={REAL_SERVICE}"),
        ("supabase/functions/.env", f"SERVICE_KEY={REAL_SERVICE}"),
        ("backend/.env", f"SUPABASE_KEY={REAL_SERVICE}"),
    ],
)
def test_admin_key_in_a_committed_env_file_is_reported(tmp_copy, vuln_app_path, rel, line):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / ".env").write_text("")
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(line + "\n")
    f = findings_for(root, find_frontend_secrets)
    assert [(x.mistake, x.severity, x.status, x.refs[0].file) for x in f] == [
        (2, "critical", "confirmed", rel)
    ]
    assert f[0].title == "Your Supabase admin key is committed in a public file"
    assert f[0].evidence["location"] == "public_file"
    assert REAL_SERVICE not in f[0].model_dump_json()


@pytest.mark.parametrize(
    "line",
    [
        f"SUPABASE_SERVICE_ROLE_KEY={DEMO_SERVICE}",
        "SUPABASE_SERVICE_ROLE_KEY=your-service-role-key",
        "OPENAI_API_KEY=sk-abcdef123456",
    ],
)
def test_non_admin_server_env_values_are_not_reported(tmp_copy, vuln_app_path, line):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").unlink()
    (root / ".env").write_text(line + "\n")
    assert findings_for(root, find_frontend_secrets) == []


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_placeholder_admin_jwt_in_docs_is_not_an_admin_key(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    placeholder = REAL_SERVICE.rsplit(".", 1)[0] + ".x"
    (root / "docs").mkdir()
    (root / "docs/SETUP.md").write_text(f"VITE_SUPABASE_ANON_KEY={placeholder}\n")
    assert [x for x in _gitleaks(root) if x.mistake == 2] == []


@pytest.mark.parametrize(
    "text",
    [
        "const env = import.meta.env;\nexport const admin = createClient(url, env.VITE_SUPABASE_SERVICE_ROLE_KEY)\n",
        "const { VITE_SUPABASE_SERVICE_ROLE_KEY: k } = import.meta.env\nconst x = process.env.SUPABASE_SERVICE_ROLE_KEY ?? import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY\n",
    ],
)
def test_vite_env_through_an_alias_is_caught(tmp_copy, vuln_app_path, text):
    root = tmp_copy(vuln_app_path)
    (root / "src/lib/admin.ts").write_text(text)
    assert _m2_files(root) == ["src/lib/admin.ts"]

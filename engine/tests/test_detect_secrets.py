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

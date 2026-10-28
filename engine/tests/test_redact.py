"""Secrets must never reach a model prompt. All secrets here are fake."""

from pathlib import Path

import pytest

from heist.fetch import Workspace
from heist.llm.redact import REDACTED, redact_for_prompt
from heist.llm.trace import build_user_prompt
from heist.models import AppGraph, CodeRef, Edge, Finding, Node

STRIPE = "sk_" + "live_FAKEcommentedKEY0123456789abcdef"
AWS = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY99"
DB_PASS = "Hunter2SuperSecret"
TMPL = "q8Zr2Lm9Xc4Vb7Nk1Pw3Ty"
CHUNK = "a1B2c3D4e5F6g7H"
SHORT_PW = "pa55w0rdShort"
JSON_KEY = "Abc123Def456Ghi789Jk"
URL_KEY = "Xk29Lm3Np8Qr7St5Uv"
LETTERS = "abcdefghijklmnopqrstuvwxyzabcdefghij"


def secret_at(rel: str, start: int, end: int | None = None) -> Finding:
    return Finding(
        id=f"m1-{rel}-{start}",
        mistake=1,
        severity="critical",
        status="confirmed",
        title="t",
        node_ids=[],
        refs=[CodeRef(file=rel, start_line=start, end_line=end or start)],
        source="gitleaks",
    )


def redact(rel: str, text: str, findings: list[Finding] | None = None) -> str:
    out = redact_for_prompt(rel, text, findings or [])
    assert len(out.splitlines()) == len(text.splitlines()), "line numbers must stay real"
    return out


# --- CRITICAL A: env comments ---------------------------------------------------------


def test_env_comment_lines_lose_their_values():
    text = f"# OLD_STRIPE={STRIPE}\n  #STRIPE_SECRET_KEY={STRIPE}\n# just a note\n# {STRIPE}\n"
    out = redact(".env", text)
    assert STRIPE not in out
    assert out.splitlines() == [
        f"# OLD_STRIPE={REDACTED}",
        f"  #STRIPE_SECRET_KEY={REDACTED}",
        "# just a note",
        f"# {REDACTED}",
    ]


# --- CRITICAL B: slashes in keys, secrets in URLs -------------------------------------


def test_base64_key_with_slashes_is_not_a_path():
    out = redact("src/x.ts", f'const value = "{AWS}";\n')
    assert AWS not in out and "bPxRfiCYFAKEKEY99" not in out
    assert out == f'const value = "{REDACTED}";\n'


def test_secret_url_segments_are_hidden_but_scheme_and_host_kept():
    text = (
        f"const hook = `https://hooks.example.com/services/{URL_KEY}`;\n"
        f"fetch('https://x.example.com/cb?code={URL_KEY}&page=2&api_key=short1')\n"
    )
    out = redact("supabase/functions/chat/index.ts", text)
    assert URL_KEY not in out and "short1" not in out
    assert f"`https://hooks.example.com/services/{REDACTED}`" in out
    assert f"?code={REDACTED}&page=2&api_key={REDACTED}" in out


def test_real_paths_and_urls_are_kept():
    text = (
        "fetch('https://api.openai.com/v1/chat/completions')\n"
        "import PetCard from '../components/PetCard.tsx'\n"
        "const m = 'supabase/migrations/0001_init.sql'\n"
        "const p = '/storage/v1/object/public/pet-photos/dog2.jpg'\n"
        "const s = 'src/pages/Step2/AdoptionForm.tsx'\n"
    )
    assert redact("src/x.ts", text) == text


# --- IMPORTANT C ----------------------------------------------------------------------


@pytest.mark.parametrize("rel", ["supabase/functions/chat/index.ts", "README.md", "notes.txt"])
def test_url_password_is_always_hidden(rel):
    text = f"postgresql://postgres:{DB_PASS}@db.x.supabase.co:5432/postgres\n"
    out = redact(rel, text)
    assert DB_PASS not in out
    assert f"postgresql://postgres:{REDACTED}@db.x.supabase.co:5432/postgres" in out


@pytest.mark.parametrize(
    "rel",
    [".dev.vars", "app/.dev.vars", "wrangler.toml", "secrets.json", "config.yaml", "ci.yml"],
)
def test_config_files_are_assignment_files(rel):
    text = f"DB_PASSWORD={SHORT_PW}\ndb_password: {SHORT_PW}\nraw {SHORT_PW}\n"
    out = redact(rel, text)
    assert SHORT_PW not in out
    assert out.splitlines()[:2] == [f"DB_PASSWORD={REDACTED}", f"db_password:{REDACTED}"]


def test_toml_keeps_sections_and_booleans():
    text = '[functions.send-email]\nverify_jwt = false\nproject_id = "heistfixture"\n'
    out = redact("supabase/config.toml", text)
    assert out.splitlines() == [
        "[functions.send-email]",
        "verify_jwt = false",
        f"project_id ={REDACTED}",
    ]


@pytest.mark.parametrize(
    ("rel", "line"),
    [
        ("src/config.json", f'{{"apiKey": "{JSON_KEY}"}}'),
        ("src/a.ts", f"const clientSecret = '{JSON_KEY}';"),
        ("src/a.ts", f"export const config = {{ authToken: `{JSON_KEY}` }}"),
        ("app.py", f'API_KEY = "{JSON_KEY}"'),
        ("app.py", f"db_pwd='{JSON_KEY}'"),
        ("config.php", f"'api_key' => '{JSON_KEY}',"),
        ("Dockerfile", f"ENV DB_PASSWORD={SHORT_PW}"),
        ("docs/setup.md", f"Set the private_credential: {SHORT_PW} before deploying."),
    ],
)
def test_values_of_secret_names_are_hidden_in_any_file(rel, line):
    out = redact(rel, line + "\n")
    assert JSON_KEY not in out and SHORT_PW not in out
    assert REDACTED in out


def test_code_expressions_and_public_values_are_kept():
    text = (
        "const apiKey = import.meta.env.VITE_OPENAI_API_KEY\n"
        "const token = await getToken()\n"
        "function f(password: string) {}\n"
        "const anonKey = 'sb_publishable_demo_value'\n"
        "const AUTH_URL = 'https://x.supabase.co/auth/v1'\n"
    )
    assert redact("src/a.ts", text) == text
    out = redact("src/a.ts", "const serviceKey = 'sb_publishable_demo_value'\n")
    assert "sb_publishable_demo_value" not in out


def test_flagged_line_widens_to_the_multi_line_template_literal():
    text = f"// don't do this\nconst key = `\n{TMPL}\n`;\nconst ok = 'keep'\n"
    out = redact("src/lib/ai.ts", text, [secret_at("src/lib/ai.ts", 2)])
    assert TMPL not in out
    assert out.splitlines()[-1] == "const ok = 'keep'"


def test_open_literal_after_a_secret_name_is_hidden_without_a_finding():
    text = f"const settings = {{ apiKey: `\n{TMPL}\n` }}\nconst ok = 'keep'\n"
    out = redact("src/lib/ai.ts", text)
    assert TMPL not in out and "const ok = 'keep'" in out


def test_widening_is_capped():
    body = "\n".join(f"{TMPL}{i}" for i in range(60))
    out = redact("src/a.ts", f"const s = `\n{body}\n`\n", [secret_at("src/a.ts", 1)])
    hidden = out.splitlines()[1:51]
    assert all(TMPL not in line for line in hidden)


@pytest.mark.parametrize(
    "text",
    [
        f'const k2 = "sk_live_" +\n  "{CHUNK}" +\n  "{CHUNK[::-1]}";\n',
        f'const k2 = "sk_live_"\n  + "{CHUNK}"\n  + "{CHUNK[::-1]}";\n',
        f'const k2 = [\n  "{CHUNK}",\n  "{CHUNK[::-1]}",\n].join("")\n',
    ],
)
def test_key_split_across_concatenation_is_hidden(text):
    out = redact("src/lib/ai.ts", text, [secret_at("src/lib/ai.ts", 1)])
    assert CHUNK not in out and CHUNK[::-1] not in out


def test_flagged_line_hides_every_literal_regardless_of_length():
    out = redact("src/a.ts", "const k = 'a' + 'b1' + `c`\n", [secret_at("src/a.ts", 1)])
    assert out == f"const k = '{REDACTED}' + '{REDACTED}' + `{REDACTED}`\n"


def test_long_letter_only_token_is_hidden_anywhere():
    out = redact("src/a.ts", f"const t = '{LETTERS}';\nconst u = {LETTERS.upper()}\n")
    assert LETTERS not in out and LETTERS.upper() not in out


# --- end to end: the reviewer's leak script -------------------------------------------


def test_reviewer_leak_cases_never_reach_the_prompt(tmp_path: Path):
    files = {
        ".env": (
            "VITE_SUPABASE_URL=https://x.supabase.co\n"
            f"# OLD_STRIPE={STRIPE}\n"
            f"  #STRIPE_SECRET_KEY={STRIPE}\n"
            "VITE_OPENAI_API_KEY=sk-proj-FAKEFAKEFAKE0123456789abcdefghij\n"
        ),
        "supabase/functions/chat/index.ts": (
            f'const AWS_SECRET = "{AWS}";\n'
            f"const db = 'postgresql://postgres:{DB_PASS}@db.x.supabase.co:5432/postgres';\n"
            f"const hook = `https://hooks.example.com/services/{URL_KEY}`;\n"
            f"const t = '{LETTERS}';\n"
            "fetch('https://api.openai.com/v1/chat/completions')\n"
        ),
        "src/lib/ai.ts": (
            f"// don't do this\nconst key = `\n{TMPL}\n`;\n"
            f'const k2 = "sk_live_" +\n "{CHUNK}" +\n "{CHUNK[::-1]}";\n'
        ),
        ".dev.vars": f"DB_PASSWORD={SHORT_PW}\n",
        "src/config.json": f'{{"apiKey": "{JSON_KEY}"}}\n',
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    ws = Workspace(root=tmp_path, app_root=tmp_path, commit_sha="x", files=sorted(files))

    def ref(rel: str) -> CodeRef:
        return CodeRef(file=rel, start_line=1, end_line=1)

    g = AppGraph(
        stack="vite_supabase",
        has_db_rules=False,
        nodes=[
            Node(
                id="page:ai", kind="page", name="ai", zone="shop_window", ref=ref("src/lib/ai.ts")
            ),
            Node(
                id="fn:chat",
                kind="function",
                name="chat",
                zone="side_doors",
                ref=ref("supabase/functions/chat/index.ts"),
            ),
            Node(id="ext:openai", kind="external_api", name="api.openai.com", zone="across_road"),
            Node(id="env", kind="env_file", name=".env", zone="shop_window", ref=ref(".env")),
            Node(id="cfg", kind="page", name="cfg", zone="shop_window", ref=ref("src/config.json")),
            Node(id="dv", kind="function", name="dv", zone="side_doors", ref=ref(".dev.vars")),
        ],
        edges=[
            Edge(src="fn:chat", dst="ext:openai", kind="calls_external"),
            Edge(src="page:ai", dst="cfg", kind="imports"),
            Edge(src="page:ai", dst="dv", kind="imports"),
            Edge(src="page:ai", dst="env", kind="imports"),
        ],
    )
    f = Finding(
        id="m1-x",
        mistake=1,
        severity="critical",
        status="confirmed",
        title="t",
        node_ids=["page:ai"],
        refs=[
            CodeRef(file="src/lib/ai.ts", start_line=2, end_line=2),
            CodeRef(file="src/lib/ai.ts", start_line=5, end_line=5),
        ],
        source="gitleaks",
        evidence={"var": "VITE_OPENAI_API_KEY", "preview": "sk-p..."},
    )
    prompt = build_user_prompt(f, g, ws, findings=[f])
    assert prompt.count("=== ") == len(files)
    for secret in (STRIPE, AWS, DB_PASS, TMPL, CHUNK, CHUNK[::-1], SHORT_PW, JSON_KEY, URL_KEY):
        assert secret not in prompt
    assert LETTERS not in prompt and "sk-proj-FAKE" not in prompt
    assert "fetch('https://api.openai.com/v1/chat/completions')" in prompt

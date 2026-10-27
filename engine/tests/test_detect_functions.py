import subprocess
from pathlib import Path

import pytest

from heist.detect import functions
from heist.detect.functions import find_function_issues
from heist.fetch import detect_stack, load_workspace
from heist.graph.build import build_app_graph
from tests.helpers import findings_for


def _run(path: Path):
    return findings_for(path, find_function_issues)


PKG = '{"dependencies": {"next": "14.0.0", "@supabase/supabase-js": "2.0.0"}}'


def _write(root: Path, files: dict[str, str]) -> Path:
    files = {"package.json": PKG, **files}
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_function_findings(vuln_app_path):
    f = _run(vuln_app_path)
    by = {(x.mistake, x.evidence["function"]) for x in f}
    assert (5, "send-email") in by
    assert (6, "update-request") in by
    assert (7, "ai-describe") in by
    m6 = next(x for x in f if x.mistake == 6)
    assert m6.status == "possible"


def test_m7_replaces_m5_for_same_function(vuln_app_path):
    f = _run(vuln_app_path)
    assert (5, "ai-describe") not in {(x.mistake, x.evidence["function"]) for x in f}
    m7 = next(x for x in f if x.mistake == 7)
    assert m7.evidence["host"] == "api.openai.com"
    assert m7.refs[0].start_line == 5


def test_verify_jwt_false_is_cited(vuln_app_path):
    m5 = [x for x in _run(vuln_app_path) if x.mistake == 5]
    assert any(r.file == "supabase/config.toml" for r in m5[0].refs)
    assert any(r.file.endswith("send-email/index.ts") for r in m5[0].refs)


def test_auth_check_clears_m5_and_m7(clean_app_path):
    f = _run(clean_app_path)
    assert not [x for x in f if x.mistake in (5, 7)]


def test_clean_app_has_no_function_findings(clean_app_path):
    assert _run(clean_app_path) == []


def test_next_route_without_auth(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "app/api/export/route.ts": (
                "export async function POST(req: Request) {\n  return Response.json({ok: true})\n}\n"
            ),
            "app/api/me/route.ts": (
                "import { auth } from '@/auth'\n"
                "export async function GET() {\n  const s = await auth()\n"
                "  return Response.json(s)\n}\n"
            ),
        },
    )
    f = _run(app)
    assert [(x.mistake, x.evidence["function"], x.node_ids) for x in f] == [
        (5, "route:/api/export", ["route:/api/export"])
    ]
    assert f[0].refs[0].start_line == 1


def test_reading_authorization_header_is_not_auth(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "supabase/functions/hook/index.ts": (
                "Deno.serve(async (req) => {\n"
                "  const token = req.headers.get('Authorization')\n"
                "  return new Response(token ?? 'none')\n})\n"
            ),
        },
    )
    f = _run(app)
    assert [(x.mistake, x.evidence["function"]) for x in f] == [(5, "hook")]


def test_auth_in_shared_helper_counts(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "supabase/functions/_shared/auth.ts": (
                "export async function requireUser(c: any) { return (await c.auth.getUser()).data }\n"
            ),
            "supabase/functions/hook/index.ts": (
                "import { requireUser } from '../_shared/auth.ts'\n"
                "Deno.serve(async (req) => {\n  await requireUser(req)\n"
                "  return new Response('ok')\n})\n"
            ),
        },
    )
    assert _run(app) == []


def test_use_server_action_without_auth(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "app/actions.ts": "'use server'\nexport async function wipe() {\n  return 1\n}\n",
        },
    )
    f = _run(app)
    assert [(x.mistake, x.evidence["function"]) for x in f] == [(5, "route:action:app/actions.ts")]


def test_missing_semgrep_returns_empty(vuln_app_path, monkeypatch, caplog):
    monkeypatch.setattr(functions.shutil, "which", lambda _name: None)
    with caplog.at_level("WARNING"):
        assert _run(vuln_app_path) == []
    assert "semgrep not found" in caplog.text


def test_semgrep_failure_returns_empty(vuln_app_path, monkeypatch):
    def boom(*_a, **_k):
        return subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="bad")

    monkeypatch.setattr(functions.subprocess, "run", boom)
    assert _run(vuln_app_path) == []


@pytest.mark.parametrize("env,expect", [(None, False), ("1", True)])
def test_community_rules_only_with_env(vuln_app_path, monkeypatch, env, expect):
    calls: list[list[str]] = []
    real = subprocess.run

    def spy(cmd, *a, **k):
        calls.append(list(cmd))
        if "p/typescript" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout='{"results": []}', stderr="")
        return real(cmd, *a, **k)

    monkeypatch.setattr(functions.subprocess, "run", spy)
    monkeypatch.delenv("HEIST_SEMGREP_COMMUNITY", raising=False)
    if env:
        monkeypatch.setenv("HEIST_SEMGREP_COMMUNITY", env)
    ws = load_workspace(vuln_app_path)
    g = build_app_graph(ws, detect_stack(ws))
    find_function_issues(ws, g)
    assert any("p/typescript" in c for c in calls) is expect
    custom = [c for c in calls if "p/typescript" not in c]
    assert len(custom) == 1
    assert "--metrics=off" in custom[0] and "--json" in custom[0]


def test_community_hit_mapping():
    out = functions._community_findings(
        {
            "results": [
                {
                    "check_id": "typescript.lang.bad",
                    "path": "/x/app/a.ts",
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {"message": "Bad thing", "severity": "ERROR"},
                },
                {
                    "check_id": "typescript.lang.other",
                    "path": "/x/app/outside.ts",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "x", "severity": "INFO"},
                },
            ]
        },
        Path("/x/app"),
        {"a.ts"},
    )
    assert len(out) == 1
    f = out[0]
    assert (f.mistake, f.severity, f.status, f.source) == (
        0,
        "high",
        "possible",
        "semgrep_community",
    )


def test_supabase_auth_callback_route_is_public_by_design(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "app/auth/callback/route.ts": (
                "import { createClient } from '@/utils/supabase/server'\n"
                "export async function GET(request: Request) {\n"
                "  const supabase = await createClient()\n"
                "  await supabase.auth.exchangeCodeForSession('code')\n"
                "  return Response.redirect('/')\n}\n"
            ),
        },
    )
    assert _run(app) == []


def test_nextauth_routes_are_public_by_design(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "app/api/auth/[...nextauth]/route.ts": (
                "import NextAuth from 'next-auth'\n"
                "const handler = NextAuth({ providers: [] })\n"
                "export { handler as GET, handler as POST }\n"
            ),
            "app/api/v5/auth/route.ts": "export { GET, POST } from '@/auth'\n",
            "app/api/v5b/auth/route.ts": (
                "import { handlers } from '@/auth'\nexport const { GET, POST } = handlers\n"
            ),
        },
    )
    assert _run(app) == []


def test_alias_import_helper_with_auth_counts(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "src/lib/guard.ts": "export async function requireUser(c: any) { return c.auth.getUser() }\n",
            "src/app/api/a/route.ts": (
                "import { requireUser } from '@/lib/guard'\n"
                "export async function GET() {\n  await requireUser(1)\n  return Response.json(1)\n}\n"
            ),
            "tsconfig.json": '{"compilerOptions": {"paths": {"~~/*": ["./src/lib/*"]}}}',
            "src/app/api/b/route.ts": (
                "import { requireUser } from '~~/guard'\n"
                "export async function GET() {\n  await requireUser(1)\n  return Response.json(1)\n}\n"
            ),
        },
    )
    assert _run(app) == []


def test_middleware_auth_downgrades_route_m5(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "middleware.ts": (
                "export async function middleware(req: any) {\n"
                "  const { data } = await supa.auth.getUser()\n  return data\n}\n"
            ),
            "app/api/x/route.ts": "export async function GET() {\n  return Response.json(1)\n}\n",
            "supabase/functions/open/index.ts": "Deno.serve(() => new Response('hi'))\n",
        },
    )
    by = {x.evidence["function"]: x for x in _run(app)}
    assert (by["route:/api/x"].severity, by["route:/api/x"].status) == ("medium", "possible")
    assert "middleware" in by["route:/api/x"].title
    assert (by["open"].severity, by["open"].status) == ("high", "confirmed")


def test_third_party_get_user_is_not_auth(tmp_path):
    app = _write(
        tmp_path / "app",
        {
            "app/api/x/route.ts": (
                "export async function GET() {\n  const u = await clerk.users.getUser('u')\n"
                "  return Response.json(u)\n}\n"
            ),
        },
    )
    assert [x.mistake for x in _run(app)] == [5]


def test_crlf_line_numbers(tmp_path):
    src = "// a\r\n// b\r\n// c\r\nDeno.serve(() => new Response('x'))\r\n"
    app = _write(tmp_path / "app", {})
    p = app / "supabase/functions/crlf/index.ts"
    p.parent.mkdir(parents=True)
    p.write_bytes(src.encode())
    f = _run(app)
    assert [(x.mistake, x.refs[0].start_line) for x in f] == [(5, 4)]


def test_semgrep_runs_in_chunks(vuln_app_path, monkeypatch):
    monkeypatch.setattr(functions, "SEMGREP_CHUNK", 2)
    calls: list[int] = []
    real = subprocess.run

    def spy(cmd, *a, **k):
        calls.append(len(cmd))
        return real(cmd, *a, **k)

    monkeypatch.setattr(functions.subprocess, "run", spy)
    by = {(x.mistake, x.evidence["function"]) for x in _run(vuln_app_path)}
    assert len(calls) == 2
    assert {(5, "send-email"), (7, "ai-describe"), (6, "update-request")} <= by

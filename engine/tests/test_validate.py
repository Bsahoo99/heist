import shutil
import subprocess
from pathlib import Path
from typing import Any, TypeVar

import pytest
from pydantic import BaseModel

from heist.fetch import Workspace, detect_stack, load_workspace
from heist.graph.build import build_app_graph
from heist.llm.client import ModelOutputError
from heist.llm.templates import fallback_trace
from heist.llm.trace import (
    FEEDBACK_HEADER,
    TRACE_MAX_TOKENS,
    build_user_prompt,
    redact_for_prompt,
    system_prompt,
    trace_finding,
    trace_with_validation,
)
from heist.models import AppGraph, CodeRef, Finding, FixOut, StepOut, TraceOut
from heist.validate import _hunk_at, check_diff, validate_trace
from tests.helpers import all_findings

T = TypeVar("T", bound=BaseModel)

EM_DASH = "\u2014"
FAKE_OPENAI_KEY = "sk-heist-fake-3f9a1c7e5b2d8046af13c9e7b5d20846a1f3c9e7"
ANON_JWT_SIGNATURE = "dOuy3eyutRCNTWXCCBcY7cT0Tk6tyMmHCoqhvxRjLvc"
MIGRATION = "supabase/migrations/0001_init.sql"
GOOD_DIFF = (
    "--- a/supabase/migrations/0001_init.sql\n"
    "+++ b/supabase/migrations/0001_init.sql\n"
    "@@ -40,2 +40,4 @@\n"
    "   body text\n"
    " );\n"
    "+\n"
    "+alter table public.messages enable row level security;\n"
)


class FakeClient:
    """Stands in for MetaClient: returns or raises queued items, records each call."""

    def __init__(self) -> None:
        self._queue: list[Any] = []
        self.calls = 0
        self.last_feedback: str | None = None
        self.last_user = ""
        self.last_system = ""
        self.last_which = ""
        self.last_max_tokens = 0

    def queue(self, *items: Any) -> None:
        self._queue.extend(items)

    def chat_json(
        self, which: Any, system: str, user: str, schema: type[T], max_tokens: int = 4000
    ) -> T:
        self.calls += 1
        self.last_user, self.last_system = user, system
        self.last_which, self.last_max_tokens = which, max_tokens
        self.last_feedback = user.split(FEEDBACK_HEADER, 1)[1] if FEEDBACK_HEADER in user else None
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def ws(vuln_app_path: Path) -> Workspace:
    return load_workspace(vuln_app_path)


@pytest.fixture
def graph(ws: Workspace) -> AppGraph:
    return build_app_graph(ws, detect_stack(ws))


@pytest.fixture(scope="module")
def vuln_findings() -> list[Finding]:
    return all_findings(Path(__file__).parent / "fixtures" / "vuln_app")


@pytest.fixture
def f_messages(vuln_findings: list[Finding]) -> Finding:
    return next(f for f in vuln_findings if f.id == "m3-messages")


@pytest.fixture
def fake_client() -> FakeClient:
    return FakeClient()


def step(
    node_id: str = "table:messages",
    zone: Any = "vault",
    file: str | None = MIGRATION,
    line: int | None = 37,
    text: str = "x",
) -> StepOut:
    return StepOut(
        node_id=node_id, zone=zone, file=file, line=line, data=text, story=text, why=text, code=text
    )


def good_trace(f: Finding) -> TraceOut:
    return TraceOut(
        ghost_path=[
            step("visitor", "street", None, None),
            step("auth:supabase", "guard_desk", None, None),
            step("table:messages", "vault", MIGRATION, 37),
        ],
        attack_path=[
            step("visitor", "street", None, None),
            step("client:src/pages/Pets.tsx:9", "shop_window", "src/pages/Pets.tsx", 9),
            step("table:messages", "vault", MIGRATION, 37),
        ],
        fix=FixOut(explanation="Turn on row level security.", diff=GOOD_DIFF, prompt="Fix"),
    )


def bad_trace(f: Finding) -> TraceOut:
    t = good_trace(f)
    t.attack_path.append(step(file="src/nope.ts", line=1))
    return t


# --- the brief's tests ---------------------------------------------------------------


def test_drops_step_with_missing_file(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path.append(step(file="src/nope.ts", line=1))
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert len(cleaned.attack_path) == len(t.attack_path) - 1
    assert "src/nope.ts" in errors[0]


def test_drops_step_with_line_past_eof_or_unknown_node(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path += [step(line=99_999), step(node_id="table:ghost")]
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert len(errors) == 2
    assert "99999" in errors[0] and "table:ghost" in errors[1]
    assert len(cleaned.attack_path) == 3


def test_attack_path_must_reach_the_missing_guard(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path = t.attack_path[:1]
    _, errors = validate_trace(t, f_messages, graph, ws)
    assert any("guard" in e for e in errors)


def test_retry_once_with_feedback_then_fallback(f_messages, graph, ws, fake_client):
    fake_client.queue(ModelOutputError("x", "bad"), ModelOutputError("x", "bad"))
    t, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "fallback" and fake_client.calls == 2
    assert t.attack_path and t.fix.prompt
    assert fake_client.last_feedback is not None and "bad" in fake_client.last_feedback


def test_retry_succeeds(f_messages, graph, ws, fake_client):
    fake_client.queue(bad_trace(f_messages), good_trace(f_messages))
    _, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry"
    assert fake_client.last_feedback is not None
    assert "src/nope.ts" in fake_client.last_feedback


def test_fallback_exists_for_every_mistake(vuln_findings, graph, ws):
    assert {f.mistake for f in vuln_findings} >= {1, 2, 3, 4, 5, 6, 7}
    for f in vuln_findings:
        t = fallback_trace(f, graph)
        assert validate_trace(t, f, graph, ws)[1] == [], f.id


# --- validation details ---------------------------------------------------------------


def test_first_try_clean_is_model(f_messages, graph, ws, fake_client):
    fake_client.queue(good_trace(f_messages))
    _, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model" and fake_client.calls == 1
    assert fake_client.last_which == "spark" and fake_client.last_max_tokens == TRACE_MAX_TOKENS


def test_retry_keeps_cleaned_trace_when_only_steps_dropped(f_messages, graph, ws, fake_client):
    fake_client.queue(bad_trace(f_messages), bad_trace(f_messages))
    t, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry"
    assert all(s.file != "src/nope.ts" for s in t.attack_path)


def test_retry_with_fatal_errors_falls_back(f_messages, graph, ws, fake_client):
    no_guard = good_trace(f_messages)
    no_guard.attack_path = no_guard.attack_path[:2]
    fake_client.queue(no_guard, no_guard)
    _, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "fallback" and fake_client.calls == 2
    assert fake_client.last_feedback is not None and "guard" in fake_client.last_feedback


def test_any_client_exception_is_caught(f_messages, graph, ws, fake_client):
    fake_client.queue(RuntimeError("boom"), good_trace(f_messages))
    _, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry"
    fake_client.queue(RuntimeError("boom"), RuntimeError("boom"))
    _, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "fallback"


def test_refless_steps_accepted_and_optional_file_still_checked(f_messages, graph, ws):
    t = good_trace(f_messages)
    _, errors = validate_trace(t, f_messages, graph, ws)
    assert errors == []
    t.attack_path.insert(1, step("auth:supabase", "guard_desk", "src/nope.ts", 1))
    _, errors = validate_trace(t, f_messages, graph, ws)
    assert len(errors) == 1 and "src/nope.ts" in errors[0]


def test_step_with_code_node_needs_file_and_line(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path.insert(1, step("table:messages", "vault", None, None))
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert len(errors) == 1 and "table:messages" in errors[0]
    assert len(cleaned.attack_path) == 3


def test_zone_mismatch_is_corrected_silently(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path[2] = step(zone="street")
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert errors == [] and cleaned.attack_path[2].zone == "vault"


def test_empty_attack_path_is_an_error(f_messages, graph, ws):
    t = good_trace(f_messages)
    t.attack_path = [step(file="src/nope.ts")]
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert cleaned.attack_path == []
    assert any("empty" in e for e in errors)


def test_em_dashes_are_replaced(f_messages, graph, ws, fake_client):
    t = good_trace(f_messages)
    t.attack_path[0] = step("visitor", "street", None, None, text=f"in{EM_DASH}out")
    t.fix.prompt = f"please{EM_DASH}now"
    cleaned, _ = validate_trace(t, f_messages, graph, ws)
    assert cleaned.attack_path[0].story == "in - out"
    assert cleaned.fix.prompt == "please - now"
    fake_client.queue(t)
    out = trace_finding(f_messages, graph, ws, fake_client, findings=[f_messages])
    dumped = out.model_dump_json()
    assert EM_DASH not in dumped and "\\u2014" not in dumped


# --- prompt ---------------------------------------------------------------------------


def test_user_prompt_has_graph_finding_and_numbered_files(f_messages, graph, ws, fake_client):
    fake_client.queue(good_trace(f_messages))
    trace_finding(f_messages, graph, ws, fake_client, findings=[f_messages])
    user = fake_client.last_user
    assert (
        "table:messages | table | messages | vault | supabase/migrations/0001_init.sql:37" in user
    )
    assert "visitor | visitor | Visitor | street | -" in user
    assert "fn:ai-describe -> ext:api.openai.com (calls_external)" in user
    assert "m3-messages" in user
    assert "37| create table public.messages (" in user
    assert "Lovable" in user
    assert FEEDBACK_HEADER not in user


def test_user_prompt_includes_neighbour_files(vuln_findings, graph, ws):
    f = next(f for f in vuln_findings if f.id == "m3-adoption_requests")
    user = build_user_prompt(f, graph, ws, findings=[f])
    assert "=== src/pages/Requests.tsx" in user
    assert "=== supabase/functions/update-request/index.ts" in user


def test_user_prompt_respects_cap(vuln_findings, graph, ws):
    f = next(f for f in vuln_findings if f.id == "m3-adoption_requests")
    user = build_user_prompt(f, graph, ws, findings=[f], cap=1500)
    assert "=== supabase/migrations/0001_init.sql" in user
    assert "=== src/pages/Requests.tsx" not in user


def test_system_prompt_rules():
    s = system_prompt()
    for needle in ["vault", "key under the doormat", "unified diff", "Lovable", "Cursor", "v0"]:
        assert needle in s
    assert EM_DASH not in s


# --- redaction ------------------------------------------------------------------------


def test_redact_env_file_keeps_names_and_lines():
    text = "# comment\nVITE_URL=https://x.supabase.co\nexport SECRET='abc'\nEMPTY=\nraw-line\n"
    out = redact_for_prompt(".env.local", text, [])
    assert out.splitlines() == [
        "# comment",
        "VITE_URL=<redacted>",
        "export SECRET=<redacted>",
        "EMPTY=",
        "<redacted>",
    ]


def test_redact_literals_on_flagged_source_lines():
    text = "a\nconst k = 'sk-live-123' + \"two\"\nconst ok = 'keep'\n"
    f = Finding(
        id="m1-x",
        mistake=1,
        severity="critical",
        status="confirmed",
        title="t",
        node_ids=[],
        refs=[CodeRef(file="src/k.ts", start_line=2, end_line=2)],
        source="gitleaks",
    )
    out = redact_for_prompt("src/k.ts", text, [f])
    assert "sk-live-123" not in out and "two" not in out
    assert "const k = '<redacted>' + \"<redacted>\"" in out
    assert "'keep'" in out
    assert redact_for_prompt("src/other.ts", text, [f]) == text


def test_secrets_never_reach_the_prompt(vuln_findings, graph, ws, fake_client):
    for f in vuln_findings:
        fake_client.queue(good_trace(f))
        trace_finding(f, graph, ws, fake_client, feedback="retry please", findings=vuln_findings)
        for text in (fake_client.last_user, fake_client.last_system):
            assert FAKE_OPENAI_KEY not in text, f.id
            assert ANON_JWT_SIGNATURE not in text, f.id
            assert "sk-h" not in text, f.id
    m1 = next(f for f in vuln_findings if f.mistake == 1)
    user = build_user_prompt(m1, graph, ws, findings=[m1])
    assert "4| VITE_OPENAI_API_KEY=<redacted>" in user


# --- fallback on the clean app --------------------------------------------------------


def _synthetic(mistake: int, node_ids: list[str], ref: CodeRef, **evidence: Any) -> Finding:
    return Finding(
        id=f"m{mistake}-synthetic",
        mistake=mistake,
        severity="low",
        status="possible",
        title="synthetic",
        node_ids=node_ids,
        refs=[ref],
        source="heist",
        evidence=evidence,
    )


def test_fallback_validates_on_clean_app(clean_app_path):
    ws = load_workspace(clean_app_path)
    g = build_app_graph(ws, detect_stack(ws))
    assert all_findings(clean_app_path) == []
    mig = "supabase/migrations/0001_init.sql"
    fn = "supabase/functions/ai-describe/index.ts"
    cases = [
        _synthetic(1, [], CodeRef(file=".env", start_line=1, end_line=1), var="VITE_X_KEY"),
        _synthetic(2, [], CodeRef(file="src/lib/admin.ts", start_line=1, end_line=1)),
        _synthetic(
            3,
            ["table:pets", "policy:pets:pets_select_own"],
            CodeRef(file=mig, start_line=20, end_line=20),
            table="pets",
            reason="open_to_everyone",
        ),
        _synthetic(
            4,
            ["bucket:pet-photos"],
            CodeRef(file="supabase/migrations/0002_storage.sql", start_line=1, end_line=1),
            bucket="pet-photos",
            public=True,
            reason="public_no_policy",
        ),
        _synthetic(5, ["fn:ai-describe"], CodeRef(file=fn, start_line=1, end_line=1)),
        _synthetic(6, ["fn:update-request"], CodeRef(file=fn, start_line=2, end_line=2)),
        _synthetic(
            7,
            ["fn:ai-describe"],
            CodeRef(file=fn, start_line=3, end_line=3),
            function="ai-describe",
            host="api.openai.com",
        ),
        _synthetic(0, [], CodeRef(file="src/pages/Pets.tsx", start_line=3, end_line=3)),
    ]
    for f in cases:
        t = fallback_trace(f, g, ws)
        assert validate_trace(t, f, g, ws)[1] == [], f.id


def test_fallback_texts_are_specific_and_dash_free(vuln_findings, graph, ws):
    for f in vuln_findings:
        t = fallback_trace(f, graph, ws)
        dumped = t.model_dump_json()
        assert EM_DASH not in dumped and "\\u2014" not in dumped
        assert 2 <= len(t.ghost_path) <= 5 and 3 <= len(t.attack_path) <= 7
        assert t.fix.diff.startswith("--- ")
        assert "Lovable" in t.fix.prompt
    by_id = {f.id: fallback_trace(f, graph, ws) for f in vuln_findings}
    messages = by_id["m3-messages"].fix.diff
    assert "alter table public.messages enable row level security;" in messages
    assert "sender_id" in messages
    assert "supabase/migrations/0004_" in messages
    assert "getUser()" in by_id["m5-send-email"].fix.diff
    assert "status: 401" in by_id["m5-send-email"].fix.diff
    assert ".eq('user_id', user.id)" in by_id["m6-update-request-12"].fix.diff
    assert "429" in by_id["m7-ai-describe-api-openai-com"].fix.diff
    assert "storage.objects" in by_id["m4-id-documents"].fix.diff
    m1 = next(t for i, t in by_id.items() if i.startswith("m1-"))
    assert "VITE_OPENAI_API_KEY" in m1.fix.explanation
    assert FAKE_OPENAI_KEY not in m1.model_dump_json()
    m2 = next(t for i, t in by_id.items() if i.startswith("m2-"))
    assert "rotate" in m2.fix.explanation.lower()


def test_redact_backstop_hides_key_like_literals_anywhere():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abcDEF123_-xyz"
    text = (
        f"const a = '{jwt}'\n"
        "const b = 'sk-proj-abcdefghijklmnop1234'\n"
        "const c = 'https://api.openai.com/v1/chat/completions'\n"
        "const d = 'hello world'\n"
    )
    out = redact_for_prompt("src/x.ts", text, [])
    assert jwt not in out and "sk-proj-abcdefghijklmnop1234" not in out
    assert "https://api.openai.com/v1/chat/completions" in out and "hello world" in out


# --- fix round 1 ----------------------------------------------------------------------

PROJ_KEY = "sk-proj-abcdefghijklmnop1234"


def test_apostrophe_in_comment_cannot_hide_a_key():
    text = f"// don't ship this\nconst k = '{PROJ_KEY}';\n"
    out = redact_for_prompt("src/x.ts", text, [])
    assert PROJ_KEY not in out
    assert "// don't ship this" in out


def test_apostrophe_in_jsx_text_cannot_hide_a_key():
    text = f"<p>Don't have an account? {{'{PROJ_KEY}'}}</p>\n"
    out = redact_for_prompt("src/Login.tsx", text, [])
    assert PROJ_KEY not in out and "Don't have an account?" in out


def test_flagged_line_with_unclosed_literal_hides_rest_of_line():
    f = Finding(
        id="m1-x",
        mistake=1,
        severity="critical",
        status="confirmed",
        title="t",
        node_ids=[],
        refs=[CodeRef(file="src/k.ts", start_line=1, end_line=2)],
        source="gitleaks",
    )
    text = "const k = `abc-short-1\nsecondpart12345678xyz`\n"
    out = redact_for_prompt("src/k.ts", text, [f])
    assert "abc-short-1" not in out and "secondpart12345678xyz" not in out


def _other_secret(rel: str, line: int) -> Finding:
    return Finding(
        id="m1-other",
        mistake=1,
        severity="critical",
        status="confirmed",
        title="t",
        node_ids=[],
        refs=[CodeRef(file=rel, start_line=line, end_line=line)],
        source="gitleaks",
    )


def test_neighbour_file_flagged_by_another_finding_is_redacted(
    vuln_findings, graph, ws, fake_client
):
    f = next(f for f in vuln_findings if f.id == "m3-adoption_requests")
    other = _other_secret("src/pages/Requests.tsx", 16)
    plain = build_user_prompt(f, graph, ws, findings=[f])
    assert "16| " in plain and "'approved'" in plain
    hidden = build_user_prompt(f, graph, ws, findings=[f, other])
    assert "'approved'" not in hidden and "16|       body: { id, status: '<redacted>' }," in hidden
    fake_client.queue(good_trace(f))
    trace_with_validation(f, graph, ws, fake_client, findings=vuln_findings + [other])
    assert "'approved'" not in fake_client.last_user


def test_m1_prompt_includes_the_function_that_should_hold_the_key(vuln_findings, graph, ws):
    m1 = next(f for f in vuln_findings if f.mistake == 1)
    user = build_user_prompt(m1, graph, ws, findings=[m1])
    assert "=== supabase/functions/ai-describe/index.ts" in user
    assert "=== supabase/functions/send-email/index.ts" not in user


def test_m2_prompt_includes_edge_functions(vuln_findings, graph, ws):
    m2 = next(f for f in vuln_findings if f.mistake == 2)
    user = build_user_prompt(m2, graph, ws, findings=[m2])
    for name in ("ai-describe", "send-email", "update-request"):
        assert f"=== supabase/functions/{name}/index.ts" in user


INVENTED_DIFF = (
    "--- a/supabase/functions/ai-describe/index.ts\n"
    "+++ b/supabase/functions/ai-describe/index.ts\n"
    "@@ -1,2 +1,3 @@\n"
    ' import { serve } from "https://deno.land/std/http/server.ts";\n'
    "+// check auth\n"
    " serve(async (req) => {\n"
)


def test_invented_diff_is_swapped_for_template_without_retry(f_messages, graph, ws, fake_client):
    t = good_trace(f_messages)
    t.fix.diff = INVENTED_DIFF
    cleaned, errors = validate_trace(t, f_messages, graph, ws)
    assert len(errors) == 1 and "template diff" in errors[0]
    assert cleaned.fix.diff == fallback_trace(f_messages, graph, ws).fix.diff
    assert cleaned.fix.explanation == t.fix.explanation and cleaned.fix.prompt == t.fix.prompt
    fake_client.queue(t)
    out, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model" and fake_client.calls == 1
    assert "enable row level security" in out.fix.diff


def test_correct_diffs_are_kept(f_messages, graph, ws):
    shifted = GOOD_DIFF.replace("@@ -40,2 +40,4 @@", "@@ -42,2 +42,4 @@").replace(
        "   body text", " body text"
    )
    new_file = "--- /dev/null\n+++ b/supabase/migrations/0004_x.sql\n@@ -0,0 +1,1 @@\n+select 1;\n"
    env = "--- a/.env\n+++ b/.env\n@@ -4,1 +3,0 @@\n-VITE_OPENAI_API_KEY=<redacted>\n"
    for diff in (GOOD_DIFF, shifted, new_file, env):
        t = good_trace(f_messages)
        t.fix.diff = diff
        cleaned, errors = validate_trace(t, f_messages, graph, ws)
        assert errors == [], diff
        assert cleaned.fix.diff == diff


def test_diff_problems_are_named():
    ws = load_workspace(Path(__file__).parent / "fixtures" / "vuln_app")
    assert check_diff("just words", ws) == ["fix diff is not a unified diff"]
    unknown = "--- a/src/nope.ts\n+++ b/src/nope.ts\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    assert any("src/nope.ts" in p for p in check_diff(unknown, ws))
    assert any("ai-describe" in p for p in check_diff(INVENTED_DIFF, ws))


def test_usable_first_answer_kept_when_retry_raises(f_messages, graph, ws, fake_client):
    fake_client.queue(bad_trace(f_messages), RuntimeError("boom"))
    t, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry" and fake_client.calls == 2
    assert all(s.file != "src/nope.ts" for s in t.attack_path)
    no_guard = good_trace(f_messages)
    no_guard.attack_path = no_guard.attack_path[:2]
    fake_client.queue(bad_trace(f_messages), no_guard)
    t, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry" and len(t.attack_path) == 3


# --- fix round 2 ----------------------------------------------------------------------

TIGHTEN = "supabase/migrations/0003_tighten.sql"
VULN_APP = Path(__file__).parent / "fixtures" / "vuln_app"


def _whole_file_deletion(keep_last: bool = False) -> str:
    real = (VULN_APP / TIGHTEN).read_text().splitlines()
    gone = real[:-1] if keep_last else real
    body = "".join(f"-{x}\n" for x in gone)
    return f"--- a/{TIGHTEN}\n+++ /dev/null\n@@ -1,{len(gone)} +0,0 @@\n{body}"


# (name, diff, accepted). git apply --check must agree with check_diff on every one.
GIT_CASES = [
    ("exact", GOOD_DIFF, True),
    ("offset by 10 lines", GOOD_DIFF.replace("@@ -40,2 +40,4 @@", "@@ -30,2 +30,4 @@"), True),
    # git pins a hunk with context at line 1 to the start of the file.
    (
        "says line 1 but sits at the end",
        GOOD_DIFF.replace("@@ -40,2 +40,4 @@", "@@ -1,2 +1,4 @@"),
        False,
    ),
    # git pins a hunk with no context after its last change to the end of the file.
    (
        "no trailing context mid-file",
        (
            f"--- a/{MIGRATION}\n+++ b/{MIGRATION}\n@@ -6,1 +6,2 @@\n"
            " alter table public.profiles enable row level security;\n+-- x\n"
        ),
        False,
    ),
    (
        "trailing context mid-file, offset by 5",
        (
            f"--- a/{MIGRATION}\n+++ b/{MIGRATION}\n@@ -11,2 +11,3 @@\n"
            " alter table public.profiles enable row level security;\n+-- x\n \n"
        ),
        True,
    ),
    ("old count too big", GOOD_DIFF.replace("@@ -40,2 +40,4 @@", "@@ -40,3 +40,4 @@"), False),
    ("new count too big", GOOD_DIFF.replace("@@ -40,2 +40,4 @@", "@@ -40,2 +40,5 @@"), False),
    ("no hunks", f"--- a/{MIGRATION}\n+++ b/{MIGRATION}\n", False),
    (
        "creates an existing file",
        f"--- /dev/null\n+++ b/{MIGRATION}\n@@ -0,0 +1,1 @@\n+select 1;\n",
        False,
    ),
    (
        "dot dot path",
        "--- a/../outside.sql\n+++ b/../outside.sql\n@@ -1,1 +1,1 @@\n-a\n+b\n",
        False,
    ),
    (
        "absolute path",
        "--- /etc/hosts\n+++ /etc/hosts\n@@ -1,1 +1,1 @@\n-a\n+b\n",
        False,
    ),
    ("inner whitespace differs", GOOD_DIFF.replace("   body text", "   body   text"), False),
    (
        "new file",
        "--- /dev/null\n+++ b/supabase/migrations/0004_x.sql\n@@ -0,0 +1,1 @@\n+select 1;\n",
        True,
    ),
    ("deletes a whole file", _whole_file_deletion(), True),
    ("deletes part of a file", _whole_file_deletion(keep_last=True), False),
]

# Cases where check_diff is deliberately stricter or looser than git, so not git-checked.
STRICT_CASES = [
    # git reads the hunk by its counts and silently drops the extra added line.
    ("new count too small", GOOD_DIFF.replace("@@ -40,2 +40,4 @@", "@@ -40,2 +40,3 @@"), False),
    # Blank context alone could sit anywhere, so the hunk is not anchored (git accepts it).
    (
        "only blank context",
        f"--- a/{MIGRATION}\n+++ b/{MIGRATION}\n@@ -5,1 +5,2 @@\n+-- x\n \n",
        False,
    ),
    (
        "adds a placeholder",
        GOOD_DIFF.replace("+alter table", "+-- key <redacted>\n+alter table").replace(
            "+40,4", "+40,5"
        ),
        False,
    ),
    # Leading indent is ignored, and placeholders in removed lines stand for the hidden text.
    ("leading indent differs", GOOD_DIFF.replace("   body text", " body text"), True),
    (
        "env placeholder",
        "--- a/.env\n+++ b/.env\n@@ -4,1 +3,0 @@\n-VITE_OPENAI_API_KEY=<redacted>\n",
        True,
    ),
    ("only a placeholder", "--- a/.env\n+++ b/.env\n@@ -4,1 +3,0 @@\n-<redacted>\n", False),
]


def _git_accepts(diff: str, work: Path) -> bool:
    r = subprocess.run(
        ["git", "apply", "--check", "-"],
        input=diff,
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    return r.returncode == 0


@pytest.mark.parametrize(("name", "diff", "accepted"), GIT_CASES + STRICT_CASES)
def test_check_diff_cases(name, diff, accepted, ws):
    assert (check_diff(diff, ws) == []) is accepted, (name, check_diff(diff, ws))


def test_check_diff_agrees_with_git_apply(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work)
    subprocess.run(["git", "init", "-q"], cwd=work, check=True)
    ws = load_workspace(work)
    for name, diff, accepted in GIT_CASES:
        assert _git_accepts(diff, work) is accepted, f"git disagrees with the case: {name}"
        assert (check_diff(diff, ws) == []) is accepted, (name, check_diff(diff, ws))


def test_hunk_match_nearest_the_header_wins():
    real = ["a", "x", "b", "x", "c", "x"]
    assert _hunk_at(["x"], 4, real) == 3
    assert _hunk_at(["x"], 1, real) == 1
    assert _hunk_at(["x"], 99, real) == 5
    assert _hunk_at(["nope"], 1, real) is None


def test_retry_keeps_the_answer_with_fewer_problems(f_messages, graph, ws, fake_client):
    worse = bad_trace(f_messages)
    worse.attack_path.append(step(file="src/also-nope.ts", line=1))
    fake_client.queue(bad_trace(f_messages), worse)
    t, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry" and fake_client.calls == 2
    assert fake_client.last_feedback is not None and "src/nope.ts" in fake_client.last_feedback
    assert len(t.attack_path) == 3
    better = bad_trace(f_messages)
    better.attack_path = better.attack_path[:3] + [step(node_id="table:ghost")]
    fake_client.queue(worse, better)
    t, how = trace_with_validation(f_messages, graph, ws, fake_client, findings=[f_messages])
    assert how == "model_retry" and all(s.node_id != "table:ghost" for s in t.attack_path)

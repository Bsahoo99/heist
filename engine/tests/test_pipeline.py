import json
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypeVar

import pytest
from pydantic import BaseModel

from heist import cli, pipeline
from heist.cli import FIXTURE_TIME, main
from heist.detect.run import run_detectors
from heist.fetch import UnsupportedRepo, Workspace, detect_stack, load_workspace
from heist.graph.build import build_app_graph
from heist.llm.client import MetaClient, SpendTracker
from heist.llm.templates import fallback_trace
from heist.llm.triage import TriageOut
from heist.models import AppGraph, DbSchema, Finding, FixOut, StepOut, TraceOut
from heist.pipeline import run_analysis
from heist.scene import ProofRow, Scene, SceneMeta, build_scene

T = TypeVar("T", bound=BaseModel)

REPO_ROOT = Path(__file__).parents[2]
SCHEMA_PATH = REPO_ROOT / "shared/scene.schema.json"
WEB_FIXTURES = REPO_ROOT / "web/tests/fixtures"
FIXED_TIME = datetime(2026, 10, 26, tzinfo=UTC)


class FakeClient(MetaClient):
    """Triage keeps everything; tracing answers with the deterministic template trace."""

    def __init__(self) -> None:
        super().__init__("fake-spark", "fake-open", SpendTracker(), max_retries=0)
        self.calls: list[str] = []
        self.ws: Workspace | None = None
        self.g: AppGraph | None = None
        self._lock = threading.Lock()

    def models(self) -> dict[str, str]:
        return {"spark": "fake-spark", "open": "fake-open"}

    def chat_json(
        self,
        which: Literal["spark", "open"],
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int = 4000,
    ) -> T:
        with self._lock:
            self.calls.append(which)
        if which == "open":
            assert schema is TriageOut
            return schema.model_validate({"groups": [], "noise": []})
        assert schema is TraceOut and self.ws is not None and self.g is not None
        finding_json = user.split("## Finding\n", 1)[1].split("\n\n## Nodes", 1)[0]
        fid = json.loads(finding_json)["id"]
        f = next(x for x in run_detectors(self.ws, self.g) if x.id == fid)
        return schema.model_validate(fallback_trace(f, self.g, self.ws).model_dump())


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    client = FakeClient()
    real = pipeline.build_app_graph

    def recording(ws, stack):
        g = real(ws, stack)
        client.ws, client.g = ws, g
        return g

    monkeypatch.setattr(pipeline, "build_app_graph", recording)
    return client


def test_pipeline_vuln_app(vuln_app_path, fake_client):
    events = []
    s = run_analysis(str(vuln_app_path), events.append, fake_client)
    assert s.findings[0].severity == "critical"
    active = {z.id for z in s.zones if z.active}
    assert {"vault", "side_doors", "warehouse", "shop_window", "across_road"} <= active
    assert [e.kind for e in events][-1] == "done"
    assert any(e.kind == "node_found" and e.data["zone"] == "vault" for e in events)
    assert s.meta.models == {"spark": "fake-spark", "open": "fake-open"}
    assert fake_client.calls.count("open") == 1
    assert fake_client.calls.count("spark") >= len(s.findings)
    assert all(f.trace_source in ("model", "model_retry") for f in s.findings)


def test_pipeline_clean_app(clean_app_path, fake_client):
    s = run_analysis(str(clean_app_path), lambda e: None, fake_client)
    assert s.findings == []
    assert s.meta.checks_held == 7
    assert all(not i.flagged for z in s.zones for i in z.items)


def test_pipeline_without_rules(tmp_copy, vuln_app_path, fake_client):
    root = tmp_copy(vuln_app_path)
    shutil.rmtree(root / "supabase/migrations")
    s = run_analysis(str(root), lambda e: None, fake_client)
    assert s.meta.has_db_rules is False
    assert s.meta.unparsed_migrations == []


def test_unsupported_repo_emits_error(tmp_path, fake_client):
    (tmp_path / "main.py").write_text("x")
    events = []
    with pytest.raises(UnsupportedRepo):
        run_analysis(str(tmp_path), events.append, fake_client)
    assert events[-1].kind == "error" and "not supported yet" in events[-1].message


def test_missing_source_is_unsupported(tmp_path):
    events = []
    with pytest.raises(UnsupportedRepo):
        run_analysis(str(tmp_path / "nope"), events.append, None)
    assert events[-1].kind == "error"


def test_unexpected_error_emits_generic_message(vuln_app_path, monkeypatch):
    def boom(ws, g):
        raise RuntimeError("secret detail /etc/passwd")

    monkeypatch.setattr(pipeline, "run_detectors", boom)
    events = []
    with pytest.raises(RuntimeError):
        run_analysis(str(vuln_app_path), events.append, None)
    assert events[-1].kind == "error"
    assert "secret detail" not in events[-1].message and "passwd" not in events[-1].message


def test_schema_is_current():
    assert json.loads(SCHEMA_PATH.read_text()) == Scene.model_json_schema()


def test_stage_events_in_order(vuln_app_path):
    events = []
    s = run_analysis(str(vuln_app_path), events.append, None)
    stages = [e.message for e in events if e.kind == "stage"]
    assert stages == [
        "Fetching the repo",
        "Mapping the app",
        "Checking the locks",
        "Sorting the findings",
        "Planning the heist",
        "Proving it",
        "Done",
    ]
    found = [e for e in events if e.kind == "node_found"]
    assert found and all(set(e.data) == {"zone", "label", "node_id", "kind"} for e in found)
    finds = [e for e in events if e.kind == "finding"]
    assert len(finds) == len(s.findings)
    assert all(set(e.data) == {"id", "mistake", "severity", "status", "title"} for e in finds)
    kinds = [(e.kind, e.message) for e in events]
    sorting = kinds.index(("stage", "Sorting the findings"))
    planning = kinds.index(("stage", "Planning the heist"))
    assert all(sorting < events.index(e) < planning for e in finds)
    assert events[-1].kind == "done"
    assert events[-1].data == {"findings": len(s.findings), "checks_held": s.meta.checks_held}


def test_offline_makes_zero_client_calls(vuln_app_path, monkeypatch):
    def no_calls(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("offline mode must not call the model")

    monkeypatch.setattr(MetaClient, "chat_json", no_calls)
    monkeypatch.setattr(MetaClient, "from_env", no_calls)
    s = run_analysis(str(vuln_app_path), lambda e: None, None)
    assert s.findings
    assert all(f.trace_source == "fallback" for f in s.findings)
    assert s.meta.models == {}


def test_offline_is_deterministic(vuln_app_path):
    a = run_analysis(str(vuln_app_path), lambda e: None, None)
    b = run_analysis(str(vuln_app_path), lambda e: None, None, analyzed_at=FIXED_TIME)
    assert b.meta.analyzed_at == FIXED_TIME
    da, db = a.model_dump(mode="json"), b.model_dump(mode="json")
    da["meta"].pop("analyzed_at")
    db["meta"].pop("analyzed_at")
    assert json.dumps(da) == json.dumps(db)


def test_scene_shape(vuln_app_path):
    s = run_analysis(str(vuln_app_path), lambda e: None, None)
    assert [z.id for z in s.zones] == [
        "street",
        "shop_window",
        "guard_desk",
        "side_doors",
        "vault",
        "warehouse",
        "across_road",
    ]
    kinds = {i.kind for z in s.zones for i in z.items}
    assert "policy" not in kinds and "client_call" not in kinds
    vault = next(z for z in s.zones if z.id == "vault")
    labels = {i.label: i.flagged for i in vault.items}
    assert labels["messages"] is True and labels["notes"] is False
    for z in s.zones:
        assert z.active == bool(z.items)
        assert [i.node_id for i in z.items] == sorted(i.node_id for i in z.items)
    ranks = [
        (
            {"proved": 0, "confirmed": 1, "possible": 2}[f.status],
            {"critical": 0, "high": 1, "medium": 2, "low": 3}[f.severity],
            f.mistake,
            f.id,
        )
        for f in s.findings
    ]
    assert ranks == sorted(ranks)
    held = 7 - len({f.mistake for f in s.findings if f.status != "possible" and f.mistake >= 1})
    assert s.meta.checks_held == held
    assert s.meta.repo == "vuln_app" and s.meta.commit_sha == "local"
    assert s.meta.has_db_rules is True
    for f in s.findings:
        assert f.guard_ref.file
        for step in [*f.ghost_path, *f.attack_path]:
            if step.node_id in ("visitor", "auth:supabase"):
                assert step.ref is None
            elif step.ref is not None:
                assert step.ref.start_line <= step.ref.end_line


def test_step_ref_prefers_node_range(vuln_app_path):
    s = run_analysis(str(vuln_app_path), lambda e: None, None)
    f = next(f for f in s.findings if f.id == "m3-messages")
    table_steps = [st for st in f.attack_path if st.node_id == "table:messages"]
    assert table_steps
    for st in table_steps:
        assert st.ref is not None and st.ref.symbol == "messages"
        assert st.ref.file == "supabase/migrations/0001_init.sql"


def test_prove_errors_leave_findings_confirmed(vuln_app_path):
    seen: list[list[str]] = []

    def prove(db: DbSchema, ws: Workspace, ids: list[str]) -> dict[str, list[ProofRow]]:
        seen.append(ids)
        raise RuntimeError("sandbox down")

    s = run_analysis(str(vuln_app_path), lambda e: None, None, prove)
    assert seen and all(i.startswith("m3-") for i in seen[0])
    assert not any(f.status == "proved" for f in s.findings)
    assert next(f for f in s.findings if f.id == "m3-messages").status == "confirmed"


def test_prove_rows_make_finding_proved_and_first(vuln_app_path):
    row = ProofRow(as_who="anonymous", table="messages", row={"body": "Test Alice says hi"})

    def prove(db: DbSchema, ws: Workspace, ids: list[str]) -> dict[str, list[ProofRow]]:
        return {"m3-messages": [row]}

    s = run_analysis(str(vuln_app_path), lambda e: None, None, prove)
    assert s.findings[0].id == "m3-messages"
    assert s.findings[0].status == "proved"
    assert s.findings[0].proof_rows == [row]


def test_prove_skipped_without_rules(tmp_copy, vuln_app_path):
    root = tmp_copy(vuln_app_path)
    shutil.rmtree(root / "supabase/migrations")
    calls = []

    def prove(db: DbSchema, ws: Workspace, ids: list[str]) -> dict[str, list[ProofRow]]:
        calls.append(ids)
        return {}

    events = []
    run_analysis(str(root), events.append, None, prove)
    assert calls == []
    assert "Proving it" in [e.message for e in events if e.kind == "stage"]


def test_skips_findings_without_refs(vuln_app_path, monkeypatch):
    real = pipeline.run_detectors

    def without_refs(ws, g) -> list[Finding]:
        out = real(ws, g)
        return [out[0].model_copy(update={"refs": []}), *out[1:]]

    monkeypatch.setattr(pipeline, "run_detectors", without_refs)
    s = run_analysis(str(vuln_app_path), lambda e: None, None)
    ids = {f.id for f in s.findings}
    assert "m1-vite-openai-api-key" not in ids and "m3-messages" in ids


def test_cli_offline_end_to_end(vuln_app_path, tmp_path, monkeypatch, capsys):
    def no_env(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("--offline must not build a Meta client")

    monkeypatch.setattr(MetaClient, "from_env", no_env)
    out = tmp_path / "scene.json"
    code = main(
        [
            "analyze",
            str(vuln_app_path),
            "--offline",
            "--out",
            str(out),
            "--analyzed-at",
            FIXTURE_TIME,
        ]
    )
    assert code == 0
    text = out.read_text()
    assert text.endswith("}\n")
    s = Scene.model_validate_json(text)
    assert s.findings and all(f.trace_source == "fallback" for f in s.findings)
    assert s.meta.analyzed_at == FIXED_TIME
    err = capsys.readouterr().err
    assert "Fetching the repo" in err


def test_cli_unsupported_exits_2(tmp_path, capsys):
    (tmp_path / "main.py").write_text("x")
    assert main(["analyze", str(tmp_path), "--offline"]) == 2
    assert "not supported yet" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["vuln", "clean"])
def test_web_fixtures_are_current(name, tmp_path):
    out = tmp_path / "scene.json"
    app = Path(__file__).parent / "fixtures" / f"{name}_app"
    code = main(
        ["analyze", str(app), "--offline", "--out", str(out), "--analyzed-at", FIXTURE_TIME]
    )
    assert code == 0
    assert out.read_text() == (WEB_FIXTURES / f"{name}-scene.json").read_text()


def _assert_steps_on_map(s: Scene) -> None:
    items = {z.id: {i.node_id for i in z.items} for z in s.zones}
    for f in s.findings:
        for st in [*f.ghost_path, *f.attack_path]:
            assert st.item_id in items[st.zone], (f.id, st.node_id, st.item_id)


@pytest.mark.parametrize("name", ["vuln", "clean"])
def test_web_fixture_steps_point_at_map_items(name):
    _assert_steps_on_map(
        Scene.model_validate_json((WEB_FIXTURES / f"{name}-scene.json").read_text())
    )


def test_offline_steps_point_at_map_items(vuln_app_path):
    s = run_analysis(str(vuln_app_path), lambda e: None, None)
    _assert_steps_on_map(s)
    steps = [st for f in s.findings for st in [*f.ghost_path, *f.attack_path]]
    policy = [st for st in steps if st.node_id == "policy:adoption_requests:requests_select_authed"]
    assert policy and all(st.item_id == "table:adoption_requests" for st in policy)
    calls = [st for st in steps if st.node_id == "client:src/pages/Requests.tsx:9"]
    assert calls and all(st.item_id == "page:src/pages/Requests.tsx" for st in calls)
    plain = [st for st in steps if st.node_id == "table:messages"]
    assert plain and all(st.item_id == "table:messages" for st in plain)


def test_online_steps_point_at_map_items(vuln_app_path, fake_client):
    _assert_steps_on_map(run_analysis(str(vuln_app_path), lambda e: None, fake_client))


def test_policy_finding_flags_its_table(vuln_app_path, monkeypatch):
    real = pipeline.run_detectors

    def only_policy(ws, g) -> list[Finding]:
        f = next(x for x in real(ws, g) if x.id == "m3-adoption_requests")
        return [
            f.model_copy(update={"node_ids": ["policy:adoption_requests:requests_select_authed"]})
        ]

    monkeypatch.setattr(pipeline, "run_detectors", only_policy)
    s = run_analysis(str(vuln_app_path), lambda e: None, None)
    flagged = {i.node_id for z in s.zones for i in z.items if i.flagged}
    assert flagged == {"table:adoption_requests"}


def test_prove_gets_only_confirmed_and_never_upgrades_possible(vuln_app_path):
    seen: list[list[str]] = []
    row = ProofRow(as_who="anonymous", table="pets", row={"name": "Test Alice's cat"})

    def prove(db: DbSchema, ws: Workspace, ids: list[str]) -> dict[str, list[ProofRow]]:
        seen.append(ids)
        return {"m3-pets": [row], "m3-messages": [row]}

    s = run_analysis(str(vuln_app_path), lambda e: None, None, prove)
    assert seen == [["m3-adoption_requests", "m3-messages"]]
    pets = next(f for f in s.findings if f.id == "m3-pets")
    assert pets.status == "possible" and pets.proof_rows == []
    assert next(f for f in s.findings if f.id == "m3-messages").status == "proved"


def test_one_trace_crash_falls_back_for_that_finding(vuln_app_path, fake_client, monkeypatch):
    real = pipeline.trace_with_validation

    def flaky(f, g, ws, client, *, findings):
        if f.id == "m3-messages":
            raise ValueError("boom")
        return real(f, g, ws, client, findings=findings)

    monkeypatch.setattr(pipeline, "trace_with_validation", flaky)
    s = run_analysis(str(vuln_app_path), lambda e: None, fake_client)
    offline = run_analysis(str(vuln_app_path), lambda e: None, None)
    assert {f.id for f in s.findings} == {f.id for f in offline.findings}
    sources = {f.id: f.trace_source for f in s.findings}
    assert sources["m3-messages"] == "fallback"
    assert all(v != "fallback" for k, v in sources.items() if k != "m3-messages")


def test_cli_online_without_open_key_exits_1(vuln_app_path, tmp_path, monkeypatch, capsys):
    def no_client(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must stop before building a client")

    monkeypatch.setattr(cli, "ENV_PATH", tmp_path / "missing.env")
    monkeypatch.delenv("OPEN_API_KEY", raising=False)
    monkeypatch.setattr(MetaClient, "from_env", no_client)
    assert main(["analyze", str(vuln_app_path), "--out", str(tmp_path / "s.json")]) == 1
    assert "Set OPEN_API_KEY in engine/.env or use --offline" in capsys.readouterr().err
    assert not (tmp_path / "s.json").exists()


def test_storage_policy_maps_to_its_bucket(clean_app_path, tmp_copy):
    root = tmp_copy(clean_app_path)
    (root / "supabase/migrations/0004_odd.sql").write_text(
        'create policy "odd_read" on storage.objects for select using (true);\n'
    )
    ws = load_workspace(root)
    g = build_app_graph(ws, detect_stack(ws))
    findings, traces = [], {}
    for pid in ("policy:objects:pet_photos_read", "policy:objects:odd_read"):
        node = g.node(pid)
        assert node.zone == "warehouse" and node.ref is not None
        f = Finding(
            id=f"m4-{node.name}",
            mistake=4,
            severity="low",
            status="possible",
            title=node.name,
            node_ids=[pid],
            refs=[node.ref],
            source="heist",
        )
        st = StepOut(
            node_id=pid,
            zone="warehouse",
            file=node.ref.file,
            line=node.ref.start_line,
            data="files",
            story="s",
            why="w",
            code="c",
        )
        fix = FixOut(explanation="e", diff="", prompt="p")
        findings.append(f)
        traces[f.id] = (TraceOut(ghost_path=[st], attack_path=[st], fix=fix), "fallback")
    meta = SceneMeta(
        repo="r",
        commit_sha="local",
        analyzed_at=FIXED_TIME,
        stack="vite_supabase",
        models={},
        has_db_rules=True,
        unparsed_migrations=[],
        checks_held=0,
    )
    s = build_scene(g, findings, traces, {}, meta)
    item = {f.id: f.attack_path[0].item_id for f in s.findings}
    assert item == {"m4-pet_photos_read": "bucket:pet-photos", "m4-odd_read": "bucket:id-documents"}
    _assert_steps_on_map(s)
    flagged = {i.node_id for z in s.zones for i in z.items if i.flagged}
    assert flagged == {"bucket:pet-photos", "bucket:id-documents"}

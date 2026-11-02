"""Pure-function tests for scripts/scan_templates.py. No network, no clones."""

import dataclasses
import json

from scan_templates import (
    METHOD,
    MISTAKE_NAMES,
    OUTCOME_COPY,
    FindingRecord,
    RepoRecord,
    aggregate,
    exception_type,
    finding_record,
    outcome_of,
    record_from_json,
    render_markdown,
)

from heist.fetch import BAD_URL_COPY, CLONE_FAILED_COPY, TOO_BIG_COPY, UNSUPPORTED_STACK_COPY
from heist.models import EM_DASH, CodeRef, Finding

OWNER = "zz-secret-owner"
NAME = "zz-secret-app"
URL = f"https://github.com/{OWNER}/{NAME}"
PATH = "src/zz_secret_path/client.ts"
SECRET = "sk_live_zzSECRETVALUE"


def fr(mistake: int, severity: str = "critical", status: str = "confirmed") -> FindingRecord:
    return FindingRecord(mistake=mistake, severity=severity, status=status, file=PATH)


def repo(i: int, findings: list[FindingRecord], **kw: object) -> RepoRecord:
    base: dict[str, object] = {
        "url": f"{URL}-{i}",
        "sha": "a" * 40,
        "stack": "vite_supabase",
        "status": "scanned",
        "has_db_rules": True,
        "findings": findings,
    }
    return RepoRecord(**{**base, **kw})  # type: ignore[arg-type]


def sample() -> list[RepoRecord]:
    return [
        repo(1, [fr(1), fr(3), fr(5, "high")]),
        repo(2, [fr(3, "low", "possible"), fr(6, "medium", "possible")], has_db_rules=False),
        repo(3, [], unparsed_migrations=2),
        repo(4, [fr(2), fr(3, "low", "possible")]),
        RepoRecord(url=f"{URL}-5", sha=None, stack=None, status="unsupported_stack"),
        RepoRecord(url=f"{URL}-6", sha=None, stack=None, status="clone_failed"),
        RepoRecord(url=f"{URL}-7", sha=None, stack=None, status="timeout"),
    ]


def test_outcomes_counted_and_left_out_of_denominator():
    s = aggregate(sample())
    assert s.total == 7
    assert s.scanned == 4
    assert s.outcomes["scanned"] == 4
    assert s.outcomes["unsupported_stack"] == 1
    assert s.outcomes["clone_failed"] == 1
    assert s.outcomes["timeout"] == 1
    assert s.outcomes["too_big"] == 0


def test_headline_counts():
    s = aggregate(sample())
    assert s.confirmed_critical == 2  # repos 1 and 4
    assert s.any_confirmed == 2
    assert s.possible_only == 1  # repo 2
    assert s.no_db_rules == 1
    assert s.unread_migrations == 1


def test_possible_critical_is_not_confirmed_critical():
    s = aggregate([repo(1, [fr(3, "critical", "possible")])])
    assert s.confirmed_critical == 0
    assert s.possible_only == 1


def test_proved_counts_as_confirmed():
    s = aggregate([repo(1, [fr(3, "critical", "proved")])])
    assert s.confirmed_critical == 1


def test_per_mistake_repo_counts():
    by = {m.mistake: m for m in aggregate(sample()).mistakes}
    assert sorted(by) == [1, 2, 3, 4, 5, 6, 7]
    assert (by[3].confirmed, by[3].possible_only) == (1, 2)
    assert (by[6].confirmed, by[6].possible_only) == (0, 1)
    assert (by[4].confirmed, by[4].possible_only) == (0, 0)


def test_findings_per_repo_median_and_range():
    s = aggregate(sample())
    assert (s.findings_median, s.findings_min, s.findings_max) == (2, 0, 3)
    assert (s.confirmed_median, s.confirmed_min, s.confirmed_max) == (0.5, 0, 3)  # 3, 0, 0, 1


def test_no_scanned_repos_does_not_crash():
    s = aggregate([RepoRecord(url=URL, sha=None, stack=None, status="error")])
    md = render_markdown(s, METHOD, "2026-11-02")
    assert "0 of 0" in md


def test_markdown_has_no_repo_name_url_or_path():
    md = render_markdown(aggregate(sample()), METHOD, "2026-11-02")
    for needle in (OWNER, NAME, URL, "github.com/", PATH, "zz_secret_path"):
        assert needle not in md
    assert EM_DASH not in md
    assert "at least one confirmed critical finding: 2 of 4 (50%)" in md
    assert "Possible, not confirmed" in md


def test_fixed_copy_has_no_em_dash_repo_link_or_numbers_that_can_go_stale():
    assert EM_DASH not in METHOD and "github.com/" not in METHOD
    assert "semgrep community rules were off" in METHOD
    assert "manual spot check" in METHOD
    assert "%" not in METHOD


def test_every_outcome_row_is_rendered_even_at_zero():
    md = render_markdown(aggregate(sample()), METHOD, "2026-11-02")
    for label in OUTCOME_COPY.values():
        assert f"| {label} | " in md
    assert "| Over Heist's size caps | 0 |" in md
    assert "| Not a valid GitHub repo URL | 0 |" in md


def test_bad_url_has_its_own_outcome():
    assert outcome_of(BAD_URL_COPY) == "bad_url"
    assert outcome_of(CLONE_FAILED_COPY) == "clone_failed"
    assert outcome_of(UNSUPPORTED_STACK_COPY) == "unsupported_stack"
    assert outcome_of(TOO_BIG_COPY.format(why="over 2,000 files")) == "too_big"
    assert outcome_of("something else") == "error"
    s = aggregate([RepoRecord(url=URL, sha=None, stack=None, status="bad_url")])
    assert s.outcomes["bad_url"] == 1 and s.scanned == 0


def test_exception_type_keeps_the_class_not_the_message():
    err = (
        f"Traceback (most recent call last):\n  File x\nValueError: bad value {SECRET} in {PATH}\n"
    )
    assert exception_type(err) == "ValueError"
    assert (
        exception_type("pydantic_core.ValidationError: 1 error") == "pydantic_core.ValidationError"
    )
    assert exception_type(f"fatal: {SECRET}") == "unknown"
    assert exception_type("") == "unknown"


def test_m3_name_covers_signed_in_users():
    assert MISTAKE_NAMES[3] == "Tables anyone (or any signed-in user) can read"


def test_finding_record_has_no_evidence_fields():
    names = {f.name for f in dataclasses.fields(FindingRecord)}
    assert names == {"mistake", "severity", "status", "file"}
    banned = {"evidence", "value", "values", "secret", "match", "matched", "line", "code", "title"}
    assert not names & banned
    repo_names = {f.name for f in dataclasses.fields(RepoRecord)}
    assert not repo_names & banned


def test_finding_record_drops_evidence_and_secret_values():
    f = Finding(
        id="m1-x",
        mistake=1,
        severity="critical",
        status="confirmed",
        title=f"A secret key {SECRET} is hardcoded",
        node_ids=[],
        refs=[CodeRef(file=PATH, start_line=3, end_line=3)],
        source="heist",
        evidence={"value": SECRET, "line": f"const k = '{SECRET}'"},
    )
    rec = finding_record(f)
    assert rec == FindingRecord(mistake=1, severity="critical", status="confirmed", file=PATH)
    assert SECRET not in json.dumps(dataclasses.asdict(rec))


def test_record_round_trips_through_json():
    r = sample()[0]
    assert record_from_json(json.loads(json.dumps(dataclasses.asdict(r)))) == r

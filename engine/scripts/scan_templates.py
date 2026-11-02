"""Scan Lovable and Bolt repos with Heist's detectors and write aggregate stats.

Reads one GitHub URL per line from data/templates.txt (gitignored).
Each repo goes through Heist's own fetch path (same caps, clone and stack detection as a real
analysis) and then the detectors only: no model calls, no proofs, no request to any deployed app.
Per-repo records go to data/template-results.jsonl (gitignored).
docs/template-stats.md gets aggregates only: no repo name, owner, URL, file path or code.

Run with `cd engine && uv run python scripts/scan_templates.py`.
"""

import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Literal

from heist.detect.run import run_detectors
from heist.fetch import (
    BAD_URL_COPY,
    CLONE_FAILED_COPY,
    TOO_BIG_COPY,
    UNSUPPORTED_STACK_COPY,
    UnsupportedRepo,
    clone_repo,
    detect_stack,
)
from heist.graph.build import build_app_graph
from heist.models import Finding

ENGINE = Path(__file__).resolve().parent.parent
REPO = ENGINE.parent
TEMPLATES = REPO / "data" / "templates.txt"
RESULTS = REPO / "data" / "template-results.jsonl"
STATS = REPO / "docs" / "template-stats.md"
LOG = REPO / "data" / "template-scan.log"

REPO_TIMEOUT_S = 300
_EXC_RE = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt))\b")
WORKERS = 4

Outcome = Literal[
    "scanned", "unsupported_stack", "too_big", "bad_url", "clone_failed", "timeout", "error"
]

OUTCOME_COPY: dict[str, str] = {
    "scanned": "Scanned",
    "unsupported_stack": "Not a supported stack (Vite or Next.js with Supabase)",
    "too_big": "Over Heist's size caps",
    "bad_url": "Not a valid GitHub repo URL",
    "clone_failed": "Could not be cloned",
    "timeout": f"Took longer than the {REPO_TIMEOUT_S} second limit",
    "error": "Crashed in Heist",
}

MISTAKE_NAMES: dict[int, str] = {
    1: "Secret keys in browser code or committed public files",
    2: "Supabase admin (service role) key in browser code or a committed public file",
    3: "Tables anyone (or any signed-in user) can read or change",
    4: "Public or unprotected storage buckets",
    5: "Server functions or routes with no sign-in check",
    6: "Records changed by an ID from the request without an owner check",
    7: "Paid AI or API calls anyone can trigger",
}

METHOD = """\
Repos were collected on 2026-11-02 with the GitHub code search API through the `gh` CLI, using read-only calls.
Lovable query: `lovable-tagger "@supabase/supabase-js" filename:package.json`, taking unique repos in the order GitHub returned them.
Bolt query: `path:.bolt supabase`, taking unique repos in the order GitHub returned them.
Each candidate was kept only if it was public, not a fork and not archived, and its root `package.json` listed `@supabase/supabase-js` with `vite` or `next`.
The first 35 Lovable repos and the first 15 Bolt repos that passed were scanned, 50 in all.
Each repo was shallow-cloned at its default branch through Heist's normal fetch path, with the same file and size caps as a real analysis.
Only Heist's detectors ran: no model calls, no proofs, and no request to any deployed app.
The optional semgrep community rules were off, so there is no row for other community findings.
Repos that failed to clone, hit the caps, or were not a supported stack are counted below and left out of every percentage.
This is a convenience sample from search ranking, not a random sample of all Lovable or Bolt apps.
The numbers are Heist's detector output as is; a manual spot check of an earlier run was used to fix false positives in the detectors, and it adds nothing to these numbers."""


@dataclass(frozen=True)
class FindingRecord:
    """One finding, stripped to what the stats need. Never evidence, matched lines or values."""

    mistake: int
    severity: str
    status: str
    file: str


@dataclass
class RepoRecord:
    url: str
    sha: str | None
    stack: str | None
    status: Outcome
    has_db_rules: bool = False
    unparsed_migrations: int = 0
    findings: list[FindingRecord] = field(default_factory=list[FindingRecord])


def finding_record(f: Finding) -> FindingRecord:
    return FindingRecord(
        mistake=f.mistake, severity=f.severity, status=f.status, file=f.refs[0].file
    )


def is_confirmed(f: FindingRecord) -> bool:
    return f.status in ("confirmed", "proved")


def is_confirmed_critical(f: FindingRecord) -> bool:
    return f.severity == "critical" and is_confirmed(f)


# --- aggregation ----------------------------------------------------------------------------


@dataclass
class MistakeStat:
    mistake: int
    confirmed: int  # repos with at least one confirmed finding of this mistake
    possible_only: int  # repos with only possible findings of this mistake


@dataclass
class Stats:
    total: int
    outcomes: dict[str, int]
    scanned: int
    confirmed_critical: int
    any_confirmed: int
    possible_only: int  # repos whose only findings are possible
    no_db_rules: int
    unread_migrations: int
    mistakes: list[MistakeStat]
    findings_median: float
    findings_min: int
    findings_max: int
    confirmed_median: float
    confirmed_min: int
    confirmed_max: int


def aggregate(records: Iterable[RepoRecord]) -> Stats:
    records = list(records)
    outcomes = {k: 0 for k in OUTCOME_COPY}
    for r in records:
        outcomes[r.status] += 1
    scanned = [r for r in records if r.status == "scanned"]

    def count(pred: Callable[[RepoRecord], bool]) -> int:
        return sum(1 for r in scanned if pred(r))

    mistakes: list[MistakeStat] = []
    for m in sorted({*MISTAKE_NAMES, *(f.mistake for r in scanned for f in r.findings)}):
        conf = count(lambda r, m=m: any(f.mistake == m and is_confirmed(f) for f in r.findings))
        anym = count(lambda r, m=m: any(f.mistake == m for f in r.findings))
        mistakes.append(MistakeStat(mistake=m, confirmed=conf, possible_only=anym - conf))

    totals = [len(r.findings) for r in scanned] or [0]
    confirmed = [sum(1 for f in r.findings if is_confirmed(f)) for r in scanned] or [0]
    any_confirmed = count(lambda r: any(is_confirmed(f) for f in r.findings))
    return Stats(
        total=len(records),
        outcomes=outcomes,
        scanned=len(scanned),
        confirmed_critical=count(lambda r: any(is_confirmed_critical(f) for f in r.findings)),
        any_confirmed=any_confirmed,
        possible_only=count(lambda r: bool(r.findings)) - any_confirmed,
        no_db_rules=count(lambda r: not r.has_db_rules),
        unread_migrations=count(lambda r: r.unparsed_migrations > 0),
        mistakes=mistakes,
        findings_median=statistics.median(totals),
        findings_min=min(totals),
        findings_max=max(totals),
        confirmed_median=statistics.median(confirmed),
        confirmed_min=min(confirmed),
        confirmed_max=max(confirmed),
    )


# --- rendering ------------------------------------------------------------------------------


def _pct(n: int, d: int) -> str:
    return f"{n} of {d} ({n / d:.0%})" if d else f"{n} of {d}"


def _num(x: float) -> str:
    return f"{x:g}"


def _mistake_name(m: int) -> str:
    return MISTAKE_NAMES.get(m, "Other (community rules)")


def render_markdown(s: Stats, method: str, run_date: str) -> str:
    """Aggregates only. Takes no repo data, so no name, URL or path can reach the page."""
    n = s.scanned
    lines = [
        "# Template stats",
        "",
        f"Date run: {run_date}.",
        "Script: `engine/scripts/scan_templates.py` (run with `cd engine && uv run python scripts/scan_templates.py`).",
        "Every number is an aggregate over the scanned repos; no repo is named here.",
        "",
        "## Method",
        "",
        method,
        "",
        "## Outcomes",
        "",
        "| Outcome | Repos |",
        "| --- | --- |",
        *(f"| {OUTCOME_COPY[k]} | {v} |" for k, v in s.outcomes.items()),
        f"| Total | {s.total} |",
        "",
        f"Every percentage below is out of the {n} scanned repos.",
        "",
        "## Headline",
        "",
        f"Repos with at least one confirmed critical finding: {_pct(s.confirmed_critical, n)}.",
        f"Repos with at least one confirmed finding of any severity: {_pct(s.any_confirmed, n)}.",
        f"Repos with only findings marked possible, not confirmed: {_pct(s.possible_only, n)}.",
        f"Repos with no database rules (migrations) in the repo: {_pct(s.no_db_rules, n)}.",
        "For those repos Heist cannot check tables or storage buckets, so mistakes 3 and 4 are unknown, not clean.",
        f"Repos with migration files Heist could not read: {_pct(s.unread_migrations, n)}.",
        f"Findings per repo: median {_num(s.findings_median)}, range {s.findings_min} to {s.findings_max}.",
        f"Confirmed findings per repo: median {_num(s.confirmed_median)}, range {s.confirmed_min} to {s.confirmed_max}.",
        "",
        "## By mistake",
        "",
        "A repo counts once per mistake, however many findings it has.",
        "A repo is under Possible, not confirmed only when none of its findings for that mistake is confirmed.",
        "",
        "| Mistake | Confirmed | Possible, not confirmed |",
        "| --- | --- | --- |",
        *(
            f"| {m.mistake}. {_mistake_name(m.mistake)} | {_pct(m.confirmed, n)} | "
            f"{_pct(m.possible_only, n)} |"
            for m in s.mistakes
        ),
        "",
    ]
    return "\n".join(lines)


# --- scanning -------------------------------------------------------------------------------


def outcome_of(reason: str) -> Outcome:
    if reason == BAD_URL_COPY:
        return "bad_url"
    if reason == UNSUPPORTED_STACK_COPY:
        return "unsupported_stack"
    if reason == CLONE_FAILED_COPY:
        return "clone_failed"
    if reason.startswith(TOO_BIG_COPY.split("{", 1)[0]):
        return "too_big"
    return "error"


def scan_one(url: str, workdir: Path) -> RepoRecord:
    """Heist's fetch path plus the detectors, nothing else. Runs in a child process; the parent
    owns `workdir` and deletes it, even when it has to kill the child."""
    try:
        ws = clone_repo(url, workdir / "repo")
    except UnsupportedRepo as exc:
        return RepoRecord(url=url, sha=None, stack=None, status=outcome_of(exc.reason))
    try:
        stack = detect_stack(ws)
    except UnsupportedRepo as exc:
        return RepoRecord(url=url, sha=ws.commit_sha, stack=None, status=outcome_of(exc.reason))
    g = build_app_graph(ws, stack)
    findings = [finding_record(f) for f in run_detectors(ws, g) if f.refs]
    return RepoRecord(
        url=url,
        sha=ws.commit_sha,
        stack=stack,
        status="scanned",
        has_db_rules=g.has_db_rules,
        unparsed_migrations=len(g.db.unparsed_migrations) if g.db else 0,
        findings=findings,
    )


def record_from_json(d: dict[str, object]) -> RepoRecord:
    raw = d.get("findings")
    findings = [FindingRecord(**f) for f in raw] if isinstance(raw, list) else []  # pyright: ignore[reportUnknownVariableType]
    return RepoRecord(**{**d, "findings": findings})  # type: ignore[arg-type]


def exception_type(stderr: str) -> str:
    """The exception class from a traceback's last line, never its message."""
    tail = stderr.strip().splitlines()[-1:] or [""]
    m = _EXC_RE.match(tail[0])
    return m.group(1) if m else "unknown"


def _scan_in_child(url: str) -> RepoRecord:
    """A child process per repo in its own process group, so a hung clone, gitleaks or semgrep
    is killed with it at the time limit. The temp dir is the parent's, so it is always removed."""
    workdir = Path(tempfile.mkdtemp(prefix="heist-tpl-"))
    try:
        proc = subprocess.Popen(
            [sys.executable, __file__, "--one", url, str(workdir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=ENGINE,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(timeout=REPO_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            print("  timeout", file=sys.stderr)
            return RepoRecord(url=url, sha=None, stack=None, status="timeout")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    last = out.strip().splitlines()[-1:] if proc.returncode == 0 else []
    if not last:
        kind = exception_type(err)
        # The URL and stderr tail go to a gitignored log only, never to the terminal.
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"{url}\n{err.strip()[-2000:]}\n\n")
        print(f"  error ({kind}), details in {LOG.relative_to(REPO)}", file=sys.stderr)
        return RepoRecord(url=url, sha=None, stack=None, status="error")
    return record_from_json(json.loads(last[0]))


def main() -> None:
    urls = [u.strip() for u in TEMPLATES.read_text().splitlines() if u.strip()]
    LOG.unlink(missing_ok=True)
    print(f"scanning {len(urls)} repos, {WORKERS} at a time")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        records = list(pool.map(_scan_in_child, urls))
    RESULTS.write_text("".join(json.dumps(asdict(r)) + "\n" for r in records))
    stats = aggregate(records)
    STATS.write_text(render_markdown(stats, METHOD, date.today().isoformat()))
    print(f"wrote {RESULTS} and {STATS}")
    for k, v in stats.outcomes.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--one":
        print(json.dumps(asdict(scan_one(sys.argv[2], Path(sys.argv[3])))))
    else:
        main()

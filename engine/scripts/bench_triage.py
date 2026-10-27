"""Benchmark triage on the vuln_app fixture and write docs/bench.md.

Runs triage RUNS times per model.
Muse Spark is skipped when it resolves to the same model id as Muse Spark Open (no Meta key yet).
Keys are loaded from engine/.env and never printed.
"""

import json
import statistics
import time
from datetime import date
from pathlib import Path

from heist.detect.run import run_detectors
from heist.fetch import detect_stack, load_workspace
from heist.graph.build import build_app_graph
from heist.llm.client import MetaClient, SpendTracker
from heist.llm.config import load_env
from heist.llm.triage import SYSTEM, TRIAGE_MAX_TOKENS, TriageOut, _payload  # pyright: ignore[reportPrivateUsage]
from heist.models import Finding

ENGINE = Path(__file__).resolve().parent.parent
REPO = ENGINE.parent
RUNS = 5


def run_model(which: str, client: MetaClient, ws, g, findings: list[Finding]) -> dict:
    latencies: list[float] = []
    outputs: list[str] = []
    before = client.tracker.total_usd
    failures = 0
    for _ in range(RUNS):
        start = time.perf_counter()
        try:
            out = client.chat_json(
                "open" if which == "open" else "spark",
                SYSTEM,
                _payload(findings, ws),
                TriageOut,
                max_tokens=TRIAGE_MAX_TOKENS,
            )
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  {which} run failed: {type(exc).__name__}")
            continue
        latencies.append(time.perf_counter() - start)
        key = json.dumps(
            {"groups": sorted(sorted(x) for x in out.groups), "noise": sorted(out.noise)}
        )
        outputs.append(key)
    usd = client.tracker.total_usd - before
    ok = len(outputs)
    agreement = (
        max(outputs.count(o) for o in set(outputs)) / ok if ok else 0.0
    )  # fraction of runs matching the most common result
    return {
        "ok": ok,
        "failures": failures,
        "median_s": statistics.median(latencies) if latencies else 0.0,
        "usd": usd,
        "usd_per_run": usd / RUNS,
        "agreement": agreement,
    }


def main() -> None:
    load_env(ENGINE / ".env")
    app = ENGINE / "tests" / "fixtures" / "vuln_app"
    ws = load_workspace(app)
    g = build_app_graph(ws, detect_stack(ws))
    findings = run_detectors(ws, g)
    tracker = SpendTracker()
    client = MetaClient.from_env(tracker)
    models = client.models()
    print(f"{len(findings)} findings, models: {models}")

    # Token totals come from the tracker's usage via a thin wrapper on add.
    totals = {"prompt": 0, "completion": 0}
    original_add = tracker.add

    def counting_add(model, usage):
        totals["prompt"] += usage.prompt_tokens
        totals["completion"] += usage.completion_tokens
        return original_add(model, usage)

    tracker.add = counting_add  # type: ignore[method-assign]

    rows: list[str] = []
    open_result = run_model("open", client, ws, g, findings)
    open_tokens = dict(totals)
    rows.append(
        f"| Muse Spark Open | `{models['open']}` | {open_result['ok']}/{RUNS} | "
        f"{open_result['median_s']:.1f} | {open_tokens['prompt'] // RUNS} / "
        f"{open_tokens['completion'] // RUNS} | "
        f"{open_result['usd_per_run']:.5f} | {open_result['agreement']:.0%} |"
    )
    if models["spark"] == models["open"]:
        rows.append("| Muse Spark | pending Meta API key | - | - | - | - | - |")
        spark_note = "Muse Spark: pending Meta API key"
    else:
        before = dict(totals)
        spark_result = run_model("spark", client, ws, g, findings)
        n = RUNS
        rows.append(
            f"| Muse Spark | `{models['spark']}` | {spark_result['ok']}/{RUNS} | "
            f"{spark_result['median_s']:.1f} | {(totals['prompt'] - before['prompt']) // n} / "
            f"{(totals['completion'] - before['completion']) // n} | "
            f"{spark_result['usd_per_run']:.5f} | {spark_result['agreement']:.0%} |"
        )
        spark_note = ""

    lines = [
        "# Triage benchmark",
        "",
        f"Date run: {date.today().isoformat()}.",
        "Script: `engine/scripts/bench_triage.py` (run with `cd engine && uv run python scripts/bench_triage.py`).",
        f"Input: triage of the `vuln_app` fixture ({len(findings)} findings), {RUNS} runs per model.",
        "Tokens are mean prompt / completion tokens per attempted run, failed runs included.",
        f"USD per run is total spend divided by {RUNS} attempted runs.",
        "Agreement is the fraction of runs that produced the most common groups and noise result.",
        "",
        "| Model | Id | Successful runs | Median latency (s) | Tokens | USD per run | Agreement |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        *rows,
        "",
    ]
    if spark_note:
        lines += [spark_note, ""]
    out = REPO / "docs" / "bench.md"
    out.write_text("\n".join(lines))
    print(f"wrote {out}")
    print("\n".join(rows))


if __name__ == "__main__":
    main()

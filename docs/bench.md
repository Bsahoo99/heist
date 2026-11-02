# Triage benchmark

Date run: 2026-11-02.
Script: `engine/scripts/bench_triage.py` (run with `cd engine && uv run python scripts/bench_triage.py`).
Input: triage of the `vuln_app` fixture (11 findings), 5 runs per model.
Tokens are mean prompt / completion tokens per attempted run, failed runs included.
USD per run is total spend divided by 5 attempted runs.
Agreement is the fraction of runs that produced the most common groups and noise result.

| Model | Id | Successful runs | Median latency (s) | Tokens | USD per run | Agreement |
| --- | --- | --- | --- | --- | --- | --- |
| Muse Spark Open | `meta-models/muse-spark-open-1026` | 5/5 | 24.4 | 1408 / 5897 | 0.02598 | 80% |
| Muse Spark | pending Meta API key | - | - | - | - | - |

Muse Spark: pending Meta API key

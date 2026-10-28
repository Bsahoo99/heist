"""Command line: `heist analyze <url-or-path> [--out scene.json] [--offline]`."""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from heist.fetch import UnsupportedRepo
from heist.llm.client import MetaClient
from heist.llm.config import load_env
from heist.models import ProgressEvent
from heist.pipeline import GENERIC_ERROR_COPY, run_analysis

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
# The analyzed time written into the checked-in web fixtures, so they diff cleanly.
FIXTURE_TIME = "2026-10-26T00:00:00Z"


def _print_event(e: ProgressEvent) -> None:
    if e.kind == "stage":
        print(f"[heist] {e.message}", file=sys.stderr)
    elif e.kind == "finding":
        d = e.data
        print(f"[heist]   {d['severity']} {d['status']}: {d['title']}", file=sys.stderr)
    elif e.kind == "done":
        d = e.data
        print(f"[heist] {d['findings']} findings, {d['checks_held']}/7 locks held", file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="heist", description="See how your app gets robbed.")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="analyze a public GitHub repo or a local folder")
    a.add_argument("source", help="GitHub URL or local path")
    a.add_argument("--out", type=Path, help="write the Scene JSON here (default: stdout)")
    a.add_argument("--offline", action="store_true", help="skip the model, use template traces")
    # Hidden: pin the analyzed time, used only to regenerate the web fixtures.
    a.add_argument("--analyzed-at", type=datetime.fromisoformat, help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    client: MetaClient | None = None
    if not args.offline:
        load_env(ENV_PATH)
        client = MetaClient.from_env()
    try:
        scene = run_analysis(args.source, _print_event, client, analyzed_at=args.analyzed_at)
    except UnsupportedRepo as exc:
        print(exc.reason, file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 - the pipeline already logged the cause
        print(GENERIC_ERROR_COPY, file=sys.stderr)
        return 1
    finally:
        if client is not None:
            print(f"[heist] model spend: ${client.tracker.total_usd:.4f}", file=sys.stderr)

    text = scene.model_dump_json(indent=2) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"[heist] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""One-shot Ethereum verified-contract intake + static triage runner."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch verified Ethereum contract sources and run local static triage."
    )
    parser.add_argument("--chain-id", default="1", help="Chain ID. Default: 1")
    parser.add_argument("--limit", type=int, default=5000, help="Default: 5000")
    parser.add_argument("--addresses-file", help="Optional address list file.")
    parser.add_argument(
        "--run-dir",
        help="Output run directory. Default: runs/eth-<chain>-<timestamp>.",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=0.35,
        help="Delay between Sourcify contract detail requests. Default: 0.35.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=35.0,
        help="HTTP timeout per request. Default: 35.",
    )
    parser.add_argument("--retries", type=int, default=4, help="Default: 4")
    parser.add_argument(
        "--include-json",
        action="store_true",
        help="Also scan JSON files produced by intake.",
    )
    parser.add_argument(
        "--critical-limit",
        type=int,
        default=500,
        help="Max critical-review.md entries. Default: 500.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Re-download existing Sourcify source folders.",
    )
    return parser.parse_args(argv)


def default_run_dir(chain_id: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("runs") / f"eth-{chain_id}-{timestamp}"


def run_command(command: list[str], cwd: Path) -> None:
    print("Running:", " ".join(command), flush=True)
    subprocess.run(command, cwd=str(cwd), check=True)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace = Path(__file__).resolve().parents[1]
    scripts_dir = Path(__file__).resolve().parent
    run_dir = Path(args.run_dir).resolve() if args.run_dir else (workspace / default_run_dir(args.chain_id)).resolve()
    scan_dir = run_dir / "scan"
    run_dir.mkdir(parents=True, exist_ok=True)

    intake_cmd = [
        sys.executable,
        str(scripts_dir / "eth-sourcify-intake.py"),
        "--chain-id",
        str(args.chain_id),
        "--limit",
        str(args.limit),
        "--out-dir",
        str(run_dir),
        "--delay-seconds",
        str(args.delay_seconds),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--retries",
        str(args.retries),
    ]
    if args.addresses_file:
        intake_cmd.extend(["--addresses-file", str(Path(args.addresses_file).resolve())])
    if args.overwrite:
        intake_cmd.append("--overwrite")

    run_command(intake_cmd, workspace)

    scan_inputs = run_dir / "scan-inputs.txt"
    if not scan_inputs.exists() or not scan_inputs.read_text(encoding="utf-8").strip():
        print(f"error: no scan inputs produced: {scan_inputs}", file=sys.stderr)
        return 1

    scan_cmd = [
        sys.executable,
        str(scripts_dir / "smart-contract-batch-scan.py"),
        "--input-list",
        str(scan_inputs),
        "--out-dir",
        str(scan_dir),
        "--critical-limit",
        str(args.critical_limit),
    ]
    if args.include_json:
        scan_cmd.append("--include-json")

    run_command(scan_cmd, workspace)
    print(f"Run complete: {run_dir}")
    print(f"Critical review: {scan_dir / 'critical-review.md'}")
    print(f"All signals: {scan_dir / 'all-signals.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

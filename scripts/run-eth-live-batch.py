#!/usr/bin/env python3
"""List Sourcify contracts, live-filter them, then fetch and scan kept sources."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live-filtered ETH contract batch.")
    parser.add_argument("--chain-id", default="1")
    parser.add_argument("--candidate-limit", type=int, default=50000)
    parser.add_argument("--exclude-targets-file", action="append", default=[])
    parser.add_argument("--keep-limit", type=int, default=5000)
    parser.add_argument("--run-dir")
    parser.add_argument("--rpc-url", default="https://ethereum-rpc.publicnode.com")
    parser.add_argument("--recent-blocks", type=int, default=10000)
    parser.add_argument("--delay-seconds", type=float, default=0.35)
    parser.add_argument("--request-delay", type=float, default=0.05)
    parser.add_argument("--filter-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--min-score", type=int, default=1)
    parser.add_argument("--eth-min-wei", type=int, default=10**15)
    parser.add_argument("--balance-score-weight", action="store_true")
    parser.add_argument("--require-threshold-balance", action="store_true")
    parser.add_argument("--require-activity", action="store_true")
    parser.add_argument("--keep-native-without-activity", action="store_true")
    parser.add_argument("--min-recent-logs", type=int, default=1)
    parser.add_argument("--logs-address-batch-size", type=int, default=5)
    parser.add_argument("--balance-batch-size", type=int, default=100)
    parser.add_argument("--token-batch-size", type=int, default=80)
    parser.add_argument("--critical-limit", type=int, default=1000)
    parser.add_argument("--skip-token-balances", action="store_true")
    parser.add_argument("--skip-logs", action="store_true")
    return parser.parse_args(argv)


def run(command: list[str], cwd: Path) -> None:
    print("Running:", " ".join(command), flush=True)
    subprocess.run(command, cwd=str(cwd), check=True)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace = Path(__file__).resolve().parents[1]
    scripts = Path(__file__).resolve().parent
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = (
        Path(args.run_dir).resolve()
        if args.run_dir
        else (workspace / "runs" / f"eth-live-{args.chain_id}-{timestamp}").resolve()
    )
    run_dir.mkdir(parents=True, exist_ok=True)

    candidates = run_dir / "candidates.txt"
    candidate_meta = run_dir / "sourcify-candidates.jsonl"
    live_dir = run_dir / "live-filter"
    scan_dir = run_dir / "scan"

    run(
        [
            sys.executable,
            str(scripts / "eth-sourcify-list.py"),
            "--chain-id",
            str(args.chain_id),
            "--limit",
            str(args.candidate_limit),
            "--out",
            str(candidates),
            "--jsonl",
            str(candidate_meta),
        ],
        workspace,
    )

    filter_cmd = [
        sys.executable,
        str(scripts / "eth-live-contract-filter.py"),
        "--targets-file",
        str(candidates),
        "--out-dir",
        str(live_dir),
        "--rpc-url",
        args.rpc_url,
        "--recent-blocks",
        str(args.recent_blocks),
        "--keep-limit",
        str(args.keep_limit),
        "--request-delay",
        str(args.request_delay),
        "--timeout-seconds",
        str(args.filter_timeout_seconds),
        "--min-score",
        str(args.min_score),
        "--eth-min-wei",
        str(args.eth_min_wei),
        "--min-recent-logs",
        str(args.min_recent_logs),
        "--logs-address-batch-size",
        str(args.logs_address_batch_size),
        "--balance-batch-size",
        str(args.balance_batch_size),
        "--token-batch-size",
        str(args.token_batch_size),
    ]
    for exclude_file in args.exclude_targets_file:
        filter_cmd.extend(["--exclude-targets-file", exclude_file])
    if args.skip_token_balances:
        filter_cmd.append("--skip-token-balances")
    if args.skip_logs:
        filter_cmd.append("--skip-logs")
    if args.balance_score_weight:
        filter_cmd.append("--balance-score-weight")
    if args.require_threshold_balance:
        filter_cmd.append("--require-threshold-balance")
    if args.require_activity:
        filter_cmd.append("--require-activity")
    if args.keep_native_without_activity:
        filter_cmd.append("--keep-native-without-activity")
    run(filter_cmd, workspace)

    live_targets = live_dir / "live-targets.txt"
    run(
        [
            sys.executable,
            str(scripts / "eth-sourcify-intake.py"),
            "--chain-id",
            str(args.chain_id),
            "--addresses-file",
            str(live_targets),
            "--out-dir",
            str(run_dir),
            "--delay-seconds",
            str(args.delay_seconds),
        ],
        workspace,
    )

    run(
        [
            sys.executable,
            str(scripts / "smart-contract-batch-scan.py"),
            "--input-list",
            str(run_dir / "scan-inputs.txt"),
            "--out-dir",
            str(scan_dir),
            "--critical-limit",
            str(args.critical_limit),
        ],
        workspace,
    )
    print(f"Run complete: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

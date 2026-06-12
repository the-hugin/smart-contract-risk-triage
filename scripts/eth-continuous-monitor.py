#!/usr/bin/env python3
"""Continuous passive monitor for newly verified EVM contracts.

The monitor polls Sourcify for contracts newer than the saved cursor, applies
the high-value live-balance filter, scans only kept contracts, and deletes
uninteresting run directories after writing compact state/events.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SOURCIFY_BASE = "https://sourcify.dev/server"
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
RUN_PREFIX = "eth-monitor-"
CHAIN_LABELS = {
    "1": "Ethereum",
    "10": "Optimism",
    "100": "Gnosis Chain",
    "324": "zkSync Era",
    "56": "BNB Smart Chain",
    "137": "Polygon PoS",
    "5000": "Mantle",
    "8453": "Base",
    "42220": "Celo",
    "42161": "Arbitrum One",
    "43114": "Avalanche C-Chain",
    "59144": "Linea",
    "534352": "Scroll",
    "81457": "Blast",
}
ALERT_TRIAGE_CLASSES = {"triage-now", "review"}
ALERT_SEVERITIES = {"critical", "high"}
PRIVATE_TELEGRAM_CHAT_RE = re.compile(r"^[1-9][0-9]*$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive high-value EVM monitor.")
    parser.add_argument("--chain-id", default="1")
    parser.add_argument("--chain-label")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--state-dir", default="runs/monitor-state")
    parser.add_argument("--candidate-limit", type=int, default=5000)
    parser.add_argument("--page-size", type=int, default=200)
    parser.add_argument("--seed-if-empty", action="store_true")
    parser.add_argument("--rpc-url", default="https://rpc.mevblocker.io")
    parser.add_argument("--recent-blocks", type=int, default=2000)
    parser.add_argument("--keep-limit", type=int, default=500)
    parser.add_argument("--eth-min-wei", type=int, default=300000000000000000)
    parser.add_argument("--token-threshold", action="append", default=[])
    parser.add_argument(
        "--token",
        action="append",
        default=[],
        metavar="ADDRESS=SYMBOL:DECIMALS:THRESHOLD",
        help="Use a custom token balance filter. Replaces default Ethereum token list when provided.",
    )
    parser.add_argument("--request-delay", type=float, default=0.08)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--balance-batch-size", type=int, default=100)
    parser.add_argument("--token-batch-size", type=int, default=80)
    parser.add_argument("--logs-address-batch-size", type=int, default=5)
    parser.add_argument("--delay-seconds", type=float, default=0.35)
    parser.add_argument("--critical-limit", type=int, default=1000)
    parser.add_argument("--delete-uninteresting", action="store_true")
    parser.add_argument("--cleanup-stale-days", type=float, default=2.0)
    parser.add_argument("--telegram-alerts", action="store_true")
    parser.add_argument("--telegram-token-env", default="SMART_CONTRACT_ALERT_BOT_TOKEN")
    parser.add_argument("--telegram-chat-id-env", default="SMART_CONTRACT_ALERT_CHAT_ID")
    parser.add_argument("--telegram-alert-state")
    parser.add_argument("--telegram-alert-top", type=int, default=3)
    return parser.parse_args(argv)


def resolve_under(base: Path, raw: str | Path) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def http_json(url: str, timeout_seconds: float, retries: int) -> Any:
    last: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "smart-contract-risk-triage-evm-monitor/0.2",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            last = exc
            if attempt >= retries:
                raise
            time.sleep(2**attempt)
    raise RuntimeError(f"request failed: {last}")


def fetch_new_rows(args: argparse.Namespace, cursor_match_id: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows_out: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    after_match_id: str | None = None
    newest_match_id: str | None = None
    newest_address: str | None = None
    cursor_reached = False
    page_size = max(1, min(args.page_size, 200))

    while len(rows_out) < args.candidate_limit:
        query = {"limit": str(page_size), "sort": "desc"}
        if after_match_id:
            query["afterMatchId"] = after_match_id
        url = (
            f"{SOURCIFY_BASE}/v2/contracts/{urllib.parse.quote(str(args.chain_id))}"
            f"?{urllib.parse.urlencode(query)}"
        )
        data = http_json(url, args.timeout_seconds, args.retries)
        rows = data.get("results", data) if isinstance(data, dict) else data
        if not isinstance(rows, list) or not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            match_id = str(row.get("matchId") or "")
            address = str(row.get("address") or "")
            chain_id = str(row.get("chainId") or args.chain_id)
            after_match_id = match_id or after_match_id
            if newest_match_id is None and match_id:
                newest_match_id = match_id
                newest_address = address
            if cursor_match_id and match_id == cursor_match_id:
                cursor_reached = True
                break
            target_key = f"{chain_id}:{address.lower()}"
            if ADDRESS_RE.match(address) and target_key not in seen_targets:
                seen_targets.add(target_key)
                rows_out.append(row)
            if len(rows_out) >= args.candidate_limit:
                break
        if cursor_reached or len(rows) < page_size:
            break

    meta = {
        "cursorReached": cursor_reached,
        "newestMatchId": newest_match_id,
        "newestAddress": newest_address,
        "candidateLimit": args.candidate_limit,
        "fetchedCount": len(rows_out),
    }
    return rows_out, meta


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def write_candidates(run_dir: Path, rows: list[dict[str, Any]], default_chain_id: str) -> None:
    candidates = run_dir / "candidates.txt"
    metadata = run_dir / "sourcify-candidates.jsonl"
    with candidates.open("w", encoding="utf-8", newline="\n") as targets_handle, metadata.open(
        "w", encoding="utf-8", newline="\n"
    ) as metadata_handle:
        for row in rows:
            chain_id = str(row.get("chainId") or default_chain_id)
            address = str(row.get("address") or "")
            targets_handle.write(f"{chain_id},{address}\n")
            metadata_handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def run_command(command: list[str], cwd: Path, log_path: Path, ok_codes: set[int] | None = None) -> int:
    ok_codes = ok_codes or {0}
    with log_path.open("a", encoding="utf-8", newline="\n") as log:
        log.write(f"$ {' '.join(command)}\n")
        log.flush()
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        log.write(f"exit={completed.returncode}\n")
    if completed.returncode not in ok_codes:
        raise RuntimeError(f"command failed with exit {completed.returncode}: {' '.join(command)}")
    return completed.returncode


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def count_scan_findings(path: Path) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    total = 0
    if path.exists():
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            total += 1
            counts[str(row.get("severity") or "unknown")] += 1
    return {"findingCount": total, "severityCounts": dict(counts)}


def safe_delete_run_dir(run_dir: Path, runs_root: Path) -> None:
    resolved = run_dir.resolve()
    root = runs_root.resolve()
    if not resolved.name.startswith(RUN_PREFIX):
        raise RuntimeError(f"refusing to delete non-monitor run dir: {resolved}")
    if root not in resolved.parents:
        raise RuntimeError(f"refusing to delete outside runs root: {resolved}")
    shutil.rmtree(resolved)


def cleanup_stale_runs(runs_root: Path, max_age_days: float) -> list[str]:
    deleted: list[str] = []
    if max_age_days <= 0 or not runs_root.exists():
        return deleted
    cutoff = time.time() - max_age_days * 86400
    for path in runs_root.glob(f"{RUN_PREFIX}*"):
        try:
            if not path.is_dir() or (path / ".keep").exists():
                continue
            if path.stat().st_mtime >= cutoff:
                continue
            safe_delete_run_dir(path, runs_root)
            deleted.append(str(path))
        except OSError:
            continue
    return deleted


def compact(value: Any, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip(" ,.;:-") + "..."


def format_balances(live: dict[str, Any]) -> str:
    parts: list[str] = []
    native = str(live.get("nativeBalanceWei") or "0")
    try:
        native_value = int(native) / 10**18
    except ValueError:
        native_value = 0.0
    if native_value:
        parts.append(f"native={native_value:.4f}")
    token_balances = live.get("majorTokenBalances")
    if isinstance(token_balances, dict):
        for symbol, raw in sorted(token_balances.items()):
            parts.append(f"{symbol}={raw}")
    return ", ".join(parts) if parts else "n/a"


def alert_key(chain_id: str, row: dict[str, Any]) -> str:
    fields = [
        chain_id,
        str(row.get("address") or "").lower(),
        str(row.get("triageClass") or ""),
        str(row.get("severity") or ""),
        str(row.get("category") or ""),
        str(row.get("function") or ""),
        str(row.get("line") or ""),
        compact(row.get("signal"), 120),
    ]
    return "|".join(fields)


def alert_rows(run_dir: Path, limit: int) -> list[dict[str, Any]]:
    rows = read_jsonl(run_dir / "triage" / "high-value-triage.jsonl")
    selected = [
        row
        for row in rows
        if str(row.get("triageClass") or "") in ALERT_TRIAGE_CLASSES
        or str(row.get("severity") or "").lower() in ALERT_SEVERITIES
    ]

    def sort_key(row: dict[str, Any]) -> tuple[int, int]:
        triage_rank = {"triage-now": 3, "review": 2, "watch": 1}.get(str(row.get("triageClass") or ""), 0)
        try:
            score = int(row.get("reliabilityScore") or 0)
        except (TypeError, ValueError):
            score = 0
        return (triage_rank, score)

    selected.sort(key=sort_key, reverse=True)
    return selected[: max(1, limit)]


def format_alert_message(chain_id: str, run_dir: Path, rows: list[dict[str, Any]], event: dict[str, Any]) -> str:
    chain_label = str(event.get("chainLabel") or CHAIN_LABELS.get(str(chain_id), f"chain {chain_id}"))
    header = [
        "Smart-contract alert",
        f"Network: {chain_label} ({chain_id})",
        f"Status: {event.get('status')}",
        f"New contracts: {event.get('newTargetCount')}; kept: {event.get('keptCount')}",
    ]
    body: list[str] = []
    for index, row in enumerate(rows, 1):
        live = row.get("live") if isinstance(row.get("live"), dict) else {}
        body.extend(
            [
                "",
                f"{index}. {str(row.get('triageClass') or 'alert')} / {str(row.get('severity') or 'unknown')}",
                f"Address: {row.get('address')}",
                f"Category: {row.get('category')} / {row.get('function')}:{row.get('line')}",
                f"Balance: {format_balances(live)}",
                f"Signal: {compact(row.get('signal'), 240)}",
                f"Manual: {compact(row.get('manualCheck'), 220)}",
            ]
        )
    footer = [
        "",
        f"Artifact: {run_dir / 'triage' / 'high-value-triage.md'}",
        "Boundary: passive signal only; no PoC or transaction steps.",
    ]
    message = "\n".join(header + body + footer)
    return message[:3900]


def send_telegram(token: str, chat_id: str, message: str, timeout_seconds: float) -> None:
    payload = {
        "chat_id": chat_id,
        "text": message,
        "disable_web_page_preview": True,
    }
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict) or not data.get("ok"):
        raise RuntimeError("Telegram API returned non-ok response")


def maybe_send_telegram_alert(
    args: argparse.Namespace,
    state_dir: Path,
    run_dir: Path,
    event: dict[str, Any],
) -> dict[str, Any]:
    if not args.telegram_alerts or not event.get("interesting"):
        return {"status": "disabled" if not args.telegram_alerts else "not_applicable"}
    token = os.environ.get(args.telegram_token_env, "")
    chat_id = os.environ.get(args.telegram_chat_id_env, "").strip()
    if not token or not chat_id:
        return {"status": "missing_env", "tokenEnv": args.telegram_token_env, "chatIdEnv": args.telegram_chat_id_env}
    if not PRIVATE_TELEGRAM_CHAT_RE.fullmatch(chat_id):
        return {
            "status": "rejected_chat_id",
            "reason": "smart-contract alerts require a positive numeric private Telegram chat id",
            "chatIdEnv": args.telegram_chat_id_env,
        }
    state_path = resolve_under(state_dir, args.telegram_alert_state) if args.telegram_alert_state else state_dir / "telegram-alert-state.json"
    state = read_json(state_path)
    sent = state.get("sent") if isinstance(state.get("sent"), dict) else {}
    rows = alert_rows(run_dir, args.telegram_alert_top)
    unsent = [row for row in rows if alert_key(str(args.chain_id), row) not in sent]
    if not unsent:
        return {"status": "already_sent", "selected": len(rows), "sent": 0, "state": str(state_path)}
    message = format_alert_message(str(args.chain_id), run_dir, unsent, event)
    send_telegram(token, chat_id, message, args.timeout_seconds)
    now = utc_now()
    for row in unsent:
        sent[alert_key(str(args.chain_id), row)] = {
            "sentAt": now,
            "address": row.get("address"),
            "triageClass": row.get("triageClass"),
            "severity": row.get("severity"),
            "category": row.get("category"),
            "function": row.get("function"),
            "line": row.get("line"),
            "runDir": str(run_dir),
        }
    write_json(state_path, {"updatedAt": now, "sent": sent})
    return {"status": "sent", "selected": len(rows), "sent": len(unsent), "state": str(state_path)}


def update_state(state_path: Path, state: dict[str, Any], newest_match_id: str | None, newest_address: str | None) -> None:
    if newest_match_id:
        state["lastSeenMatchId"] = newest_match_id
        state["lastSeenAddress"] = newest_address
        state["updatedAt"] = utc_now()
    write_json(state_path, state)


def pipeline(args: argparse.Namespace, workspace: Path, state_dir: Path, run_dir: Path, log_path: Path) -> dict[str, Any]:
    scripts = workspace / "scripts"
    live_dir = run_dir / "live-filter"
    precheck_json = run_dir / "runtime-precheck.json"
    scan_dir = run_dir / "scan"

    filter_cmd = [
        sys.executable,
        str(scripts / "eth-live-contract-filter.py"),
        "--targets-file",
        str(run_dir / "candidates.txt"),
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
        str(args.timeout_seconds),
        "--retries",
        str(args.retries),
        "--min-score",
        "1",
        "--eth-min-wei",
        str(args.eth_min_wei),
        "--min-recent-logs",
        "1",
        "--logs-address-batch-size",
        str(args.logs_address_batch_size),
        "--balance-batch-size",
        str(args.balance_batch_size),
        "--token-batch-size",
        str(args.token_batch_size),
        "--balance-score-weight",
        "--require-threshold-balance",
    ]
    for token_threshold in args.token_threshold:
        filter_cmd.extend(["--token-threshold", token_threshold])
    for token in args.token:
        filter_cmd.extend(["--token", token])
    filter_code = run_command(filter_cmd, workspace, log_path, ok_codes={0, 1})

    live_summary = read_json(live_dir / "live-filter-summary.json")
    kept_count = int(live_summary.get("keptCount") or 0)
    result: dict[str, Any] = {
        "filterExitCode": filter_code,
        "keptCount": kept_count,
        "liveSummary": live_summary,
    }
    if kept_count == 0:
        result["status"] = "no_high_value_targets"
        return result

    run_command(
        [
            sys.executable,
            str(scripts / "eth-runtime-precheck.py"),
            "--targets-file",
            str(live_dir / "live-targets.txt"),
            "--out",
            str(precheck_json),
            "--rpc-url",
            args.rpc_url,
            "--batch-size",
            str(args.token_batch_size),
            "--request-delay",
            str(args.request_delay),
            "--timeout-seconds",
            str(args.timeout_seconds),
            "--retries",
            str(args.retries),
        ],
        workspace,
        log_path,
    )
    run_command(
        [
            sys.executable,
            str(scripts / "eth-sourcify-intake.py"),
            "--chain-id",
            str(args.chain_id),
            "--addresses-file",
            str(live_dir / "live-targets.txt"),
            "--out-dir",
            str(run_dir),
            "--delay-seconds",
            str(args.delay_seconds),
        ],
        workspace,
        log_path,
    )
    run_command(
        [
            sys.executable,
            str(scripts / "smart-contract-batch-scan.py"),
            "--input-list",
            str(run_dir / "scan-inputs.txt"),
            "--out-dir",
            str(scan_dir),
            "--critical-limit",
            str(args.critical_limit),
            "--precheck-json",
            str(precheck_json),
        ],
        workspace,
        log_path,
    )
    run_command(
        [
            sys.executable,
            str(scripts / "eth-high-value-triage.py"),
            "--run-dir",
            str(run_dir),
        ],
        workspace,
        log_path,
    )

    scan_counts = count_scan_findings(scan_dir / "all-signals.jsonl")
    triage_summary = read_json(run_dir / "triage" / "high-value-triage-summary.json")
    triage_counts = triage_summary.get("triageClassCounts") if isinstance(triage_summary.get("triageClassCounts"), dict) else {}
    severity_counts = scan_counts.get("severityCounts") if isinstance(scan_counts.get("severityCounts"), dict) else {}
    interesting = (
        int(triage_counts.get("triage-now") or 0) > 0
        or int(triage_counts.get("review") or 0) > 0
        or int(severity_counts.get("critical") or 0) > 0
        or int(severity_counts.get("high") or 0) > 0
    )
    result.update(
        {
            "status": "interesting" if interesting else "uninteresting",
            "interesting": interesting,
            "scan": scan_counts,
            "triageSummary": triage_summary,
            "sourceTargetCount": count_jsonl(run_dir / "sourcify-contracts-index.jsonl"),
        }
    )
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.token and not args.token_threshold:
        args.token_threshold = [
            "WETH=0.3",
            "stETH=0.3",
            "WBTC=0.008",
            "USDC=500",
            "USDT=500",
            "DAI=500",
        ]
    workspace = Path(args.workspace).resolve()
    runs_root = workspace / "runs"
    state_dir = resolve_under(workspace, args.state_dir)
    state_path = state_dir / "state.json"
    events_path = state_dir / "events.jsonl"
    latest_path = state_dir / "latest-summary.json"
    lock_path = state_dir / "monitor.lock"
    state_dir.mkdir(parents=True, exist_ok=True)
    runs_root.mkdir(parents=True, exist_ok=True)

    if lock_path.exists():
        raise RuntimeError(f"monitor lock exists: {lock_path}")
    lock_path.write_text(str(time.time()), encoding="utf-8")
    run_dir: Path | None = None
    try:
        state = read_json(state_path)
        cursor = str(state.get("lastSeenMatchId") or "") or None
        seed_mode = args.seed_if_empty and cursor is None
        fetch_limit = 1 if seed_mode else args.candidate_limit
        original_limit = args.candidate_limit
        args.candidate_limit = fetch_limit
        rows, fetch_meta = fetch_new_rows(args, cursor)
        args.candidate_limit = original_limit

        event: dict[str, Any] = {
            "createdAt": utc_now(),
            "chainId": str(args.chain_id),
            "chainLabel": args.chain_label or CHAIN_LABELS.get(str(args.chain_id)),
            "cursorBefore": cursor,
            "fetch": fetch_meta,
            "status": "started",
        }

        newest_match_id = fetch_meta.get("newestMatchId")
        newest_address = fetch_meta.get("newestAddress")
        if seed_mode:
            update_state(state_path, state, str(newest_match_id or ""), str(newest_address or ""))
            event["status"] = "seeded"
            event["deletedRunDir"] = False
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 0

        if cursor and not fetch_meta.get("cursorReached") and len(rows) >= args.candidate_limit:
            event["status"] = "cursor_not_reached"
            event["actionRequired"] = "increase candidate limit before updating cursor"
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 1

        if not rows:
            event["status"] = "no_new_contracts"
            event["deletedRunDir"] = False
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 0

        run_dir = runs_root / f"{RUN_PREFIX}{args.chain_id}-{timestamp_slug()}-n{len(rows)}"
        run_dir.mkdir(parents=True, exist_ok=False)
        log_path = run_dir / "monitor.log"
        write_candidates(run_dir, rows, str(args.chain_id))
        event["runDir"] = str(run_dir)
        event["newTargetCount"] = len(rows)
        result = pipeline(args, workspace, state_dir, run_dir, log_path)
        event.update(result)

        if event.get("interesting"):
            (run_dir / ".keep").write_text(utc_now(), encoding="utf-8")
            event["deletedRunDir"] = False
        elif args.delete_uninteresting:
            safe_delete_run_dir(run_dir, runs_root)
            event["deletedRunDir"] = True
        else:
            event["deletedRunDir"] = False

        try:
            event["telegramAlert"] = maybe_send_telegram_alert(args, state_dir, run_dir, event)
        except Exception as exc:
            event["telegramAlert"] = {"status": "failed", "error": str(exc)}

        update_state(state_path, state, str(newest_match_id or ""), str(newest_address or ""))
        event["cursorAfter"] = newest_match_id
        event["staleDeleted"] = cleanup_stale_runs(runs_root, args.cleanup_stale_days)
        write_json(latest_path, event)
        append_jsonl(events_path, event)
        print(json.dumps(event, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        event = {
            "createdAt": utc_now(),
            "status": "failed",
            "error": str(exc),
            "runDir": str(run_dir) if run_dir else None,
        }
        write_json(latest_path, event)
        append_jsonl(events_path, event)
        print(json.dumps(event, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 1
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

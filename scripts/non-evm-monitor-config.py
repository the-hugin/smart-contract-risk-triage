#!/usr/bin/env python3
"""Manage passive non-EVM monitor chain configuration."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Iterable


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "smart-contract-non-evm-chains.json"
DEFAULT_REMOTE_ROOT = "/opt/smart-contract-risk-triage"
SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_./:=,@+%#?&-]+$")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List configured non-EVM chains.")
    list_parser.add_argument("--include-disabled", action="store_true")
    list_parser.add_argument("--json", action="store_true")

    probe_parser = subparsers.add_parser("probe", help="Probe passive RPC readiness.")
    probe_parser.add_argument("--include-disabled", action="store_true")
    probe_parser.add_argument("--only", action="append", default=[], help="Chain slug to include.")
    probe_parser.add_argument("--timeout-seconds", type=float, default=15.0)
    probe_parser.add_argument("--retries", type=int, default=1)
    probe_parser.add_argument("--json", action="store_true")

    systemd_parser = subparsers.add_parser("systemd", help="Render systemd units from config.")
    systemd_parser.add_argument("--out-dir", type=Path, required=True)
    systemd_parser.add_argument("--include-disabled", action="store_true")
    systemd_parser.add_argument("--only", action="append", default=[], help="Chain slug to render.")
    systemd_parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    systemd_parser.add_argument("--python", default="/usr/bin/python3")
    systemd_parser.add_argument("--no-telegram", action="store_true")

    return parser.parse_args(argv)


def load_config(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"failed to read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("config root must be an object")
    chains = data.get("chains")
    if not isinstance(chains, list) or not chains:
        raise ValueError("config must contain a non-empty chains list")
    return data


def validate_chain(chain: dict[str, Any]) -> None:
    required = ["slug", "label", "family", "rpcs", "onBootSec"]
    for key in required:
        if not chain.get(key):
            raise ValueError(f"chain entry missing {key}: {chain}")
    slug = str(chain["slug"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
        raise ValueError(f"invalid chain slug: {slug!r}")
    if str(chain["family"]) != "solana":
        raise ValueError(f"{slug}: unsupported non-EVM family {chain['family']!r}")
    if not isinstance(chain["rpcs"], list) or not chain["rpcs"]:
        raise ValueError(f"{slug}: rpcs must be a non-empty list")


def selected_chains(config: dict[str, Any], include_disabled: bool, only: Iterable[str]) -> list[dict[str, Any]]:
    only_set = {item.strip().lower() for item in only if item.strip()}
    chains: list[dict[str, Any]] = []
    for raw in config["chains"]:
        if not isinstance(raw, dict):
            raise ValueError("chain entry must be an object")
        slug = str(raw.get("slug") or "").lower()
        if only_set and slug not in only_set:
            continue
        if not include_disabled and not bool(raw.get("enabled")):
            continue
        validate_chain(raw)
        chains.append(raw)
    missing = only_set - {str(chain.get("slug") or "").lower() for chain in chains}
    if missing:
        raise ValueError(f"unknown or disabled chain slug(s): {', '.join(sorted(missing))}")
    return chains


def rpc_request(url: str, method: str, params: list[Any], timeout_seconds: float, retries: int) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    last: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "smart-contract-risk-triage-non-evm-config/0.2",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict) and data.get("error"):
                raise RuntimeError(json.dumps(data["error"], sort_keys=True))
            return data.get("result") if isinstance(data, dict) else None
        except Exception as exc:
            last = exc
            if attempt >= retries:
                raise
            time.sleep(2**attempt)
    raise RuntimeError(f"request failed: {last}")


def probe_chain(chain: dict[str, Any], timeout_seconds: float, retries: int) -> dict[str, Any]:
    rpc_results: list[dict[str, Any]] = []
    chosen_rpc: str | None = None
    slot: Any = None
    version: Any = None
    for rpc in chain["rpcs"]:
        row: dict[str, Any] = {"rpc": rpc, "ok": False}
        try:
            version = rpc_request(str(rpc), "getVersion", [], timeout_seconds, retries)
            slot = rpc_request(str(rpc), "getSlot", [{"commitment": "confirmed"}], timeout_seconds, retries)
            row.update({"ok": isinstance(slot, int) and isinstance(version, dict), "slot": slot})
            if row["ok"] and chosen_rpc is None:
                chosen_rpc = str(rpc)
        except Exception as exc:
            row.update({"error": type(exc).__name__})
        rpc_results.append(row)
    return {
        "slug": chain["slug"],
        "label": chain["label"],
        "family": chain["family"],
        "enabled": bool(chain.get("enabled")),
        "chosenRpc": chosen_rpc,
        "slot": slot,
        "version": version,
        "rpc": rpc_results,
        "ready": bool(chosen_rpc),
    }


def safe_arg(value: Any) -> str:
    text = str(value)
    if not SAFE_ARG_RE.match(text):
        raise ValueError(f"unsafe systemd argument: {text!r}")
    return text


def monitor_args(
    chain: dict[str, Any],
    defaults: dict[str, Any],
    remote_root: str,
    python_bin: str,
    include_telegram: bool,
) -> list[str]:
    default_monitor = defaults.get("monitor") if isinstance(defaults.get("monitor"), dict) else {}
    chain_monitor = chain.get("monitor") if isinstance(chain.get("monitor"), dict) else {}
    monitor = {**default_monitor, **chain_monitor}
    args = [
        safe_arg(python_bin),
        safe_arg(f"{remote_root.rstrip('/')}/scripts/solana-program-monitor.py"),
        "--workspace",
        safe_arg(remote_root.rstrip("/")),
        "--state-dir",
        safe_arg(f"runs/monitor-state/{chain['slug']}"),
        "--rpc-url",
        safe_arg(chain["rpcs"][0]),
        "--candidate-limit",
        safe_arg(monitor.get("candidateLimit", 25)),
    ]
    if bool(monitor.get("allowCursorSkip", False)):
        args.append("--allow-cursor-skip")
    args.extend(
        [
            "--seed-if-empty",
            "--request-delay",
            safe_arg(monitor.get("requestDelay", 0.8)),
            "--timeout-seconds",
            safe_arg(monitor.get("timeoutSeconds", 30)),
            "--retries",
            safe_arg(monitor.get("retries", 3)),
            "--transaction-batch-size",
            safe_arg(monitor.get("transactionBatchSize", 10)),
            "--max-error-rate",
            safe_arg(monitor.get("maxErrorRate", 0.2)),
            "--value-map-signature-limit",
            safe_arg(monitor.get("valueMapSignatureLimit", 6)),
            "--value-map-max-transactions",
            safe_arg(monitor.get("valueMapMaxTransactions", 3)),
            "--value-map-account-sample-limit",
            safe_arg(monitor.get("valueMapAccountSampleLimit", 20)),
        ]
    )
    if bool(monitor.get("deleteUninteresting", True)):
        args.append("--delete-uninteresting")
    args.extend(["--cleanup-stale-days", safe_arg(monitor.get("cleanupStaleDays", 2))])
    if include_telegram and bool(monitor.get("telegramAlerts", False)):
        args.extend(["--telegram-alerts", "--telegram-alert-top", safe_arg(monitor.get("telegramAlertTop", 5))])
    return args


def render_service(
    chain: dict[str, Any],
    config: dict[str, Any],
    remote_root: str,
    python_bin: str,
    include_telegram: bool,
) -> str:
    defaults = config.get("defaults") if isinstance(config.get("defaults"), dict) else {}
    systemd = defaults.get("systemd") if isinstance(defaults.get("systemd"), dict) else {}
    environment_file = systemd.get("environmentFile", "")
    lines = [
        "[Unit]",
        f"Description=Passive {chain['label']} non-EVM smart-contract monitor",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=oneshot",
        f"WorkingDirectory={safe_arg(remote_root.rstrip('/'))}",
    ]
    if include_telegram and environment_file:
        lines.append(f"EnvironmentFile={safe_arg(environment_file)}")
    lines.extend(
        [
            "ExecStart=" + " ".join(monitor_args(chain, defaults, remote_root, python_bin, include_telegram)),
            f"TimeoutStartSec={safe_arg(systemd.get('timeoutStartSec', 1800))}",
            "Nice=10",
            "IOSchedulingClass=best-effort",
            "IOSchedulingPriority=7",
            "",
        ]
    )
    return "\n".join(lines)


def render_timer(chain: dict[str, Any], config: dict[str, Any]) -> str:
    defaults = config.get("defaults") if isinstance(config.get("defaults"), dict) else {}
    default_systemd = defaults.get("systemd") if isinstance(defaults.get("systemd"), dict) else {}
    chain_systemd = chain.get("systemd") if isinstance(chain.get("systemd"), dict) else {}
    systemd = {**default_systemd, **chain_systemd}
    lines = [
        "[Unit]",
        f"Description=Run passive {chain['label']} non-EVM smart-contract monitor every 30 minutes",
        "",
        "[Timer]",
        f"OnBootSec={safe_arg(chain['onBootSec'])}",
        f"OnUnitInactiveSec={safe_arg(systemd.get('onUnitInactiveSec', '30min'))}",
        f"RandomizedDelaySec={safe_arg(systemd.get('randomizedDelaySec', 300))}",
        "Persistent=false",
        f"Unit=smart-contract-monitor-{safe_arg(chain['slug'])}.service",
        "",
        "[Install]",
        "WantedBy=timers.target",
        "",
    ]
    return "\n".join(lines)


def command_list(args: argparse.Namespace, config: dict[str, Any]) -> int:
    chains = selected_chains(config, args.include_disabled, [])
    if args.json:
        print(json.dumps(chains, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    for chain in chains:
        status = "enabled" if chain.get("enabled") else "candidate"
        print(f"{chain['slug']}\t{chain['family']}\t{status}\t{chain['label']}")
    return 0


def command_probe(args: argparse.Namespace, config: dict[str, Any]) -> int:
    chains = selected_chains(config, args.include_disabled, args.only)
    results = [probe_chain(chain, args.timeout_seconds, args.retries) for chain in chains]
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for result in results:
            state = "ready" if result["ready"] else "blocked"
            print(f"{result['slug']}\t{result['family']}\t{state}\trpc={result.get('chosenRpc') or '-'}\tslot={result.get('slot')}")
    return 0 if all(result["ready"] for result in results) else 1


def command_systemd(args: argparse.Namespace, config: dict[str, Any]) -> int:
    chains = selected_chains(config, args.include_disabled, args.only)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for chain in chains:
        slug = str(chain["slug"])
        (args.out_dir / f"smart-contract-monitor-{slug}.service").write_text(
            render_service(chain, config, args.remote_root, args.python, not args.no_telegram),
            encoding="utf-8",
            newline="\n",
        )
        (args.out_dir / f"smart-contract-monitor-{slug}.timer").write_text(
            render_timer(chain, config),
            encoding="utf-8",
            newline="\n",
        )
    print(f"rendered={len(chains)} out_dir={args.out_dir}")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        config = load_config(args.config.resolve())
        if args.command == "list":
            return command_list(args, config)
        if args.command == "probe":
            return command_probe(args, config)
        if args.command == "systemd":
            return command_systemd(args, config)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    raise RuntimeError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

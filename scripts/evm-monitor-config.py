#!/usr/bin/env python3
"""Manage passive EVM monitor chain configuration.

This script does not scan contracts. It validates chain config, probes passive
RPC/Sourcify readiness, and renders systemd units for eth-continuous-monitor.py.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "smart-contract-evm-chains.json"
DEFAULT_REMOTE_ROOT = "/opt/smart-contract-risk-triage"
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_./:=,@+%#?&-]+$")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List configured EVM chains.")
    list_parser.add_argument("--include-disabled", action="store_true")
    list_parser.add_argument("--json", action="store_true")

    probe_parser = subparsers.add_parser("probe", help="Probe RPC and Sourcify readiness.")
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


def validate_chain(chain: dict[str, Any]) -> None:
    required = ["slug", "label", "chainId", "rpcs", "nativeThresholdWei", "onBootSec"]
    for key in required:
        if not chain.get(key):
            raise ValueError(f"chain entry missing {key}: {chain}")
    slug = str(chain["slug"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
        raise ValueError(f"invalid chain slug: {slug!r}")
    int(str(chain["chainId"]))
    int(str(chain["nativeThresholdWei"]))
    if not isinstance(chain["rpcs"], list) or not chain["rpcs"]:
        raise ValueError(f"{slug}: rpcs must be a non-empty list")
    tokens = chain.get("tokens") or []
    if not isinstance(tokens, list):
        raise ValueError(f"{slug}: tokens must be a list")
    symbols: set[str] = set()
    for token in tokens:
        if not isinstance(token, dict):
            raise ValueError(f"{slug}: token entry must be an object")
        address = str(token.get("address") or "")
        symbol = str(token.get("symbol") or "")
        if not ADDRESS_RE.match(address):
            raise ValueError(f"{slug}: invalid token address {address!r}")
        if not symbol or symbol.upper() in symbols:
            raise ValueError(f"{slug}: duplicate or empty token symbol {symbol!r}")
        symbols.add(symbol.upper())
        decimals = int(token.get("decimals"))
        if decimals < 0 or decimals > 36:
            raise ValueError(f"{slug}: invalid token decimals for {symbol}")
        float(token.get("threshold"))


def rpc_request(url: str, payload: Any, timeout_seconds: float, retries: int) -> Any:
    data = json.dumps(payload).encode("utf-8")
    last: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "smart-contract-risk-triage-evm-config/0.2",
            },
            method="POST",
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


def http_json(url: str, timeout_seconds: float, retries: int) -> Any:
    last: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "smart-contract-risk-triage-evm-config/0.2"},
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


def probe_chain(chain: dict[str, Any], sourcify_base: str, timeout_seconds: float, retries: int) -> dict[str, Any]:
    expected_chain_id = hex(int(str(chain["chainId"])))
    rpc_results: list[dict[str, Any]] = []
    chosen_rpc: str | None = None
    for rpc in chain["rpcs"]:
        row: dict[str, Any] = {"rpc": rpc, "ok": False}
        try:
            data = rpc_request(
                str(rpc),
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
                    {"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber", "params": []},
                ],
                timeout_seconds,
                retries,
            )
            by_id = {item.get("id"): item for item in data} if isinstance(data, list) else {}
            chain_ok = by_id.get(1, {}).get("result") == expected_chain_id
            block_ok = str(by_id.get(2, {}).get("result") or "").startswith("0x")
            row.update({"ok": bool(chain_ok and block_ok), "chainOk": chain_ok, "batchOk": isinstance(data, list)})
            if row["ok"] and chosen_rpc is None:
                chosen_rpc = str(rpc)
        except Exception as exc:
            row.update({"error": type(exc).__name__})
        rpc_results.append(row)
    query = urllib.parse.urlencode({"limit": "1", "sort": "desc"})
    sourcify_url = f"{sourcify_base.rstrip('/')}/v2/contracts/{urllib.parse.quote(str(chain['chainId']))}?{query}"
    sourcify: dict[str, Any]
    try:
        data = http_json(sourcify_url, timeout_seconds, retries)
        rows = data.get("results", data) if isinstance(data, dict) else data
        sourcify = {"ok": isinstance(rows, list) and len(rows) >= 0, "countProbe": len(rows) if isinstance(rows, list) else -1}
    except Exception as exc:
        sourcify = {"ok": False, "error": type(exc).__name__}
    return {
        "slug": chain["slug"],
        "label": chain["label"],
        "enabled": bool(chain.get("enabled")),
        "chainId": str(chain["chainId"]),
        "chosenRpc": chosen_rpc,
        "rpc": rpc_results,
        "sourcify": sourcify,
        "ready": bool(chosen_rpc and sourcify.get("ok")),
    }


def safe_arg(value: Any) -> str:
    text = str(value)
    if not SAFE_ARG_RE.match(text):
        raise ValueError(f"unsafe systemd argument: {text!r}")
    return text


def token_arg(token: dict[str, Any]) -> str:
    return safe_arg(f"{token['address']}={token['symbol']}:{int(token['decimals'])}:{token['threshold']}")


def monitor_args(
    chain: dict[str, Any],
    defaults: dict[str, Any],
    remote_root: str,
    python_bin: str,
    include_telegram: bool,
) -> list[str]:
    monitor = defaults.get("monitor") if isinstance(defaults.get("monitor"), dict) else {}
    args = [
        safe_arg(python_bin),
        safe_arg(f"{remote_root.rstrip('/')}/scripts/eth-continuous-monitor.py"),
        "--chain-id",
        safe_arg(chain["chainId"]),
        "--workspace",
        safe_arg(remote_root.rstrip("/")),
        "--state-dir",
        safe_arg(f"runs/monitor-state/{chain['slug']}"),
        "--candidate-limit",
        safe_arg(monitor.get("candidateLimit", 5000)),
        "--page-size",
        safe_arg(monitor.get("pageSize", 200)),
        "--seed-if-empty",
        "--rpc-url",
        safe_arg(chain["rpcs"][0]),
        "--recent-blocks",
        safe_arg(monitor.get("recentBlocks", 2000)),
        "--keep-limit",
        safe_arg(monitor.get("keepLimit", 500)),
        "--eth-min-wei",
        safe_arg(chain["nativeThresholdWei"]),
    ]
    for token in chain.get("tokens") or []:
        args.extend(["--token", token_arg(token)])
    args.extend(
        [
            "--request-delay",
            safe_arg(monitor.get("requestDelay", 0.08)),
            "--timeout-seconds",
            safe_arg(monitor.get("timeoutSeconds", 30)),
            "--retries",
            safe_arg(monitor.get("retries", 2)),
            "--balance-batch-size",
            safe_arg(monitor.get("balanceBatchSize", 100)),
            "--token-batch-size",
            safe_arg(monitor.get("tokenBatchSize", 80)),
            "--logs-address-batch-size",
            safe_arg(monitor.get("logsAddressBatchSize", 5)),
            "--delay-seconds",
            safe_arg(monitor.get("delaySeconds", 0.35)),
            "--critical-limit",
            safe_arg(monitor.get("criticalLimit", 1000)),
        ]
    )
    if bool(monitor.get("deleteUninteresting", True)):
        args.append("--delete-uninteresting")
    args.extend(["--cleanup-stale-days", safe_arg(monitor.get("cleanupStaleDays", 2))])
    if include_telegram and bool(monitor.get("telegramAlerts", False)):
        args.extend(["--telegram-alerts", "--telegram-alert-top", safe_arg(monitor.get("telegramAlertTop", 3))])
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
        f"Description=Passive high-value {chain['label']} smart-contract monitor",
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
            f"TimeoutStartSec={safe_arg(systemd.get('timeoutStartSec', 7200))}",
            "Nice=10",
            "IOSchedulingClass=best-effort",
            "IOSchedulingPriority=7",
            "",
        ]
    )
    return "\n".join(lines)


def render_timer(chain: dict[str, Any], config: dict[str, Any]) -> str:
    defaults = config.get("defaults") if isinstance(config.get("defaults"), dict) else {}
    systemd = defaults.get("systemd") if isinstance(defaults.get("systemd"), dict) else {}
    lines = [
        "[Unit]",
        f"Description=Run passive high-value {chain['label']} smart-contract monitor every 30 minutes",
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
        print(f"{chain['slug']}\t{chain['chainId']}\t{status}\t{chain['label']}")
    return 0


def command_probe(args: argparse.Namespace, config: dict[str, Any]) -> int:
    chains = selected_chains(config, args.include_disabled, args.only)
    sourcify_base = str(config.get("sourcifyBase") or "https://sourcify.dev/server")
    results = [probe_chain(chain, sourcify_base, args.timeout_seconds, args.retries) for chain in chains]
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for result in results:
            state = "ready" if result["ready"] else "blocked"
            print(
                f"{result['slug']}\t{result['chainId']}\t{state}\t"
                f"rpc={result.get('chosenRpc') or '-'}\tsourcify={result['sourcify'].get('ok')}"
            )
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

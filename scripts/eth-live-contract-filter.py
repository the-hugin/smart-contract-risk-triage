#!/usr/bin/env python3
"""Filter EVM contracts by passive liveness signals.

Signals:
- native ETH balance
- recent logs emitted by the contract
- balances of selected major ERC20 tokens

No transactions are sent. This only uses read-only JSON-RPC methods.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
BALANCE_OF_SELECTOR = "70a08231"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
MAJOR_TOKENS = {
    # address: (symbol, decimals, threshold_units)
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": ("WETH", 18, 0.01),
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": ("USDC", 6, 10.0),
    "0xdAC17F958D2ee523a2206206994597C13D831ec7": ("USDT", 6, 10.0),
    "0x6B175474E89094C44Da98b954EedeAC495271d0F": ("DAI", 18, 10.0),
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599": ("WBTC", 8, 0.001),
    "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84": ("stETH", 18, 0.01),
}


@dataclass(frozen=True)
class Target:
    chain_id: str
    address: str

    @property
    def key(self) -> str:
        return f"{self.chain_id}:{self.address.lower()}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter contracts by passive liveness.")
    parser.add_argument("--targets-file", required=True)
    parser.add_argument("--exclude-targets-file", action="append", default=[])
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--rpc-url", default=DEFAULT_RPC)
    parser.add_argument("--recent-blocks", type=int, default=10000)
    parser.add_argument("--eth-min-wei", type=int, default=10**15, help="Default: 0.001 ETH")
    parser.add_argument("--keep-limit", type=int, default=5000)
    parser.add_argument("--min-score", type=int, default=1)
    parser.add_argument("--require-threshold-balance", action="store_true")
    parser.add_argument("--require-activity", action="store_true")
    parser.add_argument(
        "--keep-native-without-activity",
        action="store_true",
        help="With --require-activity, still keep contracts whose native ETH balance meets --eth-min-wei.",
    )
    parser.add_argument("--min-recent-logs", type=int, default=1)
    parser.add_argument(
        "--balance-score-weight",
        action="store_true",
        help="Boost score by balance magnitude so high-balance inactive contracts are not lost by keep-limit.",
    )
    parser.add_argument("--balance-batch-size", type=int, default=100)
    parser.add_argument("--token-batch-size", type=int, default=80)
    parser.add_argument(
        "--token-threshold",
        action="append",
        default=[],
        metavar="SYMBOL=AMOUNT",
        help="Override major-token keep threshold, e.g. WETH=10 or USDC=16600.",
    )
    parser.add_argument(
        "--token",
        action="append",
        default=[],
        metavar="ADDRESS=SYMBOL:DECIMALS:THRESHOLD",
        help="Use a custom token balance filter. Replaces default Ethereum token list when provided.",
    )
    parser.add_argument("--logs-address-batch-size", type=int, default=5)
    parser.add_argument("--request-delay", type=float, default=0.05)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--skip-token-balances", action="store_true")
    parser.add_argument("--skip-logs", action="store_true")
    return parser.parse_args(argv)


def parse_token_specs(specs: list[str]) -> dict[str, tuple[str, int, float]]:
    tokens: dict[str, tuple[str, int, float]] = {}
    for raw in specs:
        if "=" not in raw:
            raise ValueError(
                f"invalid --token {raw!r}; expected ADDRESS=SYMBOL:DECIMALS:THRESHOLD"
            )
        address_raw, config_raw = raw.split("=", 1)
        address = address_raw.strip()
        if not ADDRESS_RE.match(address):
            raise ValueError(f"invalid token address in --token: {address!r}")
        parts = [part.strip() for part in config_raw.split(":")]
        if len(parts) != 3 or not parts[0]:
            raise ValueError(
                f"invalid --token {raw!r}; expected ADDRESS=SYMBOL:DECIMALS:THRESHOLD"
            )
        symbol = parts[0]
        try:
            decimals = int(parts[1])
            threshold = float(parts[2])
        except ValueError as exc:
            raise ValueError(f"invalid --token numeric config: {raw!r}") from exc
        if decimals < 0 or decimals > 36:
            raise ValueError(f"invalid token decimals in --token: {raw!r}")
        if not math.isfinite(threshold) or threshold < 0:
            raise ValueError(f"invalid token threshold in --token: {raw!r}")
        tokens[address] = (symbol, decimals, threshold)
    return tokens


def apply_token_threshold_overrides(overrides: list[str]) -> dict[str, tuple[str, int, float]]:
    updated = dict(MAJOR_TOKENS)
    by_symbol = {config[0].upper(): token for token, config in updated.items()}
    valid = ", ".join(sorted(by_symbol))
    for raw in overrides:
        if "=" not in raw:
            raise ValueError(f"invalid --token-threshold {raw!r}; expected SYMBOL=AMOUNT")
        symbol_raw, amount_raw = raw.split("=", 1)
        symbol = symbol_raw.strip().upper()
        if symbol not in by_symbol:
            raise ValueError(f"unknown token symbol {symbol!r}; valid: {valid}")
        try:
            amount = float(amount_raw)
        except ValueError as exc:
            raise ValueError(f"invalid threshold amount for {symbol}: {amount_raw!r}") from exc
        if not math.isfinite(amount) or amount < 0:
            raise ValueError(f"invalid threshold amount for {symbol}: {amount_raw!r}")
        token = by_symbol[symbol]
        original_symbol, decimals, _threshold = updated[token]
        updated[token] = (original_symbol, decimals, amount)
    return updated


def token_threshold_summary() -> dict[str, float]:
    return {
        symbol: threshold_units
        for _token, (symbol, _decimals, threshold_units) in MAJOR_TOKENS.items()
    }


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def read_targets(path: Path) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        chain_id = "1"
        address = line
        if "," in line:
            left, right = [part.strip() for part in line.split(",", 1)]
            if ADDRESS_RE.match(left):
                address, chain_id = left, right or "1"
            else:
                chain_id, address = left, right
        elif " " in line or "\t" in line:
            left, right = line.split()[:2]
            if ADDRESS_RE.match(left):
                address, chain_id = left, right
            else:
                chain_id, address = left, right
        if not ADDRESS_RE.match(address):
            raise ValueError(f"{path}:{line_no}: invalid address: {address}")
        target = Target(str(chain_id), address)
        if target.key not in seen:
            seen.add(target.key)
            targets.append(target)
    return targets


def read_target_keys(path: Path) -> set[str]:
    return {target.key for target in read_targets(path)}


def rpc_request(payload: Any, args: argparse.Namespace) -> Any:
    data = json.dumps(payload).encode("utf-8")
    last: Exception | None = None
    for attempt in range(args.retries + 1):
        req = urllib.request.Request(
            args.rpc_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "smart-contract-risk-triage-live-filter/0.2",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=args.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code in {400, 401, 403, 413}:
                raise
            if attempt >= args.retries:
                raise
            time.sleep(2**attempt)
        except Exception as exc:
            last = exc
            if attempt >= args.retries:
                raise
            time.sleep(2**attempt)
    raise RuntimeError(f"RPC failed: {last}")


def rpc_call(method: str, params: list[Any], args: argparse.Namespace) -> Any:
    response = rpc_request({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, args)
    if isinstance(response, dict) and "error" in response:
        raise RuntimeError(response["error"])
    return response["result"]


def rpc_batch(calls: list[tuple[str, list[Any], str]], args: argparse.Namespace) -> dict[str, Any]:
    payload = [
        {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
        for index, (method, params, _key) in enumerate(calls, 1)
    ]
    response = rpc_request(payload, args)
    if isinstance(response, dict) and "error" in response and len(calls) > 1:
        message = str(response.get("error", {}).get("message", "")).lower()
        if "batch" in message and ("too many" in message or "limit" in message):
            midpoint = len(calls) // 2
            result = rpc_batch(calls[:midpoint], args)
            result.update(rpc_batch(calls[midpoint:], args))
            return result
    if not isinstance(response, list):
        raise RuntimeError(f"unexpected batch response: {response}")
    by_id = {item.get("id"): item for item in response if isinstance(item, dict)}
    result: dict[str, Any] = {}
    for index, (_method, _params, key) in enumerate(calls, 1):
        item = by_id.get(index)
        if not item:
            result[key] = {"error": "missing response"}
        elif "error" in item:
            result[key] = {"error": item["error"]}
        else:
            result[key] = item.get("result")
    if args.request_delay > 0:
        time.sleep(args.request_delay)
    return result


def pad_address(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def balance_of_data(address: str) -> str:
    return "0x" + BALANCE_OF_SELECTOR + pad_address(address)


def hex_to_int(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        return 0
    if value == "0x":
        return 0
    return int(value, 16)


def get_native_balances(targets: list[Target], args: argparse.Namespace) -> dict[str, int]:
    balances: dict[str, int] = {}
    groups = list(chunks(targets, args.balance_batch_size))
    for index, group in enumerate(groups, 1):
        calls = [
            ("eth_getBalance", [target.address, "latest"], target.key)
            for target in group
        ]
        response = rpc_batch(calls, args)
        for key, value in response.items():
            balances[key] = hex_to_int(value)
        if index % 50 == 0 or index == len(groups):
            print(f"Native balance groups: {index}/{len(groups)}", flush=True)
    return balances


def get_token_balances(targets: list[Target], args: argparse.Namespace) -> dict[str, dict[str, int]]:
    token_balances: dict[str, dict[str, int]] = {target.key: {} for target in targets}
    for token, (symbol, _decimals, _threshold) in MAJOR_TOKENS.items():
        groups = list(chunks(targets, args.token_batch_size))
        for index, group in enumerate(groups, 1):
            calls = [
                (
                    "eth_call",
                    [{"to": token, "data": balance_of_data(target.address)}, "latest"],
                    target.key,
                )
                for target in group
            ]
            response = rpc_batch(calls, args)
            for key, value in response.items():
                if isinstance(value, dict) and "error" in value:
                    continue
                amount = hex_to_int(value)
                if amount:
                    token_balances[key][symbol] = amount
            if index % 100 == 0 or index == len(groups):
                print(f"Token {symbol} groups: {index}/{len(groups)}", flush=True)
    return token_balances


def get_log_counts_recursive(
    addresses: list[str],
    from_block: str,
    to_block: str,
    args: argparse.Namespace,
) -> tuple[Counter[str], list[dict[str, Any]]]:
    if not addresses:
        return Counter(), []
    try:
        result = rpc_call(
            "eth_getLogs",
            [{"fromBlock": from_block, "toBlock": to_block, "address": addresses}],
            args,
        )
        counts: Counter[str] = Counter()
        if isinstance(result, list):
            for row in result:
                if isinstance(row, dict) and isinstance(row.get("address"), str):
                    counts[row["address"].lower()] += 1
        if args.request_delay > 0:
            time.sleep(args.request_delay)
        return counts, []
    except Exception as exc:
        if len(addresses) > 1:
            midpoint = len(addresses) // 2
            left_counts, left_errors = get_log_counts_recursive(
                addresses[:midpoint], from_block, to_block, args
            )
            right_counts, right_errors = get_log_counts_recursive(
                addresses[midpoint:], from_block, to_block, args
            )
            left_counts.update(right_counts)
            return left_counts, left_errors + right_errors
        return Counter(), [{"address": addresses[0], "error": str(exc)}]


def get_recent_log_counts(targets: list[Target], args: argparse.Namespace) -> tuple[dict[str, int], list[dict[str, Any]], int, int]:
    latest = int(rpc_call("eth_blockNumber", [], args), 16)
    from_block_int = max(0, latest - args.recent_blocks)
    from_block = hex(from_block_int)
    to_block = hex(latest)
    counts_by_address: Counter[str] = Counter()
    errors: list[dict[str, Any]] = []
    groups = list(chunks(targets, args.logs_address_batch_size))
    for index, group in enumerate(groups, 1):
        counts, group_errors = get_log_counts_recursive(
            [target.address for target in group], from_block, to_block, args
        )
        counts_by_address.update(counts)
        errors.extend(group_errors)
        if index % 100 == 0 or index == len(groups):
            print(
                f"Log groups: {index}/{len(groups)} errors={len(errors)}",
                flush=True,
            )
    by_key = {target.key: counts_by_address[target.address.lower()] for target in targets}
    return by_key, errors, from_block_int, latest


def token_keep_reasons(token_balances: dict[str, int]) -> list[str]:
    reasons: list[str] = []
    for _token, (symbol, decimals, threshold_units) in MAJOR_TOKENS.items():
        amount = token_balances.get(symbol, 0)
        threshold = int(threshold_units * (10**decimals))
        if amount >= threshold:
            reasons.append(f"{symbol}_balance")
    return reasons


def magnitude_bonus(amount: int, threshold: int) -> int:
    if threshold <= 0 or amount < threshold:
        return 0
    multiple = amount / threshold
    if multiple < 10:
        return 0
    return min(20, int(math.log10(multiple)) * 2)


def has_threshold_balance(reasons: list[str]) -> bool:
    return any(reason.endswith("_balance") for reason in reasons)


def score_row(
    target: Target,
    native_balance: int,
    recent_logs: int,
    token_balances: dict[str, int],
    args: argparse.Namespace,
) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0
    has_native_threshold = native_balance >= args.eth_min_wei
    if has_native_threshold:
        reasons.append("native_eth_balance")
        native_score = 5
        if args.balance_score_weight:
            native_score += magnitude_bonus(native_balance, args.eth_min_wei)
        score += native_score
    if recent_logs > 0:
        reasons.append("recent_emitted_logs")
        score += min(10, 2 + recent_logs.bit_length())
    token_reasons = token_keep_reasons(token_balances)
    if token_reasons:
        reasons.extend(token_reasons)
        token_score = 6 + len(token_reasons)
        if args.balance_score_weight:
            token_bonus = 0
            for _token, (symbol, decimals, threshold_units) in MAJOR_TOKENS.items():
                amount = token_balances.get(symbol, 0)
                threshold = int(threshold_units * (10**decimals))
                token_bonus += magnitude_bonus(amount, threshold)
            token_score += min(30, token_bonus)
        score += token_score
    keep = bool(reasons) and score >= args.min_score
    if args.require_threshold_balance and not has_threshold_balance(reasons):
        keep = False
    native_activity_bypass = args.keep_native_without_activity and has_native_threshold
    if args.require_activity and recent_logs < args.min_recent_logs and not native_activity_bypass:
        keep = False
    return {
        "chainId": target.chain_id,
        "address": target.address,
        "score": score,
        "keep": keep,
        "reasons": reasons,
        "nativeBalanceWei": str(native_balance),
        "recentLogCount": recent_logs,
        "majorTokenBalances": {symbol: str(value) for symbol, value in token_balances.items()},
        "balanceScoreWeighted": bool(args.balance_score_weight),
        "nativeActivityBypass": bool(native_activity_bypass),
    }


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    global MAJOR_TOKENS
    try:
        if args.token:
            MAJOR_TOKENS = parse_token_specs(args.token)
        MAJOR_TOKENS = apply_token_threshold_overrides(args.token_threshold)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    targets = read_targets(Path(args.targets_file).resolve())
    exclude_keys: set[str] = set()
    for exclude_file in args.exclude_targets_file:
        exclude_keys.update(read_target_keys(Path(exclude_file).resolve()))
    original_target_count = len(targets)
    if exclude_keys:
        targets = [target for target in targets if target.key not in exclude_keys]
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Targets loaded: {original_target_count}", flush=True)
    if exclude_keys:
        print(
            f"Targets after exclusion: {len(targets)} "
            f"(excluded {original_target_count - len(targets)})",
            flush=True,
        )
    recent_log_counts = {target.key: 0 for target in targets}
    log_errors: list[dict[str, Any]] = []
    from_block = latest_block = 0
    balance_targets = targets
    if args.require_activity and not args.skip_logs:
        partial_log_counts, log_errors, from_block, latest_block = get_recent_log_counts(
            targets,
            args,
        )
        recent_log_counts.update(partial_log_counts)
        balance_targets = [
            target
            for target in targets
            if recent_log_counts.get(target.key, 0) >= args.min_recent_logs
        ]
        print(
            f"Activity prefilter targets: {len(balance_targets)}/{len(targets)}",
            flush=True,
        )
    native_balance_targets = targets if args.keep_native_without_activity else balance_targets
    if args.keep_native_without_activity and args.require_activity:
        print(
            f"Native balance targets: {len(native_balance_targets)}/{len(targets)}",
            flush=True,
        )
    native_balances = {target.key: 0 for target in targets}
    native_balances.update(get_native_balances(native_balance_targets, args))
    print("Native balance stage complete", flush=True)
    token_balances = {target.key: {} for target in targets}
    if not args.skip_token_balances:
        token_balances.update(get_token_balances(balance_targets, args))
    print("Token balance stage complete", flush=True)
    if args.skip_logs:
        pass
    elif args.require_activity:
        pass
    else:
        log_targets = targets
        if args.require_threshold_balance:
            log_targets = [
                target
                for target in targets
                if native_balances.get(target.key, 0) >= args.eth_min_wei
                or token_keep_reasons(token_balances.get(target.key, {}))
            ]
            print(
                f"Recent log prefilter targets: {len(log_targets)}/{len(targets)}",
                flush=True,
            )
        partial_log_counts, log_errors, from_block, latest_block = get_recent_log_counts(
            log_targets,
            args,
        )
        recent_log_counts = {target.key: 0 for target in targets}
        recent_log_counts.update(partial_log_counts)
    print("Recent logs stage complete", flush=True)

    rows = [
        score_row(
            target,
            native_balances.get(target.key, 0),
            recent_log_counts.get(target.key, 0),
            token_balances.get(target.key, {}),
            args,
        )
        for target in targets
    ]
    rows.sort(key=lambda row: (-int(row["score"]), row["address"].lower()))
    kept = [row for row in rows if row["keep"]]
    if args.keep_limit > 0:
        kept = kept[: args.keep_limit]

    write_jsonl(out_dir / "live-contract-scores.jsonl", rows)
    write_jsonl(out_dir / "live-contracts.jsonl", kept)
    write_jsonl(out_dir / "live-log-errors.jsonl", log_errors)
    (out_dir / "live-targets.txt").write_text(
        "".join(f"{row['chainId']},{row['address']}\n" for row in kept),
        encoding="utf-8",
        newline="\n",
    )

    reason_counts = Counter(reason for row in kept for reason in row["reasons"])
    summary = {
        "targetCount": len(targets),
        "inputTargetCount": original_target_count,
        "excludedTargetCount": original_target_count - len(targets),
        "keptCount": len(kept),
        "keepLimit": args.keep_limit,
        "minScore": args.min_score,
        "requireThresholdBalance": args.require_threshold_balance,
        "requireActivity": args.require_activity,
        "keepNativeWithoutActivity": args.keep_native_without_activity,
        "minRecentLogs": args.min_recent_logs,
        "rpcUrl": args.rpc_url,
        "recentBlocks": args.recent_blocks,
        "fromBlock": from_block,
        "latestBlock": latest_block,
        "ethMinWei": str(args.eth_min_wei),
        "majorTokenThresholds": token_threshold_summary(),
        "balanceScoreWeighted": bool(args.balance_score_weight),
        "reasonCounts": dict(reason_counts),
        "logErrorCount": len(log_errors),
        "skipTokenBalances": args.skip_token_balances,
        "skipLogs": args.skip_logs,
    }
    (out_dir / "live-filter-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )

    print(f"Targets: {len(targets)}")
    print(f"Kept: {len(kept)}")
    print(f"Reasons: {dict(reason_counts)}")
    print(f"Output: {out_dir}")
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

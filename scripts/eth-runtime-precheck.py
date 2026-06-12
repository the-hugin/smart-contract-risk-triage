#!/usr/bin/env python3
"""Read-only runtime state prechecks for EVM triage.

This sends no transactions. It only uses eth_getStorageAt and eth_call to
collect coarse state that helps downgrade common static false positives.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable


ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
GET_THRESHOLD_SELECTOR = "0xe75235b8"
SLOT0_SELECTOR = "0x3850c7bd"
OWNER_SELECTOR = "0x8da5cb5b"
START_TIMESTAMP_SELECTOR = "0xe6fd48bc"
LAST_CLAIM_TIMESTAMP_SELECTOR = "0x607af397"
INITIALIZED_SELECTOR = "0x158ef93e"
IS_INITIALIZED_SELECTOR = "0x392e53cd"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only runtime precheck state.")
    parser.add_argument("--targets-file", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rpc-url", default=DEFAULT_RPC)
    parser.add_argument("--batch-size", type=int, default=80)
    parser.add_argument("--request-delay", type=float, default=0.05)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--retries", type=int, default=4)
    return parser.parse_args(argv)


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def read_addresses(path: Path) -> list[str]:
    addresses: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s,]+", line)
        address = next((part for part in parts if ADDRESS_RE.match(part)), "")
        if not address:
            raise ValueError(f"{path}:{line_no}: invalid target line: {line}")
        normalized = address.lower()
        if normalized not in seen:
            seen.add(normalized)
            addresses.append(address)
    return addresses


def rpc_request(payload: Any, args: argparse.Namespace) -> Any:
    data = json.dumps(payload).encode("utf-8")
    last: Exception | None = None
    for attempt in range(args.retries + 1):
        req = urllib.request.Request(
            args.rpc_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "smart-contract-risk-triage-runtime-precheck/0.3",
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


def hex_to_int(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        return 0
    if value == "0x":
        return 0
    return int(value, 16)


def word_to_address(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    raw = value.removeprefix("0x").rjust(64, "0")
    address = "0x" + raw[-40:]
    if int(address, 16) == 0:
        return None
    return address


def collect_storage(addresses: list[str], args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {address.lower(): {"address": address} for address in addresses}
    slots = {
        "implementationSlot": EIP1967_IMPLEMENTATION_SLOT,
        "adminSlot": EIP1967_ADMIN_SLOT,
        "beaconSlot": EIP1967_BEACON_SLOT,
    }
    calls: list[tuple[str, list[Any], str]] = []
    for address in addresses:
        for label, slot in slots.items():
            calls.append(("eth_getStorageAt", [address, slot, "latest"], f"{address.lower()}:{label}"))
    groups = list(chunks(calls, args.batch_size))
    for index, group in enumerate(groups, 1):
        response = rpc_batch(group, args)
        for key, value in response.items():
            address, label = key.split(":", 1)
            decoded = word_to_address(value)
            if decoded:
                states[address][label] = decoded
        if index % 50 == 0 or index == len(groups):
            print(f"Storage precheck groups: {index}/{len(groups)}", flush=True)
    return states


def collect_calls(addresses: list[str], args: argparse.Namespace, states: dict[str, dict[str, Any]]) -> None:
    selectors = {
        "safeThreshold": GET_THRESHOLD_SELECTOR,
        "slot0": SLOT0_SELECTOR,
        "owner": OWNER_SELECTOR,
        "startTimestamp": START_TIMESTAMP_SELECTOR,
        "lastClaimTimestamp": LAST_CLAIM_TIMESTAMP_SELECTOR,
        "initialized": INITIALIZED_SELECTOR,
        "isInitialized": IS_INITIALIZED_SELECTOR,
    }
    calls: list[tuple[str, list[Any], str]] = []
    for address in addresses:
        for label, selector in selectors.items():
            calls.append(
                (
                    "eth_call",
                    [{"to": address, "data": selector}, "latest"],
                    f"{address.lower()}:{label}",
                )
            )
    groups = list(chunks(calls, args.batch_size))
    for index, group in enumerate(groups, 1):
        response = rpc_batch(group, args)
        for key, value in response.items():
            if isinstance(value, dict) and "error" in value:
                continue
            address, label = key.split(":", 1)
            if label == "safeThreshold":
                threshold = hex_to_int(value)
                if threshold > 0:
                    states[address]["safeThreshold"] = threshold
            elif label == "slot0":
                raw = value.removeprefix("0x") if isinstance(value, str) else ""
                if len(raw) >= 64:
                    sqrt_price = int(raw[:64], 16)
                    if sqrt_price > 0:
                        states[address]["poolInitialized"] = True
                        states[address]["slot0SqrtPriceX96"] = str(sqrt_price)
            elif label == "owner":
                owner = word_to_address(value)
                if owner:
                    states[address]["owner"] = owner
            elif label in {"startTimestamp", "lastClaimTimestamp"}:
                decoded = hex_to_int(value)
                if decoded > 0:
                    states[address][label] = decoded
            elif label in {"initialized", "isInitialized"}:
                decoded = hex_to_int(value)
                if decoded in {0, 1}:
                    states[address][label] = bool(decoded)
        if index % 50 == 0 or index == len(groups):
            print(f"Call precheck groups: {index}/{len(groups)}", flush=True)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    addresses = read_addresses(Path(args.targets_file).resolve())
    states = collect_storage(addresses, args)
    collect_calls(addresses, args, states)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Prechecked: {len(addresses)}")
    print(f"Output: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Passive Solana program monitor.

This is intentionally separate from the EVM monitor. It watches Solana's
upgradeable loader activity, records fresh deploy/upgrade/authority events, and
alerts only on higher-signal upgrade or authority-change events.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
PRIVATE_TELEGRAM_CHAT_RE = re.compile(r"^[1-9][0-9]*$")
PUBKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
ALERT_TRIAGE_CLASSES = {"review", "triage-now"}
ALERT_EVENT_TYPES = {"setAuthority", "setAuthorityChecked"}
MONITORED_EVENT_TYPES = {"deployWithMaxDataLen", "upgrade", "setAuthority", "setAuthorityChecked", "close"}
LAMPORTS_PER_SOL = 1_000_000_000
NATIVE_SOL_VALUE_THRESHOLD = 7.4
STABLE_VALUE_THRESHOLD = 500.0
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}
ED25519_P = 2**255 - 19
ED25519_D = (-121665 * pow(121666, -1, ED25519_P)) % ED25519_P
KNOWN_VALUE_MINTS = {
    "So11111111111111111111111111111111111111112": {
        "symbol": "WSOL",
        "threshold": NATIVE_SOL_VALUE_THRESHOLD,
    },
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
        "symbol": "USDC",
        "threshold": STABLE_VALUE_THRESHOLD,
    },
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY7j2X5X3Z8f9jJ": {
        "symbol": "USDT",
        "threshold": STABLE_VALUE_THRESHOLD,
    },
}


def base58_decode(value: str) -> bytes:
    number = 0
    for char in value:
        digit = BASE58_INDEX.get(char)
        if digit is None:
            raise ValueError("invalid base58 character")
        number = number * 58 + digit
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + raw


def is_solana_on_curve(address: str | None) -> bool | None:
    if not address or not PUBKEY_RE.fullmatch(address):
        return None
    try:
        compressed = base58_decode(address)
    except ValueError:
        return None
    if len(compressed) != 32:
        return None
    y = int.from_bytes(compressed, "little") & ((1 << 255) - 1)
    if y >= ED25519_P:
        return False
    y2 = (y * y) % ED25519_P
    denominator = (ED25519_D * y2 + 1) % ED25519_P
    if denominator == 0:
        return False
    x2 = ((y2 - 1) * pow(denominator, -1, ED25519_P)) % ED25519_P
    return x2 == 0 or pow(x2, (ED25519_P - 1) // 2, ED25519_P) == 1
KNOWN_SHARED_VALUE_ACCOUNTS = {
    "62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV": "pump_protocol_fee_recipient",
    "7VtfL8fvgNfhz17qKRMjzQEXgbdpnHHHQRh54R9jP2RJ": "pump_protocol_fee_recipient",
    "7hTckgnGnLQR6sdH7YkqFTAA7VwTfYFaZ6EhEsU3saCX": "pump_protocol_fee_recipient",
    "9rPYyANsfQZw3DnDmKE3YCQF5E8oD89UXoHn9JFEhJUz": "pump_protocol_fee_recipient",
    "AVmoTthdrX6tKt4nDjco2D775W2YK3sDhxPcMmzUAmTY": "pump_protocol_fee_recipient",
    "CebN5WGQ4jvEPvsVU4EoHEpgzq1VV7AbicfhtW4xC9iM": "pump_protocol_fee_recipient",
    "FWsW1xNtWscwNmKv6wVsU1iTzRN6wmmk3MjxRP5tT7hz": "pump_protocol_fee_recipient",
    "G5UZAVbAf46s7cKWoyKu8kYTip9DGTpbLZ2qa9Aq69dP": "pump_protocol_fee_recipient",
    "94qWNrtmfn42h3ZjUZwWvK1MEo9uVmmrBPd2hpNjYDjb": "pump_amm_protocol_fee_wsol_account",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive Solana program monitor.")
    parser.add_argument("--rpc-url", default="https://api.mainnet-beta.solana.com")
    parser.add_argument("--workspace", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--state-dir", default="runs/monitor-state/solana")
    parser.add_argument("--candidate-limit", type=int, default=25)
    parser.add_argument("--allow-cursor-skip", action="store_true")
    parser.add_argument("--seed-if-empty", action="store_true")
    parser.add_argument("--commitment", default="confirmed")
    parser.add_argument("--request-delay", type=float, default=0.6)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--transaction-batch-size", type=int, default=10)
    parser.add_argument("--max-error-rate", type=float, default=0.2)
    parser.add_argument("--delete-uninteresting", action="store_true")
    parser.add_argument("--cleanup-stale-days", type=float, default=2.0)
    parser.add_argument("--alert-deploys", action="store_true")
    parser.add_argument("--disable-value-map", action="store_true")
    parser.add_argument("--value-map-signature-limit", type=int, default=6)
    parser.add_argument("--value-map-max-transactions", type=int, default=3)
    parser.add_argument("--value-map-account-sample-limit", type=int, default=20)
    parser.add_argument("--telegram-alerts", action="store_true")
    parser.add_argument("--telegram-token-env", default="SMART_CONTRACT_ALERT_BOT_TOKEN")
    parser.add_argument("--telegram-chat-id-env", default="SMART_CONTRACT_ALERT_CHAT_ID")
    parser.add_argument("--telegram-alert-state")
    parser.add_argument("--telegram-alert-top", type=int, default=5)
    return parser.parse_args(argv)


def resolve_under(base: Path, raw: str | Path) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    resolved = path.resolve()
    return resolved


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
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def rpc_request(args: argparse.Namespace, method: str, params: list[Any]) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    last: Exception | None = None
    for attempt in range(args.retries + 1):
        request = urllib.request.Request(
            args.rpc_url,
            data=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "smart-contract-risk-triage-solana-monitor/0.2",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=args.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict) and data.get("error"):
                raise RuntimeError(json.dumps(data["error"], sort_keys=True))
            return data.get("result") if isinstance(data, dict) else None
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code == 429 and attempt < args.retries:
                retry_after = exc.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else min(30.0, 2.0 * (2**attempt))
                time.sleep(delay)
                continue
            if attempt >= args.retries:
                raise
        except Exception as exc:
            last = exc
            if attempt >= args.retries:
                raise
            time.sleep(min(30.0, 1.5 * (2**attempt)))
    raise RuntimeError(f"rpc request failed: {last}")


def rpc_batch_request(args: argparse.Namespace, calls: list[tuple[str, list[Any]]]) -> list[Any]:
    if not calls:
        return []
    payload = [
        {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
        for index, (method, params) in enumerate(calls)
    ]
    body = json.dumps(payload).encode("utf-8")
    last: Exception | None = None
    for attempt in range(args.retries + 1):
        request = urllib.request.Request(
            args.rpc_url,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "smart-contract-risk-triage-solana-monitor/0.2",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=args.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict) and data.get("error"):
                raise RuntimeError(json.dumps(data["error"], sort_keys=True))
            if not isinstance(data, list):
                raise RuntimeError("batch RPC response was not a list")
            by_id: dict[int, Any] = {}
            for row in data:
                if not isinstance(row, dict):
                    continue
                try:
                    row_id = int(row.get("id"))
                except (TypeError, ValueError):
                    continue
                if row.get("error"):
                    by_id[row_id] = {"_rpcError": row["error"]}
                else:
                    by_id[row_id] = row.get("result")
            return [by_id.get(index) for index in range(len(calls))]
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code == 429 and attempt < args.retries:
                retry_after = exc.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else min(30.0, 2.0 * (2**attempt))
                time.sleep(delay)
                continue
            if attempt >= args.retries:
                raise
        except Exception as exc:
            last = exc
            if attempt >= args.retries:
                raise
            time.sleep(min(30.0, 1.5 * (2**attempt)))
    raise RuntimeError(f"batch rpc request failed: {last}")


def fetch_new_signatures(args: argparse.Namespace, cursor_signature: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    total_limit = max(1, args.candidate_limit)
    newest_signature = ""
    newest_slot = None
    out: list[dict[str, Any]] = []
    cursor_reached = False
    before: str | None = None
    page_count = 0
    raw_fetched_count = 0
    while len(out) < total_limit:
        page_limit = min(1000, total_limit - len(out))
        options: dict[str, Any] = {"limit": page_limit, "commitment": args.commitment}
        if before:
            options["before"] = before
        rows = rpc_request(args, "getSignaturesForAddress", [BPF_UPGRADEABLE_LOADER, options])
        if not isinstance(rows, list) or not rows:
            break
        page_count += 1
        raw_fetched_count += len(rows)
        if not newest_signature and isinstance(rows[0], dict):
            newest_signature = str(rows[0].get("signature") or "")
            newest_slot = rows[0].get("slot")
        last_signature = ""
        for row in rows:
            if not isinstance(row, dict):
                continue
            signature = str(row.get("signature") or "")
            if not signature:
                continue
            last_signature = signature
            if cursor_signature and signature == cursor_signature:
                cursor_reached = True
                break
            out.append(row)
            if len(out) >= total_limit:
                break
        if cursor_reached or len(out) >= total_limit or len(rows) < page_limit or not last_signature:
            break
        before = last_signature
        time.sleep(args.request_delay)
    return out, {
        "cursorReached": cursor_reached,
        "newestSignature": newest_signature,
        "newestSlot": newest_slot,
        "candidateLimit": total_limit,
        "pageCount": page_count,
        "rawFetchedCount": raw_fetched_count,
        "fetchedCount": len(out),
    }


def loader_instructions(transaction: dict[str, Any]) -> list[dict[str, Any]]:
    message = ((transaction.get("transaction") or {}).get("message") or {})
    instructions = message.get("instructions") if isinstance(message, dict) else []
    out: list[dict[str, Any]] = []
    if isinstance(instructions, list):
        for instruction in instructions:
            if not isinstance(instruction, dict):
                continue
            if instruction.get("programId") == BPF_UPGRADEABLE_LOADER or instruction.get("program") == "bpf-upgradeable-loader":
                out.append(instruction)
    return out


def parsed_instruction_info(instruction: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    parsed = instruction.get("parsed")
    if not isinstance(parsed, dict):
        return "raw", {}
    event_type = str(parsed.get("type") or "unknown")
    info = parsed.get("info")
    return event_type, info if isinstance(info, dict) else {}


def get_account_value(args: argparse.Namespace, address: str) -> dict[str, Any] | None:
    if not address or not PUBKEY_RE.fullmatch(address):
        return None
    result = rpc_request(args, "getAccountInfo", [address, {"encoding": "jsonParsed", "commitment": args.commitment}])
    if not isinstance(result, dict):
        return None
    value = result.get("value")
    return value if isinstance(value, dict) else None


def parse_program_account(value: dict[str, Any] | None) -> dict[str, Any]:
    if not value:
        return {}
    data = value.get("data") if isinstance(value.get("data"), dict) else {}
    parsed = data.get("parsed") if isinstance(data.get("parsed"), dict) else {}
    info = parsed.get("info") if isinstance(parsed.get("info"), dict) else {}
    return {
        "owner": value.get("owner"),
        "executable": value.get("executable"),
        "lamports": value.get("lamports"),
        "space": value.get("space") or data.get("space"),
        "programDataAccount": info.get("programData"),
    }


def parse_program_data_account(value: dict[str, Any] | None) -> dict[str, Any]:
    if not value:
        return {}
    data = value.get("data") if isinstance(value.get("data"), dict) else {}
    parsed = data.get("parsed") if isinstance(data.get("parsed"), dict) else {}
    info = parsed.get("info") if isinstance(parsed.get("info"), dict) else {}
    return {
        "owner": value.get("owner"),
        "executable": value.get("executable"),
        "lamports": value.get("lamports"),
        "space": value.get("space") or data.get("space"),
        "authority": info.get("authority"),
        "slot": info.get("slot"),
    }


def account_key_at(transaction: dict[str, Any], index: int) -> dict[str, Any]:
    keys = (((transaction.get("transaction") or {}).get("message") or {}).get("accountKeys") or [])
    if not isinstance(keys, list) or index < 0 or index >= len(keys):
        return {}
    key = keys[index]
    if isinstance(key, dict):
        return key
    if isinstance(key, str):
        return {"pubkey": key}
    return {}


def account_pubkey_at(transaction: dict[str, Any], index: int) -> str:
    key = account_key_at(transaction, index)
    return str(key.get("pubkey") or "")


def account_key_by_pubkey(transaction: dict[str, Any], pubkey: str) -> dict[str, Any]:
    keys = (((transaction.get("transaction") or {}).get("message") or {}).get("accountKeys") or [])
    if not isinstance(keys, list) or not pubkey:
        return {}
    for key in keys:
        if isinstance(key, dict) and str(key.get("pubkey") or "") == pubkey:
            return key
        if isinstance(key, str) and key == pubkey:
            return {"pubkey": key}
    return {}


def token_ui_amount(row: dict[str, Any]) -> float:
    amount = row.get("uiTokenAmount") if isinstance(row.get("uiTokenAmount"), dict) else {}
    raw = amount.get("uiAmountString") or amount.get("uiAmount") or "0"
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def token_row_map(rows: Any) -> dict[tuple[int, str, str], dict[str, Any]]:
    out: dict[tuple[int, str, str], dict[str, Any]] = {}
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        account_index = row.get("accountIndex")
        try:
            index = int(account_index)
        except (TypeError, ValueError):
            continue
        mint = str(row.get("mint") or "")
        owner = str(row.get("owner") or "")
        out[(index, mint, owner)] = row
    return out


def summarize_transaction_value(transaction: dict[str, Any], account_sample_limit: int) -> dict[str, Any]:
    meta = transaction.get("meta") if isinstance(transaction.get("meta"), dict) else {}
    pre_balances = meta.get("preBalances") if isinstance(meta.get("preBalances"), list) else []
    post_balances = meta.get("postBalances") if isinstance(meta.get("postBalances"), list) else []
    max_account_sol = 0.0
    max_abs_delta_sol = 0.0
    max_writable_non_signer_sol = 0.0
    max_writable_non_signer_delta_sol = 0.0
    max_account_sol_account = ""
    max_abs_delta_sol_account = ""
    max_writable_non_signer_sol_account = ""
    max_writable_non_signer_delta_sol_account = ""
    writable_non_signer_accounts: list[str] = []
    for index, post in enumerate(post_balances):
        pre = pre_balances[index] if index < len(pre_balances) else 0
        try:
            pre_lamports = int(pre)
            post_lamports = int(post)
        except (TypeError, ValueError):
            continue
        post_sol = post_lamports / LAMPORTS_PER_SOL
        delta_sol = abs(post_lamports - pre_lamports) / LAMPORTS_PER_SOL
        key = account_key_at(transaction, index)
        pubkey = str(key.get("pubkey") or "")
        if post_sol > max_account_sol:
            max_account_sol = post_sol
            max_account_sol_account = pubkey
        if delta_sol > max_abs_delta_sol:
            max_abs_delta_sol = delta_sol
            max_abs_delta_sol_account = pubkey
        is_writable_non_signer = bool(pubkey and key.get("writable") and not key.get("signer"))
        if is_writable_non_signer:
            if post_sol > max_writable_non_signer_sol:
                max_writable_non_signer_sol = post_sol
                max_writable_non_signer_sol_account = pubkey
            if delta_sol > max_writable_non_signer_delta_sol:
                max_writable_non_signer_delta_sol = delta_sol
                max_writable_non_signer_delta_sol_account = pubkey
            if len(writable_non_signer_accounts) < account_sample_limit:
                writable_non_signer_accounts.append(pubkey)

    pre_tokens = token_row_map(meta.get("preTokenBalances"))
    post_tokens = token_row_map(meta.get("postTokenBalances"))
    token_accounts: dict[str, dict[str, Any]] = {}
    for key in sorted(set(pre_tokens) | set(post_tokens)):
        pre_row = pre_tokens.get(key, {})
        post_row = post_tokens.get(key, {})
        index, mint, owner = key
        pre_ui = token_ui_amount(pre_row)
        post_ui = token_ui_amount(post_row)
        account = account_pubkey_at(transaction, index)
        key = account_key_at(transaction, index)
        owner_key = account_key_by_pubkey(transaction, owner)
        token_accounts[f"{account}:{mint}:{owner}"] = {
            "account": account,
            "mint": mint,
            "owner": owner or None,
            "ownerIsOnCurve": is_solana_on_curve(owner) if owner else None,
            "ownerIsSigner": bool(owner_key.get("signer")),
            "ownerIsWritable": bool(owner_key.get("writable")),
            "accountIsWritable": bool(key.get("writable")),
            "accountIsSigner": bool(key.get("signer")),
            "preUiAmount": pre_ui,
            "postUiAmount": post_ui,
            "absDeltaUiAmount": abs(post_ui - pre_ui),
            "maxUiAmount": max(pre_ui, post_ui),
        }
    return {
        "maxAccountSol": max_account_sol,
        "maxAbsDeltaSol": max_abs_delta_sol,
        "maxWritableNonSignerSol": max_writable_non_signer_sol,
        "maxWritableNonSignerDeltaSol": max_writable_non_signer_delta_sol,
        "maxAccountSolAccount": max_account_sol_account or None,
        "maxAbsDeltaSolAccount": max_abs_delta_sol_account or None,
        "maxWritableNonSignerSolAccount": max_writable_non_signer_sol_account or None,
        "maxWritableNonSignerDeltaSolAccount": max_writable_non_signer_delta_sol_account or None,
        "writableNonSignerAccounts": writable_non_signer_accounts,
        "tokenAccounts": token_accounts,
    }


def merge_value_summary(base: dict[str, Any], row: dict[str, Any]) -> None:
    for amount_key, account_key in [
        ("maxAccountSol", "maxAccountSolAccount"),
        ("maxAbsDeltaSol", "maxAbsDeltaSolAccount"),
        ("maxWritableNonSignerSol", "maxWritableNonSignerSolAccount"),
        ("maxWritableNonSignerDeltaSol", "maxWritableNonSignerDeltaSolAccount"),
    ]:
        current = float(base.get(amount_key) or 0.0)
        incoming = float(row.get(amount_key) or 0.0)
        if incoming > current:
            base[amount_key] = incoming
            base[account_key] = row.get(account_key)
    seen_accounts = set(base.setdefault("writableNonSignerAccounts", []))
    for account in row.get("writableNonSignerAccounts") or []:
        if account not in seen_accounts:
            base["writableNonSignerAccounts"].append(account)
            seen_accounts.add(account)
    tokens = base.setdefault("tokenAccounts", {})
    for key, token in (row.get("tokenAccounts") or {}).items():
        current = tokens.get(key)
        if not current:
            tokens[key] = token
            continue
        current["maxUiAmount"] = max(float(current.get("maxUiAmount") or 0.0), float(token.get("maxUiAmount") or 0.0))
        current["absDeltaUiAmount"] = max(float(current.get("absDeltaUiAmount") or 0.0), float(token.get("absDeltaUiAmount") or 0.0))
        current["preUiAmount"] = token.get("preUiAmount", current.get("preUiAmount"))
        current["postUiAmount"] = token.get("postUiAmount", current.get("postUiAmount"))
        current["accountIsWritable"] = bool(current.get("accountIsWritable") or token.get("accountIsWritable"))
        current["accountIsSigner"] = bool(current.get("accountIsSigner") or token.get("accountIsSigner"))
        current["ownerIsSigner"] = bool(current.get("ownerIsSigner") or token.get("ownerIsSigner"))
        current["ownerIsWritable"] = bool(current.get("ownerIsWritable") or token.get("ownerIsWritable"))
        if current.get("ownerIsOnCurve") is None:
            current["ownerIsOnCurve"] = token.get("ownerIsOnCurve")


def classified_value_signals(summary: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    signals: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    token_account_addresses = {
        str(token.get("account") or "")
        for token in (summary.get("tokenAccounts") or {}).values()
        if token.get("account")
    }

    for amount_key, account_key, reason in [
        ("maxWritableNonSignerSol", "maxWritableNonSignerSolAccount", "writable_non_signer_balance"),
        ("maxWritableNonSignerDeltaSol", "maxWritableNonSignerDeltaSolAccount", "writable_non_signer_delta"),
    ]:
        amount = float(summary.get(amount_key) or 0.0)
        if amount < NATIVE_SOL_VALUE_THRESHOLD:
            continue
        signal = {
            "asset": "SOL",
            "reason": reason,
            "amount": summary[amount_key],
            "threshold": NATIVE_SOL_VALUE_THRESHOLD,
            "account": summary.get(account_key),
            "accountIsOnCurve": is_solana_on_curve(str(summary.get(account_key) or "")),
        }
        if str(signal.get("account") or "") in token_account_addresses:
            signal["suppressedReason"] = "spl_token_account_lamports"
            suppressed.append(signal)
        elif signal.get("accountIsOnCurve") is True:
            signal["suppressedReason"] = "native_account_on_curve"
            suppressed.append(signal)
        else:
            signal["confidence"] = "direct_or_unknown_native_account"
            signals.append(signal)

    for token in (summary.get("tokenAccounts") or {}).values():
        mint = str(token.get("mint") or "")
        known = KNOWN_VALUE_MINTS.get(mint)
        if not known:
            continue
        if not token.get("accountIsWritable") or token.get("accountIsSigner"):
            continue
        amount = float(token.get("maxUiAmount") or 0.0)
        if amount < float(known["threshold"]):
            continue
        signal = {
            "asset": known["symbol"],
            "mint": mint,
            "reason": "max_token_account_balance",
            "amount": amount,
            "threshold": known["threshold"],
            "account": token.get("account"),
            "owner": token.get("owner"),
            "ownerIsOnCurve": token.get("ownerIsOnCurve"),
            "ownerIsSigner": token.get("ownerIsSigner"),
        }
        if token.get("ownerIsSigner"):
            signal["suppressedReason"] = "token_owner_signed_transaction"
            suppressed.append(signal)
        elif token.get("ownerIsOnCurve") is True:
            signal["suppressedReason"] = "token_owner_on_curve"
            suppressed.append(signal)
        else:
            signal["confidence"] = "off_curve_token_owner_unverified"
            signals.append(signal)
    return signals, suppressed


def value_signals(summary: dict[str, Any]) -> list[dict[str, Any]]:
    signals, _ = classified_value_signals(summary)
    return signals


def trim_value_summary(summary: dict[str, Any], account_sample_limit: int) -> dict[str, Any]:
    tokens = list((summary.get("tokenAccounts") or {}).values())
    tokens.sort(key=lambda row: (float(row.get("maxUiAmount") or 0.0), float(row.get("absDeltaUiAmount") or 0.0)), reverse=True)
    signals, suppressed = classified_value_signals(summary)
    return {
        "source": "recent_program_transactions",
        "signatureSampleCount": summary.get("signatureSampleCount", 0),
        "transactionSampleCount": summary.get("transactionSampleCount", 0),
        "maxAccountSol": round(float(summary.get("maxAccountSol") or 0.0), 9),
        "maxAbsDeltaSol": round(float(summary.get("maxAbsDeltaSol") or 0.0), 9),
        "maxWritableNonSignerSol": round(float(summary.get("maxWritableNonSignerSol") or 0.0), 9),
        "maxWritableNonSignerDeltaSol": round(float(summary.get("maxWritableNonSignerDeltaSol") or 0.0), 9),
        "maxAccountSolAccount": summary.get("maxAccountSolAccount"),
        "maxAbsDeltaSolAccount": summary.get("maxAbsDeltaSolAccount"),
        "maxWritableNonSignerSolAccount": summary.get("maxWritableNonSignerSolAccount"),
        "maxWritableNonSignerDeltaSolAccount": summary.get("maxWritableNonSignerDeltaSolAccount"),
        "writableNonSignerAccounts": (summary.get("writableNonSignerAccounts") or [])[:account_sample_limit],
        "tokenAccounts": tokens[:account_sample_limit],
        "valueSignals": signals,
        "valueSignalCount": len(signals),
        "suppressedValueSignals": suppressed[:account_sample_limit],
        "suppressedValueSignalCount": len(suppressed),
        "errorCount": summary.get("errorCount", 0),
    }


def value_map_program(args: argparse.Namespace, program_id: str) -> dict[str, Any]:
    if not program_id or not PUBKEY_RE.fullmatch(program_id):
        return {"source": "recent_program_transactions", "disabled": True, "reason": "invalid_program_id"}
    summary: dict[str, Any] = {
        "signatureSampleCount": 0,
        "transactionSampleCount": 0,
        "maxAccountSol": 0.0,
        "maxAbsDeltaSol": 0.0,
        "maxWritableNonSignerSol": 0.0,
        "maxWritableNonSignerDeltaSol": 0.0,
        "maxAccountSolAccount": None,
        "maxAbsDeltaSolAccount": None,
        "maxWritableNonSignerSolAccount": None,
        "maxWritableNonSignerDeltaSolAccount": None,
        "writableNonSignerAccounts": [],
        "tokenAccounts": {},
        "errorCount": 0,
    }
    try:
        signatures = rpc_request(
            args,
            "getSignaturesForAddress",
            [
                program_id,
                {
                    "limit": max(1, min(args.value_map_signature_limit, 50)),
                    "commitment": args.commitment,
                },
            ],
        )
    except Exception:
        summary["errorCount"] = 1
        return trim_value_summary(summary, args.value_map_account_sample_limit)
    if not isinstance(signatures, list):
        signatures = []
    summary["signatureSampleCount"] = len(signatures)
    for row in signatures[: max(1, args.value_map_max_transactions)]:
        if not isinstance(row, dict) or not row.get("signature"):
            continue
        try:
            transaction = rpc_request(
                args,
                "getTransaction",
                [
                    row["signature"],
                    {
                        "encoding": "jsonParsed",
                        "commitment": args.commitment,
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
            )
            time.sleep(args.request_delay)
            if not isinstance(transaction, dict):
                continue
            tx_summary = summarize_transaction_value(transaction, args.value_map_account_sample_limit)
            merge_value_summary(summary, tx_summary)
            summary["transactionSampleCount"] += 1
        except Exception:
            summary["errorCount"] += 1
    return trim_value_summary(summary, args.value_map_account_sample_limit)


def apply_value_classification(event: dict[str, Any], args: argparse.Namespace) -> None:
    value_map = event.get("valueMap") if isinstance(event.get("valueMap"), dict) else {}
    signal_count = int(value_map.get("valueSignalCount") or 0)
    event_type = str(event.get("eventType") or "")
    if signal_count <= 0:
        return
    signals = value_map.get("valueSignals") if isinstance(value_map.get("valueSignals"), list) else []
    direct_signal_count = sum(
        1
        for signal in signals
        if isinstance(signal, dict) and signal.get("confidence") != "off_curve_token_owner_unverified"
    )
    if event_type == "upgrade":
        event["triageClass"] = "triage-now" if direct_signal_count else "watch"
        event["severity"] = "high" if direct_signal_count else "low"
        event["valueSignalStrength"] = "direct" if direct_signal_count else "weak_off_curve_token_context"
    elif str(event.get("triageClass") or "") == "watch":
        event["triageClass"] = "review"
        event["severity"] = "medium"
        event["valueSignalStrength"] = "direct" if direct_signal_count else "weak_off_curve_token_context"


def filter_value_map_for_event(event: dict[str, Any], value_map: dict[str, Any]) -> dict[str, Any]:
    excluded_accounts = {account: reason for account, reason in KNOWN_SHARED_VALUE_ACCOUNTS.items()}
    excluded_accounts.update(
        {
            str(event.get("programId") or ""): "upgraded_program_account",
            str(event.get("programDataAccount") or ""): "upgraded_program_data_account",
        }
    )
    excluded_accounts = {
        account: reason
        for account, reason in excluded_accounts.items()
        if account
    }
    if not excluded_accounts:
        return value_map
    signals = value_map.get("valueSignals") if isinstance(value_map.get("valueSignals"), list) else []
    kept: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        account = str(signal.get("account") or "")
        owner = str(signal.get("owner") or "")
        if account in excluded_accounts:
            excluded_signal = dict(signal)
            excluded_signal["excludedReason"] = excluded_accounts[account]
            excluded.append(excluded_signal)
        elif owner in excluded_accounts:
            excluded_signal = dict(signal)
            excluded_signal["excludedReason"] = excluded_accounts[owner]
            excluded.append(excluded_signal)
        else:
            kept.append(signal)
    if len(kept) == len(signals):
        return value_map
    filtered = dict(value_map)
    filtered["valueSignals"] = kept
    filtered["valueSignalCount"] = len(kept)
    filtered["excludedValueSignals"] = excluded[:5]
    filtered["excludedValueSignalCount"] = len(excluded)
    return filtered


def event_from_instruction(
    args: argparse.Namespace,
    signature_row: dict[str, Any],
    instruction: dict[str, Any],
    event_type: str | None = None,
    info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if event_type is None or info is None:
        event_type, info = parsed_instruction_info(instruction)
    program_id = str(info.get("programAccount") or info.get("programId") or "")
    program_data_account = str(info.get("programDataAccount") or "")
    authority = str(info.get("authority") or info.get("newAuthority") or "")
    if program_id:
        program_value = get_account_value(args, program_id)
        time.sleep(args.request_delay)
        program_account = parse_program_account(program_value)
        program_data_account = program_data_account or str(program_account.get("programDataAccount") or "")
    else:
        program_account = {}
    if program_data_account:
        program_data_value = get_account_value(args, program_data_account)
        time.sleep(args.request_delay)
        program_data = parse_program_data_account(program_data_value)
        authority = authority or str(program_data.get("authority") or "")
    else:
        program_data = {}
    triage_class = "watch"
    severity = "low"
    if event_type in {"setAuthority", "setAuthorityChecked"} and authority:
        triage_class = "review"
        severity = "medium"
    elif event_type == "deployWithMaxDataLen" and args.alert_deploys and authority:
        triage_class = "review"
        severity = "medium"
    return {
        "chain": "solana",
        "signature": signature_row.get("signature"),
        "slot": signature_row.get("slot"),
        "blockTime": signature_row.get("blockTime"),
        "eventType": event_type,
        "severity": severity,
        "triageClass": triage_class,
        "programId": program_id,
        "programDataAccount": program_data_account,
        "authority": authority or None,
        "programAccount": program_account,
        "programData": program_data,
        "loader": BPF_UPGRADEABLE_LOADER,
    }


def collect_events(args: argparse.Namespace, signature_rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    value_cache: dict[str, dict[str, Any]] = {}
    rows = [row for row in signature_rows if isinstance(row, dict) and row.get("signature")]
    batch_size = max(1, min(int(args.transaction_batch_size or 1), 50))
    transaction_fetch_count = 0
    transaction_batch_count = 0
    for offset in range(0, len(rows), batch_size):
        batch = rows[offset : offset + batch_size]
        calls: list[tuple[str, list[Any]]] = []
        for row in batch:
            calls.append(
                (
                    "getTransaction",
                    [
                        str(row.get("signature") or ""),
                        {
                            "encoding": "jsonParsed",
                            "commitment": args.commitment,
                            "maxSupportedTransactionVersion": 0,
                        },
                    ],
                )
            )
        try:
            transactions = rpc_batch_request(args, calls)
            transaction_batch_count += 1
            time.sleep(args.request_delay)
        except Exception as exc:
            for row in batch:
                errors.append({"signature": str(row.get("signature") or ""), "error": type(exc).__name__})
            continue
        for row, transaction in zip(batch, transactions):
            signature = str(row.get("signature") or "")
            transaction_fetch_count += 1
            if isinstance(transaction, dict) and transaction.get("_rpcError"):
                rpc_error = transaction.get("_rpcError") if isinstance(transaction.get("_rpcError"), dict) else {}
                errors.append(
                    {
                        "signature": signature,
                        "error": "rpc_error",
                        "code": str(rpc_error.get("code") or ""),
                        "message": str(rpc_error.get("message") or "")[:160],
                    }
                )
                continue
            if not isinstance(transaction, dict):
                continue
            for instruction in loader_instructions(transaction):
                event_type, info = parsed_instruction_info(instruction)
                counters[event_type] = counters.get(event_type, 0) + 1
                if event_type not in MONITORED_EVENT_TYPES:
                    continue
                try:
                    event = event_from_instruction(args, row, instruction, event_type, info)
                    program_id = str(event.get("programId") or "")
                    if program_id and not args.disable_value_map:
                        if program_id not in value_cache:
                            value_cache[program_id] = value_map_program(args, program_id)
                            time.sleep(args.request_delay)
                        event["valueMap"] = filter_value_map_for_event(event, value_cache[program_id])
                        apply_value_classification(event, args)
                    events.append(event)
                except Exception as exc:
                    errors.append({"signature": signature, "error": type(exc).__name__})
    return events, {
        "eventTypeCounts": counters,
        "errorCount": len(errors),
        "errors": errors[:10],
        "transactionBatchCount": transaction_batch_count,
        "transactionFetchCount": transaction_fetch_count,
        "valueMappedProgramCount": len(value_cache),
    }


def alert_key(row: dict[str, Any]) -> str:
    fields = [
        "solana",
        str(row.get("signature") or ""),
        str(row.get("eventType") or ""),
        str(row.get("programId") or ""),
        str(row.get("programDataAccount") or ""),
    ]
    return "|".join(fields)


def alert_rows(events: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    rows = [
        row
        for row in events
        if str(row.get("triageClass") or "") in ALERT_TRIAGE_CLASSES
        or str(row.get("eventType") or "") in ALERT_EVENT_TYPES
    ]
    return rows[: max(1, limit)]


def format_alert_message(rows: list[dict[str, Any]], event: dict[str, Any]) -> str:
    lines = [
        "Smart-contract alert",
        "Network: Solana",
        f"Status: {event.get('status')}",
        f"New loader signatures: {event.get('newSignatureCount')}; events: {event.get('eventCount')}",
        "Boundary: passive RPC/source triage only. No transaction or exploit was run.",
    ]
    if event.get("cursorSkipped"):
        lines.append("Cursor: previous cursor was outside the bounded window; older loader signatures were skipped.")
    for index, row in enumerate(rows, start=1):
        value_map = row.get("valueMap") if isinstance(row.get("valueMap"), dict) else {}
        value_signals = value_map.get("valueSignals") if isinstance(value_map.get("valueSignals"), list) else []
        value_text = "none"
        if value_signals:
            value_text = "; ".join(
                f"{signal.get('asset')} {signal.get('amount')} acct={str(signal.get('account') or '-')[:8]}"
                for signal in value_signals[:3]
            )
        lines.extend(
            [
                "",
                f"{index}. {row.get('triageClass')} / {row.get('severity')}",
                f"Event: {row.get('eventType')}",
                f"Program: {row.get('programId') or '-'}",
                f"ProgramData: {row.get('programDataAccount') or '-'}",
                f"Authority: {row.get('authority') or '-'}",
                f"Value signals: {value_text}",
                f"Signature: {row.get('signature')}",
            ]
        )
    return "\n".join(lines)


def send_telegram(token: str, chat_id: str, message: str, timeout_seconds: float) -> None:
    payload = {"chat_id": chat_id, "text": message, "disable_web_page_preview": True}
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
    events: list[dict[str, Any]],
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
    rows = alert_rows(events, args.telegram_alert_top)
    unsent = [row for row in rows if alert_key(row) not in sent]
    if not unsent:
        return {"status": "already_sent", "selected": len(rows), "sent": 0, "state": str(state_path)}
    message = format_alert_message(unsent, event)
    send_telegram(token, chat_id, message, args.timeout_seconds)
    now = utc_now()
    for row in unsent:
        sent[alert_key(row)] = {
            "sentAt": now,
            "signature": row.get("signature"),
            "eventType": row.get("eventType"),
            "programId": row.get("programId"),
        }
    state["sent"] = sent
    write_json(state_path, state)
    return {"status": "sent", "selected": len(rows), "sent": len(unsent), "state": str(state_path)}


def safe_delete_run_dir(run_dir: Path, runs_root: Path) -> None:
    resolved = run_dir.resolve()
    root = runs_root.resolve()
    if not str(resolved).startswith(str(root)) or resolved == root:
        raise RuntimeError(f"refusing to delete unsafe run dir: {resolved}")
    shutil.rmtree(resolved)


def cleanup_stale_runs(runs_root: Path, stale_days: float) -> list[str]:
    cutoff = time.time() - stale_days * 86400.0
    deleted: list[str] = []
    for path in runs_root.glob("solana-monitor-*"):
        if not path.is_dir() or (path / ".keep").exists():
            continue
        try:
            if path.stat().st_mtime < cutoff:
                safe_delete_run_dir(path, runs_root)
                deleted.append(str(path))
        except OSError:
            continue
    return deleted


def update_state(state_path: Path, state: dict[str, Any], signature: str, slot: Any) -> None:
    if signature:
        state["lastSeenSignature"] = signature
    if slot is not None:
        state["lastSeenSlot"] = slot
    state["updatedAt"] = utc_now()
    write_json(state_path, state)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace = Path(args.workspace).resolve()
    runs_root = workspace / "runs"
    state_dir = resolve_under(workspace, args.state_dir)
    state_path = state_dir / "state.json"
    latest_path = state_dir / "latest-summary.json"
    events_path = state_dir / "events.jsonl"
    lock_path = state_dir / "monitor.lock"
    state_dir.mkdir(parents=True, exist_ok=True)
    runs_root.mkdir(parents=True, exist_ok=True)
    if lock_path.exists():
        raise RuntimeError(f"monitor lock exists: {lock_path}")
    lock_path.write_text(str(time.time()), encoding="utf-8")
    run_dir: Path | None = None
    try:
        state = read_json(state_path)
        cursor = str(state.get("lastSeenSignature") or "") or None
        seed_mode = args.seed_if_empty and cursor is None
        original_limit = args.candidate_limit
        args.candidate_limit = 1 if seed_mode else args.candidate_limit
        signatures, fetch_meta = fetch_new_signatures(args, cursor)
        args.candidate_limit = original_limit
        event: dict[str, Any] = {
            "createdAt": utc_now(),
            "chain": "solana",
            "cursorBefore": cursor,
            "fetch": fetch_meta,
            "status": "started",
        }
        newest_signature = str(fetch_meta.get("newestSignature") or "")
        newest_slot = fetch_meta.get("newestSlot")
        if seed_mode:
            update_state(state_path, state, newest_signature, newest_slot)
            event["status"] = "seeded"
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 0
        cursor_missed = bool(cursor and not fetch_meta.get("cursorReached") and len(signatures) >= args.candidate_limit)
        if cursor_missed:
            fetch_meta["windowTruncated"] = True
        if cursor_missed and not args.allow_cursor_skip:
            event["status"] = "cursor_not_reached"
            event["actionRequired"] = "increase candidate limit before updating cursor"
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 1
        if not signatures:
            event["status"] = "no_new_loader_signatures"
            update_state(state_path, state, newest_signature, newest_slot)
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 0
        run_dir = runs_root / f"solana-monitor-{timestamp_slug()}-n{len(signatures)}"
        run_dir.mkdir(parents=True, exist_ok=False)
        (run_dir / "loader-signatures.jsonl").write_text("", encoding="utf-8")
        for row in signatures:
            append_jsonl(run_dir / "loader-signatures.jsonl", row)
        collected, collect_meta = collect_events(args, signatures)
        for row in collected:
            append_jsonl(run_dir / "program-events.jsonl", row)
        error_count = int(collect_meta.get("errorCount") or 0)
        transaction_fetch_count = int(collect_meta.get("transactionFetchCount") or 0)
        error_rate = (error_count / transaction_fetch_count) if transaction_fetch_count else 0.0
        if transaction_fetch_count and error_rate > max(0.0, float(args.max_error_rate)):
            event.update(
                {
                    "runDir": str(run_dir),
                    "newSignatureCount": len(signatures),
                    "eventCount": len(collected),
                    "interesting": False,
                    "collect": collect_meta,
                    "status": "rpc_error_rate_high",
                    "cursorSkipped": cursor_missed,
                    "errorRate": round(error_rate, 4),
                    "actionRequired": "reduce RPC rate/batch size or switch Solana RPC before updating cursor",
                }
            )
            (run_dir / ".keep").write_text(utc_now(), encoding="utf-8")
            event["deletedRunDir"] = False
            write_json(latest_path, event)
            append_jsonl(events_path, event)
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
            return 1
        interesting = any(str(row.get("triageClass") or "") in ALERT_TRIAGE_CLASSES for row in collected)
        event.update(
            {
                "runDir": str(run_dir),
                "newSignatureCount": len(signatures),
                "eventCount": len(collected),
                "interesting": interesting,
                "collect": collect_meta,
                "status": "interesting" if interesting else "uninteresting",
                "cursorSkipped": cursor_missed,
            }
        )
        if interesting:
            (run_dir / ".keep").write_text(utc_now(), encoding="utf-8")
            event["deletedRunDir"] = False
        elif args.delete_uninteresting:
            safe_delete_run_dir(run_dir, runs_root)
            event["deletedRunDir"] = True
        else:
            event["deletedRunDir"] = False
        try:
            event["telegramAlert"] = maybe_send_telegram_alert(args, state_dir, collected, event)
        except Exception as exc:
            event["telegramAlert"] = {"status": "failed", "error": str(exc)}
        update_state(state_path, state, newest_signature, newest_slot)
        event["cursorAfter"] = newest_signature
        event["staleDeleted"] = cleanup_stale_runs(runs_root, args.cleanup_stale_days)
        write_json(latest_path, event)
        append_jsonl(events_path, event)
        print(json.dumps(event, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        event = {"createdAt": utc_now(), "chain": "solana", "status": "failed", "error": str(exc), "runDir": str(run_dir) if run_dir else None}
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

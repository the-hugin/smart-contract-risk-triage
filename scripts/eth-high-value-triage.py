#!/usr/bin/env python3
"""Build a high-value triage view from a live-filtered EVM batch."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
MONEY_FUNCTION_RE = re.compile(
    r"(withdraw|redeem|claim|collect|payout|sweep|rescue|refund|release|"
    r"unstake|unbond|liquidate|borrow|repay|swap|sell|buy|settle|take)",
    re.I,
)
SOURCE_NOISE_MARKERS = (
    "/mock/",
    "/mocks/",
    "/test/",
    "/tests/",
    "/fixture/",
    "/fixtures/",
    "/example/",
    "/examples/",
)
DEPENDENCY_MARKERS = (
    "/@openzeppelin/",
    "/@uniswap/",
    "/dependencies/",
    "/openzeppelin/contracts/",
    "/openzeppelin-contracts/",
    "/solady/",
    "/solmate/",
    "/uniswap/v3-core/",
    "/v3-core/",
    "/v4-core/",
)
STANDARD_FILES = {
    "Address.sol",
    "AddressUpgradeable.sol",
    "Context.sol",
    "ContextUpgradeable.sol",
    "ECDSA.sol",
    "ERC20.sol",
    "ERC721.sol",
    "IERC20.sol",
    "IERC721.sol",
    "Initializable.sol",
    "Ownable.sol",
    "OwnableUpgradeable.sol",
    "Proxy.sol",
    "TransparentUpgradeableProxy.sol",
    "TransferHelper.sol",
}
SEVERITY_SCORE = {"critical": 100, "high": 70, "medium": 35, "low": 10, "info": 0}
CONFIDENCE_SCORE = {"high": 25, "medium": 12, "low": 0}
FALSE_POSITIVE_NOTES = {
    "scanner_non_runtime_warning",
    "scanner_precheck_consumed",
    "safe_threshold_nonzero",
    "pool_initialized",
    "proxy_implementation_slot_nonzero",
    "factory_gated_pair_initializer",
}
ACCESS_CONTROL_MODIFIER_RE = re.compile(
    r"\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernor|onlyGovernance|onlyFactory|"
    r"onlyTreasury|onlyOperator|onlyManager|onlyController|requiresAuth)\b"
)
WATCHLIST_NOTES = {
    "fixed_recipient_watchlist",
    "stream_initializer_watchlist",
}
ADDRESS_CONTROL_FUNCTION_RE = re.compile(
    r"(setTreasury|setFeeRecipient|setRecipient|setBeneficiary|setOracle|"
    r"configureOracle|setRouter|withdrawTo|drainNative|rescueTo)",
    re.I,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render high-value EVM triage report.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out-dir")
    parser.add_argument("--top", type=int, default=200)
    parser.add_argument(
        "--verdicts-file",
        default=str(Path(__file__).resolve().parents[1] / "reports" / "smart-contract-verdicts.jsonl"),
        help="Append-only manual feedback JSONL used to suppress old false positives or preserve confirmed candidates.",
    )
    parser.add_argument(
        "--validation-profile",
        choices=("aggressive", "standard"),
        default="aggressive",
        help="Post-detection validation strictness. aggressive runs every read-only/source downgrade gate.",
    )
    return parser.parse_args(argv)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip().lstrip("\ufeff")
        if not raw:
            continue
        rows.append(json.loads(raw))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def truncate_text(value: Any, limit: int = 2400) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def address_from_text(value: str) -> str | None:
    match = ADDRESS_RE.search(value)
    return match.group(0).lower() if match else None


def address_from_finding(finding: dict[str, Any]) -> str | None:
    path = str(finding.get("path") or "")
    normalized = path.replace("\\", "/")
    match = re.search(r"/sources/\d+/(0x[a-fA-F0-9]{40})(?:/|$)", f"/{normalized}")
    if match:
        return match.group(1).lower()
    return address_from_text(path)


def chain_from_finding_path(finding_path: str) -> str | None:
    normalized = finding_path.replace("\\", "/")
    match = re.search(r"/sources/(\d+)/(0x[a-fA-F0-9]{40})(?:/|$)", f"/{normalized}")
    return match.group(1) if match else None


def load_sourcify_meta(run_dir: Path) -> dict[str, dict[str, Any]]:
    meta_by_address: dict[str, dict[str, Any]] = {}
    for path in run_dir.rglob("_sourcify.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        address = str(data.get("address") or "").lower()
        if ADDRESS_RE.fullmatch(address):
            data["_metaPath"] = str(path)
            meta_by_address[address] = data
    return meta_by_address


def load_precheck(run_dir: Path) -> dict[str, dict[str, Any]]:
    path = run_dir / "runtime-precheck.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(address).lower(): state
        for address, state in data.items()
        if isinstance(address, str) and isinstance(state, dict)
    }


def normalize_verdict(value: Any) -> str:
    verdict = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "fp": "false-positive",
        "falsepositive": "false-positive",
        "invalid": "false-positive",
        "watch": "watch-only",
        "watchlist": "watch-only",
        "confirmed": "confirmed-candidate",
        "confirmed-candidate": "confirmed-candidate",
        "candidate": "confirmed-candidate",
    }
    return aliases.get(verdict, verdict)


def load_manual_verdicts(path: Path) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    normalized: list[dict[str, Any]] = []
    for row in rows:
        address = str(row.get("address") or "").lower()
        verdict = normalize_verdict(row.get("verdict"))
        if not address or verdict not in {"false-positive", "watch-only", "confirmed-candidate"}:
            continue
        copied = dict(row)
        copied["address"] = address
        copied["verdict"] = verdict
        copied["function"] = str(row.get("function") or "")
        copied["category"] = str(row.get("category") or "")
        copied["chain"] = str(row.get("chain") or "")
        normalized.append(copied)
    return normalized


def verdict_matches(row: dict[str, Any], address: str, function: str, category: str, chain: str | None) -> bool:
    if str(row.get("address") or "").lower() != address.lower():
        return False
    row_chain = str(row.get("chain") or "")
    if row_chain and chain and row_chain != chain:
        return False
    row_function = str(row.get("function") or "")
    if row_function and row_function != function:
        return False
    row_category = str(row.get("category") or "")
    if row_category and row_category != category:
        return False
    return True


def manual_verdict_for(
    verdicts: list[dict[str, Any]],
    address: str,
    function: str,
    category: str,
    chain: str | None,
) -> dict[str, Any] | None:
    matched: dict[str, Any] | None = None
    for row in verdicts:
        if verdict_matches(row, address, function, category, chain):
            matched = row
    return matched


def apply_manual_verdict(validation: dict[str, Any], row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return validation
    verdict = normalize_verdict(row.get("verdict"))
    if verdict == "confirmed-candidate":
        mapped = "candidate"
        result = "keep"
    elif verdict == "watch-only":
        mapped = "watch-only"
        result = "downgrade"
    elif verdict == "false-positive":
        mapped = "false-positive"
        result = "downgrade"
    else:
        return validation
    updated = dict(validation)
    tests = list(updated.get("tests") or [])
    reason = str(row.get("reason") or row.get("ruleHint") or "manual feedback verdict")
    tests.append(
        {
            "name": "manual_feedback_verdict",
            "result": result,
            "reason": reason,
        }
    )
    updated["verdict"] = mapped
    updated["tests"] = tests
    return updated


def source_path_from_finding(run_dir: Path, finding_path: str) -> Path | None:
    raw = Path(finding_path)
    candidates = [raw]
    workspace = run_dir.parent.parent
    candidates.append(workspace / finding_path)
    normalized = finding_path.replace("\\", "/")
    marker = f"runs/{run_dir.name}/"
    if marker in normalized:
        candidates.append(run_dir.parent / normalized.split("runs/", 1)[1])
    if "/sources/" in normalized:
        candidates.append(run_dir / "sources" / normalized.split("/sources/", 1)[1])
    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate
        except OSError:
            continue
    return None


def read_source_text(source_path: Path | None) -> str:
    if not source_path:
        return ""
    try:
        return source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def extract_function_block(source_text: str, function: str, line_no: Any) -> str:
    if not source_text or not function:
        return ""
    lines = source_text.splitlines()
    search_start = 0
    try:
        search_start = max(0, int(line_no) - 1)
    except (TypeError, ValueError):
        search_start = 0
    function_re = re.compile(rf"\bfunction\s+{re.escape(function)}\s*\(", re.I)
    start = None
    for index in range(search_start, -1, -1):
        if function_re.search(lines[index]):
            start = index
            break
    if start is None:
        for index, line in enumerate(lines):
            if function_re.search(line):
                start = index
                break
    if start is None:
        return ""

    block_lines: list[str] = []
    depth = 0
    opened = False
    for line in lines[start:]:
        block_lines.append(line)
        depth += line.count("{") - line.count("}")
        opened = opened or "{" in line
        if opened and depth <= 0:
            break
        if len(block_lines) > 220:
            break
    return "\n".join(block_lines)


def extract_named_function_block(source_text: str, function: str) -> str:
    return extract_function_block(source_text, function, 1)


def internal_calls(function_block: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"\b(_[A-Za-z][A-Za-z0-9_]*)\s*\(", function_block):
        name = match.group(1)
        if name.lower() in {"_msgsender", "_checkowner", "_checkrole"}:
            continue
        if name not in names:
            names.append(name)
    return names[:8]


def expanded_function_context(source_text: str, function_block: str) -> tuple[str, list[str]]:
    blocks = [function_block]
    resolved: list[str] = []
    for call_name in internal_calls(function_block):
        helper = extract_named_function_block(source_text, call_name)
        if helper:
            blocks.append(helper)
            resolved.append(call_name)
    return "\n\n".join(blocks), resolved


def function_params(function_block: str, function: str) -> str:
    match = re.search(rf"\bfunction\s+{re.escape(function)}\s*\((.*?)\)", function_block, re.I | re.S)
    return match.group(1) if match else ""


def has_address_param(function_block: str, function: str) -> bool:
    return bool(re.search(r"\baddress(?:\s+payable)?\b", function_params(function_block, function)))


def is_user_bound_claim_false_positive(finding: dict[str, Any], function_block: str) -> bool:
    function = str(finding.get("function") or "")
    if not function.lower().startswith("claim"):
        return False
    category = str(finding.get("category") or "")
    signal = str(finding.get("signal") or "")
    manual = str(finding.get("manual_check") or "")
    joined = f"{signal}\n{manual}".lower()
    if category in {"reentrancy", "accounting"}:
        return False
    if "call before accounting" in joined or "external call before accounting" in joined:
        return False
    if category != "access-control" and "no obvious access control" not in joined:
        return False
    params = function_params(function_block, function)
    if re.search(r"\baddress(?:\s+payable)?\b", params):
        return False
    block_lower = function_block.lower()
    if "msg.sender" not in block_lower:
        return False
    user_bound_call = re.search(r"\b\w+\s*\(\s*msg\.sender\b", function_block) or re.search(
        r"\b(safetransfer|transfer)\s*\(\s*msg\.sender\b",
        function_block,
        re.I,
    )
    return bool(user_bound_call)


def is_fixed_recipient_watchlist(finding: dict[str, Any], function_block: str) -> bool:
    function = str(finding.get("function") or "")
    if not MONEY_FUNCTION_RE.search(function):
        return False
    if has_address_param(function_block, function):
        return False
    block_lower = function_block.lower()
    fixed_targets = (
        "recipient",
        "returnaddress",
        "treasury",
        "feeRecipient".lower(),
        "beneficiary",
        "owner",
    )
    if "msg.sender" in block_lower and re.search(r"\b(safetransfer|transfer)\s*\(\s*msg\.sender\b", function_block, re.I):
        return False
    return any(
        re.search(rf"\b(safetransfer|transfer|send|call)\s*\(\s*{target}\b", function_block, re.I)
        or re.search(rf"\b{target}\s*\.\s*(transfer|send|call)\b", function_block, re.I)
        for target in fixed_targets
    )


def is_stream_initializer_watchlist(
    finding: dict[str, Any],
    function_block: str,
    precheck: dict[str, Any] | None,
) -> bool:
    if str(finding.get("function") or "").lower() != "initialize":
        return False
    if str(finding.get("category") or "") != "upgradeability":
        return False
    if precheck and int(precheck.get("startTimestamp") or 0) > 0:
        return True
    block_lower = function_block.lower()
    state_markers = (
        "starttimestamp",
        "lastclaimtimestamp",
        "streamstate.started",
        "state =",
        "block.timestamp",
    )
    return sum(1 for marker in state_markers if marker in block_lower) >= 2


def is_address_control_candidate(finding: dict[str, Any], function_block: str) -> bool:
    category = str(finding.get("category") or "")
    if category not in {"address-control", "access-control", "upgradeability"}:
        return False
    function = str(finding.get("function") or "")
    if ADDRESS_CONTROL_FUNCTION_RE.search(function) and has_address_param(function_block, function):
        return True
    if category in {"address-control", "access-control"} and finding.get("funds_at_risk") and has_address_param(
        function_block, function
    ):
        return True
    block_lower = function_block.lower()
    return bool(
        has_address_param(function_block, function)
        and (
            re.search(r"\b\w+\s*=\s*\w+", function_block)
            or ".transfer(" in block_lower
            or ".safetransfer(" in block_lower
            or ".call{" in block_lower
        )
    )


def compact_source(value: str) -> str:
    return re.sub(r"\s+", "", value.lower())


def has_inline_access_guard(function_block: str) -> bool:
    compact = compact_source(function_block)
    guarded_patterns = (
        "require(msg.sender==owner",
        "require(_msgsender()==owner",
        "require(msg.sender==admin",
        "require(msg.sender==governance",
        "require(msg.sender==manager",
        "require(msg.sender==controller",
        "require(msg.sender==treasury",
        "require(owner()==msg.sender",
        "require(hasrole(",
        "_checkrole(",
        "_checkowner()",
        "onlyowner()",
    )
    if any(pattern in compact for pattern in guarded_patterns):
        return True
    return bool(
        re.search(
            r"(require|if)\s*\([^;]*(msg\.sender|_msgSender\(\))[^;]*(owner|admin|governance|manager|controller|operator)",
            function_block,
            flags=re.I | re.S,
        )
    )


def transfer_line_index(function_block: str) -> int | None:
    transfer_re = re.compile(r"(\.call\s*(\{|<|\()|\.send\s*\(|\.transfer\s*\(|safeTransfer|transferFrom)", re.I)
    for index, line in enumerate(function_block.splitlines()):
        if transfer_re.search(line):
            return index
    return None


def accounting_write_indexes(function_block: str) -> list[int]:
    write_re = re.compile(
        r"\b("
        r"balances?|shares?|assets?|totalSupply|supply|debt|credit|positions?|"
        r"liquidity|rewards?|claimable|pending|owed|accounting|claimed|rewardDebt"
        r")\b[^;\n]*(=|\+=|-=|\+\+|--)",
        re.I,
    )
    return [index for index, line in enumerate(function_block.splitlines()) if write_re.search(line)]


def accounting_before_transfer(function_block: str) -> bool:
    transfer_index = transfer_line_index(function_block)
    if transfer_index is None:
        return False
    return any(index < transfer_index for index in accounting_write_indexes(function_block))


def transfer_before_accounting(function_block: str) -> bool:
    transfer_index = transfer_line_index(function_block)
    if transfer_index is None:
        return False
    return any(index > transfer_index for index in accounting_write_indexes(function_block))


def has_nonreentrant_guard(function_block: str) -> bool:
    return bool(re.search(r"\b(nonReentrant|reentrancyGuard|locked|noReentrant)\b", function_block, flags=re.I))


def is_cost_bound_user_redemption(function_block: str) -> bool:
    compact = compact_source(function_block)
    pulls_from_caller = (
        "transferfrom(msg.sender,address(this)" in compact
        or "safetransferfrom(msg.sender,address(this)" in compact
        or "transferfrom(msg.sender," in compact
        or "safetransferfrom(msg.sender," in compact
        or "require(msg.value" in compact
        or "if(msg.value" in compact
    )
    pays_caller = (
        ".transfer(msg.sender," in compact
        or ".safetransfer(msg.sender," in compact
        or ".call{value:" in compact and "msg.sender" in compact
    )
    burns_or_debits = any(
        marker in compact
        for marker in (
            "burnfrom(msg.sender",
            "burn(msg.sender",
            "balances[msg.sender]-=",
            "shares[msg.sender]-=",
            "rewarddebt",
            "claimed[msg.sender]",
        )
    )
    return pulls_from_caller and pays_caller and burns_or_debits


def is_keeper_settlement_watchlist(function: str, function_block: str) -> bool:
    if not re.search(r"(settle|cleanup|expire|finalize|execute)", function, flags=re.I):
        return False
    compact = compact_source(function_block)
    pays_non_caller = any(
        marker in compact
        for marker in (
            ".transfer(order.owner,",
            ".safetransfer(order.owner,",
            ".transfer(seller,",
            ".safetransfer(seller,",
            ".transfer(winner,",
            ".safetransfer(winner,",
            ".transfer(beneficiary,",
            ".safetransfer(beneficiary,",
        )
    )
    has_state_gate = any(
        marker in compact
        for marker in ("expired", "auction", "settled", "status=", "block.timestamp", "deadline")
    )
    caller_profit = ".transfer(msg.sender," in compact or ".safetransfer(msg.sender," in compact
    return pays_non_caller and has_state_gate and not caller_profit


def is_guarded_signature_flow(function_block: str) -> bool:
    compact = compact_source(function_block)
    if "ecrecover(" not in compact and ".recover(" not in compact:
        return False
    has_domain = any(marker in compact for marker in ("domainseparator", "chainid", "address(this)", "_hashrestricteddomain"))
    has_expiry = "deadline" in compact or "expiry" in compact or "expiration" in compact
    has_replay_guard = any(marker in compact for marker in ("nonce", "used", "filled", "cancelled", "executed"))
    has_signer_check = "require(" in compact and any(marker in compact for marker in ("signer", "owner", "hasrole"))
    return has_domain and has_expiry and has_replay_guard and has_signer_check


def positive_candidate_verdict(
    finding: dict[str, Any],
    function_block: str,
) -> tuple[str, dict[str, str]] | None:
    category = str(finding.get("category") or "")
    function = str(finding.get("function") or "")
    compact = compact_source(function_block)
    if category == "reentrancy" and transfer_before_accounting(function_block) and not has_nonreentrant_guard(function_block):
        attacker_receiver = (
            ".call{value:" in compact and "msg.sender" in compact
        ) or ".transfer(msg.sender," in compact or ".safetransfer(msg.sender," in compact
        if attacker_receiver:
            return (
                "candidate",
                {
                    "name": "positive_reentrancy_profit_path",
                    "result": "keep",
                    "reason": "external transfer to caller appears before accounting without a reentrancy guard",
                },
            )
    if category in {"access-control", "address-control"} and has_address_param(function_block, function):
        caller_recipient = bool(
            re.search(r"\b(transfer|safeTransfer)\s*\(\s*(to|recipient|receiver|beneficiary)\b", function_block, re.I)
            or re.search(r"\b(to|recipient|receiver|beneficiary)\s*\.\s*(transfer|send|call)\b", function_block, re.I)
        )
        if caller_recipient:
            return (
                "candidate",
                {
                    "name": "positive_caller_controlled_recipient",
                    "result": "keep",
                    "reason": "public money path can route value to an address parameter",
                },
            )
    if category in {"upgradeability", "address-control"} and has_address_param(function_block, function):
        critical_names = ("treasury", "oracle", "router", "implementation", "admin", "owner", "recipient")
        if any(re.search(rf"\b{name}\s*=", function_block, flags=re.I) for name in critical_names):
            return (
                "candidate",
                {
                    "name": "positive_critical_address_substitution",
                    "result": "keep",
                    "reason": "public function can replace a critical address/control variable",
                },
            )
    return None


def risk_class(finding: dict[str, Any]) -> str:
    category = str(finding.get("category") or "")
    function = str(finding.get("function") or "")
    if category == "reentrancy":
        return "money path / reentrancy"
    if category in {"upgradeability", "address-control"}:
        return "control path / address substitution"
    if MONEY_FUNCTION_RE.search(function):
        return "money path"
    return category or "unknown"


def first_keep_test(validation: dict[str, Any]) -> dict[str, str]:
    tests = validation.get("tests") if isinstance(validation.get("tests"), list) else []
    for item in tests:
        if isinstance(item, dict) and item.get("result") == "keep":
            return {str(key): str(value) for key, value in item.items()}
    for item in tests:
        if isinstance(item, dict):
            return {str(key): str(value) for key, value in item.items()}
    return {"name": "candidate", "result": "keep", "reason": "post-validation candidate"}


def next_manual_check(finding: dict[str, Any], validation: dict[str, Any]) -> str:
    gate = first_keep_test(validation).get("name", "")
    category = str(finding.get("category") or "")
    if gate == "positive_reentrancy_profit_path":
        return "Confirm attacker-controlled receiver can reenter and value/accounting delta is repeatable."
    if gate == "positive_caller_controlled_recipient":
        return "Confirm the address parameter is caller-controlled and routes live token/native value."
    if gate == "positive_critical_address_substitution":
        return "Confirm caller can change the live critical address and then route value/control through it."
    if category == "signature-replay":
        return "Confirm missing nonce/deadline/domain/signer binding against the exact runtime source."
    return "Open the evidence pack source context and verify caller profit or unauthorized control."


def candidate_evidence_pack(
    row: dict[str, Any],
    finding: dict[str, Any],
    source_text: str,
    source_path: Path | None,
    live: dict[str, Any] | None,
    meta: dict[str, Any],
    precheck: dict[str, Any] | None,
) -> dict[str, Any] | None:
    validation = row.get("validation") if isinstance(row.get("validation"), dict) else {}
    if validation.get("verdict") != "candidate":
        return None
    function = str(finding.get("function") or "")
    block = extract_function_block(source_text, function, finding.get("line"))
    context, helpers = expanded_function_context(source_text, block) if block else ("", [])
    compilation = meta.get("compilation") if isinstance(meta.get("compilation"), dict) else {}
    return {
        "address": row.get("address"),
        "riskClass": risk_class(finding),
        "positiveGate": first_keep_test(validation),
        "nextManualCheck": next_manual_check(finding, validation),
        "source": {
            "path": str(source_path or finding.get("path") or ""),
            "line": finding.get("line"),
            "function": function,
            "resolvedHelpers": helpers,
            "snippet": truncate_text(context, 3200),
        },
        "live": live or {},
        "runtime": {
            "precheck": precheck or {},
            "runtimeMatch": meta.get("runtimeMatch"),
            "match": meta.get("match"),
            "fqn": compilation.get("fullyQualifiedName"),
            "proxyResolution": meta.get("proxyResolution"),
        },
        "scanner": {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "category": finding.get("category"),
            "signal": finding.get("signal"),
            "manualCheck": finding.get("manual_check"),
            "evidence": finding.get("evidence"),
        },
    }


def detector_suppression_verdict(
    finding: dict[str, Any],
    function_block: str,
    source_text: str,
    validation_profile: str = "aggressive",
) -> tuple[str, dict[str, str]] | None:
    function = str(finding.get("function") or "").lower()
    category = str(finding.get("category") or "")
    compact_block = compact_source(function_block)
    compact_file = compact_source(source_text)
    header = function_block.split("{", 1)[0]

    if category == "access-control" and has_inline_access_guard(function_block):
        return (
            "false-positive",
            {
                "name": "inline_access_guard_present",
                "result": "downgrade",
                "reason": "function body checks caller against owner/admin/role before the money path",
            },
        )

    if category in {"reentrancy", "dos-locked-funds"} and ACCESS_CONTROL_MODIFIER_RE.search(header):
        return (
            "false-positive",
            {
                "name": "access_guarded_money_ordering",
                "result": "downgrade",
                "reason": "money-path ordering is behind an explicit access-control modifier",
            },
        )

    if validation_profile == "aggressive" and category == "reentrancy":
        if has_nonreentrant_guard(function_block):
            return (
                "watch-only",
                {
                    "name": "nonreentrant_reentrancy_guard",
                    "result": "downgrade",
                    "reason": "function has a reentrancy guard; keep as watch-only unless another candidate test fires",
                },
            )
        if accounting_before_transfer(function_block) and not transfer_before_accounting(function_block):
            return (
                "false-positive",
                {
                    "name": "accounting_before_external_transfer",
                    "result": "downgrade",
                    "reason": "accounting write appears before the external transfer",
                },
            )

    if validation_profile == "aggressive" and is_cost_bound_user_redemption(function_block):
        return (
            "false-positive",
            {
                "name": "cost_bound_user_redemption",
                "result": "downgrade",
                "reason": "caller must fund/burn/debit value before receiving the payout",
            },
        )

    if validation_profile == "aggressive" and is_keeper_settlement_watchlist(function, function_block):
        return (
            "watch-only",
            {
                "name": "keeper_settlement_non_caller_payout",
                "result": "downgrade",
                "reason": "permissionless settlement pays seller/winner/beneficiary rather than the caller",
            },
        )

    if validation_profile == "aggressive" and category == "signature-replay" and is_guarded_signature_flow(function_block):
        return (
            "false-positive",
            {
                "name": "guarded_signature_flow",
                "result": "downgrade",
                "reason": "signature path includes domain, expiry, replay, and signer checks",
            },
        )

    if function.startswith("claim") and "merkleproof.verify" in compact_block and "merkleroot" in compact_block:
        if ("_setclaimed(index)" in compact_block or "claimedbitmap" in compact_block) and (
            ".safetransfer(account," in compact_block or ".transfer(account," in compact_block
        ):
            return (
                "false-positive",
                {
                    "name": "merkle_claim_leaf_bound",
                    "result": "downgrade",
                    "reason": "claim requires Merkle proof, marks claimed state, and pays the leaf account",
                },
            )

    if ("cleanup" in function or "expired" in function) and "expired" in compact_block and "order.owner" in compact_block:
        if "status=orderstatus.expired" in compact_block or "status=expired" in compact_block:
            return (
                "watch-only",
                {
                    "name": "expired_order_keeper_cleanup",
                    "result": "downgrade",
                    "reason": "permissionless cleanup refunds expired order value to order.owner",
                },
            )

    token_owner_claim = False
    if "claim" in function:
        owner_lookup = "ownerof(tokenid)" in compact_block or "_ownerof(tokenid)" in compact_block
        owner_payout = (
            ".call{value:" in compact_block and ("owner" in compact_block or "owneraddr" in compact_block)
        ) or any(
            marker in compact_block
            for marker in (
                ".safetransfer(owner",
                ".transfer(owner",
                ".safetransfer(owneraddr",
                ".transfer(owneraddr",
            )
        )
        debt_update = any(marker in compact_block for marker in ("_setfeedebt(", "rewarddebt", "claimed"))
        token_owner_claim = owner_lookup and owner_payout and debt_update
        token_owner_claim = token_owner_claim or (
            "_claimone(tokenid)" in compact_block
            and ("_ownerof(tokenid)" in compact_file or "ownerof(tokenid)" in compact_file)
            and any(marker in compact_file for marker in ("_setfeedebt(", "rewarddebt", "claimed"))
        )
    if token_owner_claim:
        return (
            "false-positive",
            {
                "name": "token_owner_bound_claim",
                "result": "downgrade",
                "reason": "claim path pays the current token owner and updates per-token accounting",
            },
        )

    if "sweep" in function and "bountytreasury" in compact_block:
        if ("owedscaled" in compact_block or "pendingundistributed" in compact_block) and (
            "deposit{value:" in compact_block or ".call{value:" in compact_block or ".transfer(" in compact_block
        ):
            return (
                "watch-only",
                {
                    "name": "reserved_dust_sweep",
                    "result": "downgrade",
                    "reason": "sweep is reserve-bounded and routes dust to a fixed treasury",
                },
            )

    if "claim" in function and "tokenids.length" in compact_block:
        owns_token_check = (
            "ownerof(tokenid)!=msg.sender" in compact_block
            or "ownerof(tokenid)==msg.sender" in compact_block
            or "_ownerof(tokenid)!=msg.sender" in compact_block
            or "_ownerof(tokenid)==msg.sender" in compact_block
        )
        caller_payout = (
            "_pay(msg.sender" in compact_block
            or ".transfer(msg.sender," in compact_block
            or ".safetransfer(msg.sender," in compact_block
        )
        if owns_token_check and caller_payout and any(
            marker in compact_block for marker in ("rewarddebt", "claimed", "pending")
        ):
            return (
                "false-positive",
                {
                    "name": "caller_owned_token_claim_loop",
                    "result": "downgrade",
                    "reason": "loop is bounded to caller-owned token IDs with per-token accounting",
                },
            )

    return None


def validation_tests(
    finding: dict[str, Any],
    notes: list[str],
    source_text: str,
    precheck: dict[str, Any] | None = None,
    validation_profile: str = "aggressive",
) -> dict[str, Any]:
    tests: list[dict[str, str]] = []
    hard_false_positive = sorted(FALSE_POSITIVE_NOTES.intersection(notes))
    if hard_false_positive:
        tests.append(
            {
                "name": "known_false_positive_precheck",
                "result": "downgrade",
                "reason": ",".join(hard_false_positive),
            }
        )
        return {"verdict": "false-positive", "tests": tests}

    function = str(finding.get("function") or "")
    block = extract_function_block(source_text, function, finding.get("line"))
    resolved_helpers: list[str] = []
    if block:
        context_block, resolved_helpers = expanded_function_context(source_text, block)
        if resolved_helpers:
            tests.append(
                {
                    "name": "interprocedural_source_context",
                    "result": "checked",
                    "reason": "resolved internal helpers: " + ",".join(resolved_helpers),
                }
            )
        else:
            context_block = block
        suppression = detector_suppression_verdict(finding, context_block, source_text, validation_profile)
        if suppression:
            verdict, test = suppression
            tests.append(test)
            return {"verdict": verdict, "tests": tests}
        positive = positive_candidate_verdict(finding, context_block)
        if positive:
            verdict, test = positive
            tests.append(test)
            return {"verdict": verdict, "tests": tests}

    if block and is_address_control_candidate(finding, context_block):
        tests.append(
            {
                "name": "address_control_money_path",
                "result": "keep",
                "reason": "address parameter can affect value recipient or trusted destination",
            }
        )
        return {"verdict": "candidate", "tests": tests}

    if block and is_stream_initializer_watchlist(finding, context_block, precheck):
        tests.append(
            {
                "name": "stream_initializer_state_only",
                "result": "downgrade",
                "reason": "initializer appears to set stream/timestamp state rather than attacker-owned payout",
            }
        )
        return {"verdict": "watch-only", "tests": tests}

    if block and str(finding.get("category") or "") == "access-control":
        header = context_block.split("{", 1)[0]
        if ACCESS_CONTROL_MODIFIER_RE.search(header):
            tests.append(
                {
                    "name": "access_modifier_present",
                    "result": "downgrade",
                    "reason": "function header contains an explicit access-control modifier",
                }
            )
            return {"verdict": "false-positive", "tests": tests}

    if block and is_user_bound_claim_false_positive(finding, context_block):
        tests.append(
            {
                "name": "user_bound_claim_recipient",
                "result": "downgrade",
                "reason": "claim path binds the beneficiary to msg.sender and has no address recipient parameter",
            }
        )
        return {"verdict": "false-positive", "tests": tests}

    if block and is_fixed_recipient_watchlist(finding, context_block):
        tests.append(
            {
                "name": "fixed_recipient_money_path",
                "result": "downgrade",
                "reason": "public money path pays a fixed stored recipient instead of caller-controlled address",
            }
        )
        return {"verdict": "watch-only", "tests": tests}

    if block:
        tests.append({"name": "source_function_context", "result": "checked", "reason": "no downgrade rule matched"})
    else:
        tests.append({"name": "source_function_context", "result": "missing", "reason": "function body not available"})
    return {"verdict": "needs-review", "tests": tests}


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").lower()


def runtime_source_match(meta: dict[str, Any], finding_path: str, source_path: Path | None) -> tuple[int, list[str]]:
    notes: list[str] = []
    score = 0
    compilation = meta.get("compilation") if isinstance(meta.get("compilation"), dict) else {}
    runtime_fqn = str(compilation.get("fullyQualifiedName") or "")
    runtime_file = runtime_fqn.split(":", 1)[0].replace("\\", "/").lower()
    normalized_path = normalize_path(finding_path)
    source_files = [normalize_path(str(item)) for item in meta.get("sourceFiles") or []]
    if str(meta.get("runtimeMatch") or "").lower() in {"match", "exact_match", "perfect"}:
        score += 20
        notes.append("runtime_match")
    if runtime_file and normalized_path.endswith(runtime_file):
        score += 35
        notes.append("runtime_fqn_file")
    elif any(normalized_path.endswith(source) for source in source_files):
        score += 8
        notes.append("verified_source_file")
    else:
        score -= 25
        notes.append("not_listed_source")

    proxy = meta.get("proxyResolution") if isinstance(meta.get("proxyResolution"), dict) else {}
    implementations = proxy.get("implementations") if isinstance(proxy.get("implementations"), list) else []
    implementation_names = {
        str(item.get("name") or "").lower()
        for item in implementations
        if isinstance(item, dict) and item.get("name")
    }
    if proxy.get("isProxy"):
        notes.append(f"proxy:{proxy.get('proxyType') or 'unknown'}")
        if source_path and implementation_names:
            try:
                text = source_path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                text = ""
            if any(re.search(rf"\b(contract|abstract contract)\s+{re.escape(name)}\b", text) for name in implementation_names):
                score += 30
                notes.append("proxy_implementation_source")
    else:
        score += 8
        notes.append("not_proxy")
    return score, notes


def balance_score(live: dict[str, Any] | None) -> tuple[int, list[str]]:
    if not live:
        return -50, ["missing_live_balance_row"]
    reasons = list(live.get("reasons") or [])
    notes = [f"reason:{reason}" for reason in reasons if reason.endswith("_balance")]
    score = 0
    if notes:
        score += 35
    native = int(str(live.get("nativeBalanceWei") or "0"))
    if native >= 10**19:
        score += 12
        notes.append("native_balance_ge_10_eth")
    token_balances = live.get("majorTokenBalances") if isinstance(live.get("majorTokenBalances"), dict) else {}
    if token_balances:
        score += min(15, len(token_balances) * 3)
    if int(live.get("recentLogCount") or 0) > 0:
        score += 6
        notes.append("recent_logs")
    return score, notes


def noise_score(finding: dict[str, Any], finding_path: str) -> tuple[int, list[str]]:
    notes: list[str] = []
    score = 0
    normalized = normalize_path(finding_path)
    basename = Path(finding_path.replace("\\", "/")).name
    if any(marker in normalized for marker in SOURCE_NOISE_MARKERS) or "mock" in basename.lower():
        score -= 45
        notes.append("mock_or_test_path")
    if any(marker in normalized for marker in DEPENDENCY_MARKERS) or basename in STANDARD_FILES:
        score -= 30
        notes.append("dependency_or_standard_file")
    if basename == "UniswapV2Pair.sol" and str(finding.get("function") or "").lower() == "initialize":
        score -= 45
        notes.append("factory_gated_pair_initializer")
    joined = " ".join(str(finding.get(key) or "") for key in ("signal", "manual_check"))
    lowered = joined.lower()
    if "non-runtime" in lowered:
        score -= 60
        notes.append("scanner_non_runtime_warning")
    if "already consumed" in lowered:
        score -= 55
        notes.append("scanner_precheck_consumed")
    if "fixed recipient" in lowered or "fixed return address" in lowered or "not the caller" in lowered:
        score -= 35
        notes.append("fixed_recipient_watchlist")
    if "timestamp/state only" in lowered or "stream-initializer" in lowered:
        score -= 35
        notes.append("stream_initializer_watchlist")
    elif "requires live" in lowered or "requires implementation-slot precheck" in lowered:
        score -= 20
        notes.append("scanner_requires_precheck")
    return score, notes


def vuln_score(finding: dict[str, Any], precheck: dict[str, Any] | None) -> tuple[int, list[str]]:
    category = str(finding.get("category") or "")
    function = str(finding.get("function") or "")
    signal = str(finding.get("signal") or "")
    manual = str(finding.get("manual_check") or "")
    joined = f"{signal}\n{manual}".lower()
    score = SEVERITY_SCORE.get(str(finding.get("severity") or ""), 0)
    score += CONFIDENCE_SCORE.get(str(finding.get("confidence") or ""), 0)
    if finding.get("funds_at_risk"):
        score += 25
    notes: list[str] = [f"category:{category}"]
    if category in {"reentrancy", "accounting"}:
        score += 20
        notes.append("money_bug_class")
    if category == "address-control":
        score += 35
        notes.append("critical_address_control")
    if category == "access-control" and MONEY_FUNCTION_RE.search(function):
        score += 12
        notes.append("money_function_name")
    if "external call before accounting" in joined or "call-before-accounting" in joined:
        score += 30
        notes.append("call_before_accounting")
    if "no obvious access control" in joined:
        score += 10
        notes.append("unguarded_path")
    if precheck:
        if precheck.get("safeThreshold") and function.lower() == "setup":
            score -= 50
            notes.append("safe_threshold_nonzero")
        if precheck.get("poolInitialized") and "amm/pool initializer" in joined:
            score -= 45
            notes.append("pool_initialized")
        if (
            (precheck.get("implementationSlot") or precheck.get("beaconSlot"))
            and "standard proxy initializer" in joined
        ):
            score -= 45
            notes.append("proxy_implementation_slot_nonzero")
    return score, notes


def classify(score: int, notes: list[str], validation: dict[str, Any] | None = None) -> str:
    validation = validation or {}
    if validation.get("verdict") == "false-positive":
        return "invalid"
    if validation.get("verdict") == "watch-only":
        return "watch"
    if validation.get("verdict") == "candidate" and score < 130:
        return "review"
    hard_noise = any(note in notes for note in {"mock_or_test_path", *FALSE_POSITIVE_NOTES})
    hard_noise = hard_noise or any(note in notes for note in WATCHLIST_NOTES)
    if hard_noise and score < 165:
        return "watch"
    if "low_priority_compiler" in notes:
        return "watch"
    if "factory_gated_pair_initializer" in notes:
        return "watch"
    if score >= 180:
        return "triage-now"
    if score >= 130:
        return "review"
    return "watch"


def build_rows(
    run_dir: Path,
    validation_profile: str = "aggressive",
    manual_verdicts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    live_rows = read_jsonl(run_dir / "live-filter" / "live-contracts.jsonl")
    live_by_address = {
        str(row.get("address") or "").lower(): row
        for row in live_rows
        if ADDRESS_RE.fullmatch(str(row.get("address") or "").lower())
    }
    findings = read_jsonl(run_dir / "scan" / "all-signals.jsonl")
    meta_by_address = load_sourcify_meta(run_dir)
    precheck_by_address = load_precheck(run_dir)
    rows: list[dict[str, Any]] = []
    for finding in findings:
        address = address_from_finding(finding)
        if not address:
            continue
        finding_path = str(finding.get("path") or "")
        chain_id = chain_from_finding_path(finding_path)
        source_path = source_path_from_finding(run_dir, finding_path)
        live = live_by_address.get(address)
        meta = meta_by_address.get(address, {})
        precheck = precheck_by_address.get(address)
        source_text = read_source_text(source_path)
        score = 0
        notes: list[str] = []
        for value, value_notes in (
            balance_score(live),
            runtime_source_match(meta, finding_path, source_path),
            noise_score(finding, finding_path),
            vuln_score(finding, precheck),
        ):
            score += value
            notes.extend(value_notes)
        if finding.get("category") == "compiler" and finding.get("severity") in {"low", "info"}:
            score = min(score, 90)
            notes.append("low_priority_compiler")
        validation = validation_tests(finding, sorted(set(notes)), source_text, precheck, validation_profile)
        manual_verdict = manual_verdict_for(
            manual_verdicts or [],
            address,
            str(finding.get("function") or ""),
            str(finding.get("category") or ""),
            chain_id or str((precheck or {}).get("chain") or ""),
        )
        validation = apply_manual_verdict(validation, manual_verdict)
        row = {
            "address": address,
            "reliabilityScore": score,
            "triageClass": classify(score, notes, validation),
            "validation": validation,
            "validationProfile": validation_profile,
            "notes": sorted(set(notes)),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "category": finding.get("category"),
            "function": finding.get("function"),
            "line": finding.get("line"),
            "path": finding_path,
            "chain": chain_id,
            "signal": finding.get("signal"),
            "manualCheck": finding.get("manual_check"),
            "evidence": finding.get("evidence"),
            "live": live or {},
            "sourcify": {
                "runtimeMatch": meta.get("runtimeMatch"),
                "match": meta.get("match"),
                "fqn": (meta.get("compilation") or {}).get("fullyQualifiedName")
                if isinstance(meta.get("compilation"), dict)
                else None,
                "proxyResolution": meta.get("proxyResolution"),
            },
            "precheck": precheck or {},
        }
        if manual_verdict:
            row["manualFeedback"] = {
                "verdict": manual_verdict.get("verdict"),
                "reason": manual_verdict.get("reason"),
                "ruleHint": manual_verdict.get("ruleHint"),
                "createdAt": manual_verdict.get("createdAt"),
            }
        evidence_pack = candidate_evidence_pack(row, finding, source_text, source_path, live, meta, precheck)
        if evidence_pack:
            row["evidencePack"] = {
                "riskClass": evidence_pack["riskClass"],
                "positiveGate": evidence_pack["positiveGate"],
                "nextManualCheck": evidence_pack["nextManualCheck"],
            }
        rows.append(row)
    rows.sort(key=lambda row: (-int(row["reliabilityScore"]), row["address"], str(row["path"])))
    return rows


def candidate_evidence_packs(rows: list[dict[str, Any]], run_dir: Path) -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    meta_by_address = load_sourcify_meta(run_dir)
    precheck_by_address = load_precheck(run_dir)
    live_rows = read_jsonl(run_dir / "live-filter" / "live-contracts.jsonl")
    live_by_address = {
        str(row.get("address") or "").lower(): row
        for row in live_rows
        if ADDRESS_RE.fullmatch(str(row.get("address") or "").lower())
    }
    for row in rows:
        validation = row.get("validation") if isinstance(row.get("validation"), dict) else {}
        if validation.get("verdict") != "candidate":
            continue
        address = str(row.get("address") or "").lower()
        finding = {
            "path": row.get("path"),
            "function": row.get("function"),
            "line": row.get("line"),
            "category": row.get("category"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "signal": row.get("signal"),
            "manual_check": row.get("manualCheck"),
            "evidence": row.get("evidence"),
        }
        source_path = source_path_from_finding(run_dir, str(row.get("path") or ""))
        source_text = read_source_text(source_path)
        pack = candidate_evidence_pack(
            row,
            finding,
            source_text,
            source_path,
            live_by_address.get(address),
            meta_by_address.get(address, {}),
            precheck_by_address.get(address),
        )
        if pack:
            packs.append(pack)
    return packs


def render_candidate_evidence_packs(packs: list[dict[str, Any]], run_dir: Path) -> str:
    lines = [
        "# Candidate Evidence Packs",
        "",
        "Mode: passive evidence pack. No transaction, fork replay, or exploit execution.",
        "",
        f"- Run: `{run_dir}`",
        f"- Candidate packs: {len(packs)}",
        "",
    ]
    for index, pack in enumerate(packs, 1):
        source = pack.get("source") if isinstance(pack.get("source"), dict) else {}
        live = pack.get("live") if isinstance(pack.get("live"), dict) else {}
        runtime = pack.get("runtime") if isinstance(pack.get("runtime"), dict) else {}
        gate = pack.get("positiveGate") if isinstance(pack.get("positiveGate"), dict) else {}
        native_wei = str(live.get("nativeBalanceWei") or "0")
        try:
            native_value = int(native_wei) / 10**18
        except ValueError:
            native_value = 0.0
        token_balances = live.get("majorTokenBalances") if isinstance(live.get("majorTokenBalances"), dict) else {}
        token_text = ", ".join(f"{key}={value}" for key, value in token_balances.items()) or "none"
        lines.extend(
            [
                f"## {index}. {pack.get('address')} - {pack.get('riskClass')}",
                "",
                f"- Positive gate: `{gate.get('name')}` - {gate.get('reason')}",
                f"- Next check: {pack.get('nextManualCheck')}",
                f"- Live value: native={native_value:.6f}; tokens={token_text}; recentLogs={live.get('recentLogCount') or 0}",
                f"- Runtime: match={runtime.get('runtimeMatch') or runtime.get('match')}; fqn={runtime.get('fqn') or 'n/a'}",
                f"- Source: `{source.get('path')}:{source.get('line')}`; helpers={', '.join(source.get('resolvedHelpers') or []) or 'none'}",
                "",
                "```solidity",
                str(source.get("snippet") or ""),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def render_markdown(rows: list[dict[str, Any]], top: int, run_dir: Path) -> str:
    counts = Counter(row["triageClass"] for row in rows)
    verdict_counts = Counter(
        str((row.get("validation") or {}).get("verdict") or "n/a")
        for row in rows
        if isinstance(row.get("validation"), dict)
    )
    test_counts: Counter[str] = Counter()
    for row in rows:
        validation = row.get("validation") if isinstance(row.get("validation"), dict) else {}
        tests = validation.get("tests") if isinstance(validation.get("tests"), list) else []
        for item in tests:
            if isinstance(item, dict) and item.get("name"):
                test_counts[str(item["name"])] += 1
    alertable_count = counts["triage-now"] + counts["review"]
    lines = [
        "# High-Value Triage",
        "",
        "Mode: passive post-processing only. This is not a proof of exploitability.",
        "",
        "## Summary",
        "",
        f"- Run: `{run_dir}`",
        f"- Findings scored: {len(rows)}",
        f"- Triage now: {counts['triage-now']}",
        f"- Review: {counts['review']}",
        f"- Watch: {counts['watch']}",
        f"- Invalid: {counts['invalid']}",
        f"- Alertable: {alertable_count}",
        f"- Validation verdicts: {dict(verdict_counts)}",
        f"- Top validation tests: {dict(test_counts.most_common(12))}",
        "",
        "## Top Items",
        "",
    ]
    for index, row in enumerate(rows[:top], 1):
        live = row.get("live") if isinstance(row.get("live"), dict) else {}
        native_eth = int(str(live.get("nativeBalanceWei") or "0")) / 10**18
        token_balances = live.get("majorTokenBalances") if isinstance(live.get("majorTokenBalances"), dict) else {}
        tokens = ", ".join(f"{k}={v}" for k, v in token_balances.items()) or "none"
        notes = ", ".join(row.get("notes") or [])
        validation = row.get("validation") if isinstance(row.get("validation"), dict) else {}
        tests = validation.get("tests") if isinstance(validation.get("tests"), list) else []
        test_summary = "; ".join(
            f"{item.get('name')}={item.get('result')}"
            for item in tests
            if isinstance(item, dict)
        )
        lines.extend(
            [
                f"### {index}. {row['triageClass']} score={row['reliabilityScore']} {row['address']}",
                "",
                f"- Finding: {row.get('severity')}/{row.get('confidence')} {row.get('category')} `{row.get('function')}`",
                f"- Balance: {native_eth:.6f} ETH; tokens: {tokens}",
                f"- Source: `{row.get('path')}:{row.get('line')}`",
                f"- Signal: {row.get('signal')}",
                f"- Reliability notes: {notes}",
                f"- Validation: {validation.get('verdict') or 'n/a'}; {test_summary or 'n/a'}",
                f"- Manual check: {row.get('manualCheck')}",
                "",
            ]
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = Path(args.run_dir).resolve()
    out_dir = Path(args.out_dir).resolve() if args.out_dir else run_dir / "triage"
    out_dir.mkdir(parents=True, exist_ok=True)
    verdicts_file = Path(args.verdicts_file).resolve()
    manual_verdicts = load_manual_verdicts(verdicts_file)
    rows = build_rows(run_dir, args.validation_profile, manual_verdicts)
    packs = candidate_evidence_packs(rows, run_dir)
    write_jsonl(out_dir / "high-value-triage.jsonl", rows)
    (out_dir / "candidate-evidence-packs.json").write_text(
        json.dumps(packs, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "candidate-evidence-packs.md").write_text(
        render_candidate_evidence_packs(packs, run_dir),
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "high-value-triage.md").write_text(
        render_markdown(rows, args.top, run_dir),
        encoding="utf-8",
        newline="\n",
    )
    summary = {
        "runDir": str(run_dir),
        "findingCount": len(rows),
        "triageClassCounts": dict(Counter(row["triageClass"] for row in rows)),
        "topLimit": args.top,
        "validationProfile": args.validation_profile,
        "manualVerdictsFile": str(verdicts_file),
        "manualVerdictCount": len(manual_verdicts),
        "manualVerdictAppliedCount": sum(1 for row in rows if row.get("manualFeedback")),
    }
    verdict_counts = Counter(
        str((row.get("validation") or {}).get("verdict") or "n/a")
        for row in rows
        if isinstance(row.get("validation"), dict)
    )
    test_counts: Counter[str] = Counter()
    for row in rows:
        validation = row.get("validation") if isinstance(row.get("validation"), dict) else {}
        tests = validation.get("tests") if isinstance(validation.get("tests"), list) else []
        for item in tests:
            if isinstance(item, dict) and item.get("name"):
                test_counts[str(item["name"])] += 1
    summary["validationVerdictCounts"] = dict(verdict_counts)
    summary["validationTestCounts"] = dict(test_counts)
    summary["alertableCount"] = int(summary["triageClassCounts"].get("triage-now", 0)) + int(
        summary["triageClassCounts"].get("review", 0)
    )
    summary["candidateEvidencePackCount"] = len(packs)
    summary["candidateEvidencePackArtifact"] = str(out_dir / "candidate-evidence-packs.md")
    (out_dir / "high-value-triage-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    print(f"Findings scored: {len(rows)}")
    print(f"Output: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

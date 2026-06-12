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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render high-value EVM triage report.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out-dir")
    parser.add_argument("--top", type=int, default=200)
    return parser.parse_args(argv)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        rows.append(json.loads(raw))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


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


def classify(score: int, notes: list[str]) -> str:
    hard_noise = any(
        note in notes
        for note in {
            "mock_or_test_path",
            "scanner_non_runtime_warning",
            "scanner_precheck_consumed",
            "safe_threshold_nonzero",
            "pool_initialized",
            "proxy_implementation_slot_nonzero",
            "fixed_recipient_watchlist",
            "stream_initializer_watchlist",
        }
    )
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


def build_rows(run_dir: Path) -> list[dict[str, Any]]:
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
        source_path = source_path_from_finding(run_dir, finding_path)
        live = live_by_address.get(address)
        meta = meta_by_address.get(address, {})
        precheck = precheck_by_address.get(address)
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
        rows.append(
            {
                "address": address,
                "reliabilityScore": score,
                "triageClass": classify(score, notes),
                "notes": sorted(set(notes)),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "category": finding.get("category"),
                "function": finding.get("function"),
                "line": finding.get("line"),
                "path": finding_path,
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
        )
    rows.sort(key=lambda row: (-int(row["reliabilityScore"]), row["address"], str(row["path"])))
    return rows


def render_markdown(rows: list[dict[str, Any]], top: int, run_dir: Path) -> str:
    counts = Counter(row["triageClass"] for row in rows)
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
        lines.extend(
            [
                f"### {index}. {row['triageClass']} score={row['reliabilityScore']} {row['address']}",
                "",
                f"- Finding: {row.get('severity')}/{row.get('confidence')} {row.get('category')} `{row.get('function')}`",
                f"- Balance: {native_eth:.6f} ETH; tokens: {tokens}",
                f"- Source: `{row.get('path')}:{row.get('line')}`",
                f"- Signal: {row.get('signal')}",
                f"- Reliability notes: {notes}",
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
    rows = build_rows(run_dir)
    write_jsonl(out_dir / "high-value-triage.jsonl", rows)
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
    }
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

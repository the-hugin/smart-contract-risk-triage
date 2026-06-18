from __future__ import annotations

import json
import importlib.util
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
OUT_DIR = ROOT / "tmp" / "regression-out"
PRECHECK_DIR = ROOT / "tmp" / "regression-precheck"
PRECHECK_OUT_DIR = ROOT / "tmp" / "regression-precheck-out"
PACK_DIR = ROOT / "tmp" / "regression-candidate-pack"
VERDICTS_DIR = ROOT / "tmp" / "regression-manual-verdicts"
SCANNER = ROOT / "scripts" / "smart-contract-batch-scan.py"
SOLANA_MONITOR = ROOT / "scripts" / "solana-program-monitor.py"
ETH_HIGH_VALUE_TRIAGE = ROOT / "scripts" / "eth-high-value-triage.py"
ETH_CONTINUOUS_MONITOR = ROOT / "scripts" / "eth-continuous-monitor.py"
ADD_VERDICT = ROOT / "scripts" / "smart-contract-add-verdict.py"
STREAM_PRECHECK_ADDRESS = "0x1111111111111111111111111111111111111111"

EXPECTED_CRITICALS = {
    ("tests/fixtures/FinanceBank.sol", "Collect", "reentrancy"),
    ("tests/fixtures/MockPoolManagerV12.sol", "take", "access-control"),
    ("tests/fixtures/AddressSubstitution.sol", "setTreasury", "upgradeability"),
    ("tests/fixtures/AddressSubstitution.sol", "configureOracle", "upgradeability"),
    ("tests/fixtures/AddressSubstitution.sol", "withdrawTo", "access-control"),
    ("tests/fixtures/AddressSubstitution.sol", "drainNative", "access-control"),
}

ALLOWED_EXTRA_RAW_CRITICALS = {
    ("tests/fixtures/StreamerVesting.sol", "claim", "access-control"),
    ("tests/fixtures/StreamerVesting.sol", "sweepRemaining", "access-control"),
}


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def run_capture(command: list[str], expected_code: int = 0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if completed.returncode != expected_code:
        raise AssertionError(
            f"command {command} returned {completed.returncode}, expected {expected_code}; "
            f"stdout={completed.stdout} stderr={completed.stderr}"
        )
    return completed


def load_findings(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def normalized_path(value: object) -> str:
    return str(value).replace("\\", "/")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"failed to load module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_validation_verdict(
    eth_triage,
    source: str,
    function: str,
    category: str,
    expected: str,
) -> dict[str, object]:
    result = eth_triage.validation_tests(
        {"function": function, "category": category, "line": 4, "signal": "", "manual_check": ""},
        [],
        source,
        None,
    )
    if result.get("verdict") != expected:
        raise AssertionError(f"{function}: expected validation {expected}, got {result}")
    return result


def assert_validation_test(
    result: dict[str, object],
    expected_name: str,
) -> None:
    tests = result.get("tests") if isinstance(result.get("tests"), list) else []
    names = [str(item.get("name")) for item in tests if isinstance(item, dict)]
    if expected_name not in names:
        raise AssertionError(f"expected validation test {expected_name}, got {tests}")


def main() -> int:
    run([sys.executable, "-m", "py_compile", *map(str, sorted((ROOT / "scripts").glob("*.py")))])

    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    if PRECHECK_DIR.exists():
        shutil.rmtree(PRECHECK_DIR)
    if PRECHECK_OUT_DIR.exists():
        shutil.rmtree(PRECHECK_OUT_DIR)
    if PACK_DIR.exists():
        shutil.rmtree(PACK_DIR)
    if VERDICTS_DIR.exists():
        shutil.rmtree(VERDICTS_DIR)
    run(
        [
            sys.executable,
            str(SCANNER),
            str(FIXTURES),
            "--out-dir",
            str(OUT_DIR),
            "--critical-limit",
            "200",
        ]
    )

    findings = load_findings(OUT_DIR / "all-signals.jsonl")
    severity = Counter(str(row.get("severity")) for row in findings)
    if severity.get("critical", 0) < len(EXPECTED_CRITICALS):
        raise AssertionError(f"critical scanner signals regressed: {dict(severity)}")

    criticals = {
        (
            normalized_path(row.get("path")),
            str(row.get("function")),
            str(row.get("category")),
        )
        for row in findings
        if row.get("severity") == "critical"
    }
    if not EXPECTED_CRITICALS.issubset(criticals):
        raise AssertionError(f"missing expected critical findings: {sorted(EXPECTED_CRITICALS - criticals)}")
    unexpected = criticals - EXPECTED_CRITICALS - ALLOWED_EXTRA_RAW_CRITICALS
    if unexpected:
        raise AssertionError(f"unexpected raw critical findings: {sorted(unexpected)}")

    eth_triage = load_module(ETH_HIGH_VALUE_TRIAGE, "eth_high_value_triage_regression")
    critical_rows = {
        (normalized_path(row.get("path")), str(row.get("function")), str(row.get("category"))): row
        for row in findings
        if row.get("severity") == "critical"
    }
    address_control_row = critical_rows[
        ("tests/fixtures/AddressSubstitution.sol", "setTreasury", "upgradeability")
    ]
    synthetic_live = {
        "reasons": ["native_eth_balance"],
        "nativeBalanceWei": str(3 * 10**17),
        "recentLogCount": 1,
        "majorTokenBalances": {},
    }
    score_parts = [
        eth_triage.balance_score(synthetic_live),
        eth_triage.vuln_score(address_control_row, None),
    ]
    score = sum(int(value) for value, _ in score_parts)
    notes = [note for _, part_notes in score_parts for note in part_notes]
    if eth_triage.classify(score, notes) != "triage-now":
        raise AssertionError(
            f"live-value address-control should be triage-now, got score={score} notes={notes}"
        )
    finance_source = (FIXTURES / "FinanceBank.sol").read_text(encoding="utf-8")
    finance_validation = assert_validation_verdict(
        eth_triage,
        finance_source,
        "Collect",
        "reentrancy",
        "candidate",
    )
    assert_validation_test(finance_validation, "positive_reentrancy_profit_path")
    pool_source = (FIXTURES / "MockPoolManagerV12.sol").read_text(encoding="utf-8")
    pool_validation = assert_validation_verdict(
        eth_triage,
        pool_source,
        "take",
        "access-control",
        "candidate",
    )
    assert_validation_test(pool_validation, "positive_caller_controlled_recipient")
    address_substitution_source = (FIXTURES / "AddressSubstitution.sol").read_text(encoding="utf-8")
    address_validation = assert_validation_verdict(
        eth_triage,
        address_substitution_source,
        "setTreasury",
        "upgradeability",
        "candidate",
    )
    assert_validation_test(address_validation, "positive_critical_address_substitution")
    stream_source = (FIXTURES / "StreamerVesting.sol").read_text(encoding="utf-8")
    for stream_function, stream_category in (
        ("initialize", "upgradeability"),
        ("claim", "access-control"),
        ("sweepRemaining", "access-control"),
    ):
        assert_validation_verdict(
            eth_triage,
            stream_source,
            stream_function,
            stream_category,
            "watch-only",
        )
    assert_validation_verdict(
        eth_triage,
        """
        contract MerkleDistributor {
            function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external {
                require(MerkleProof.verify(proof, merkleRoot, keccak256(abi.encode(index, account, amount))));
                _setClaimed(index);
                token.safeTransfer(account, amount);
            }
        }
        """,
        "claim",
        "access-control",
        "false-positive",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract Orderbook {
            function cleanupExpiredOrder(uint256 orderId) external nonReentrant {
                Order storage order = orders[orderId];
                require(isOrderExpired(orderId));
                order.status = OrderStatus.Expired;
                token.safeTransfer(order.owner, order.amount);
            }
        }
        """,
        "cleanupExpiredOrder",
        "reentrancy",
        "watch-only",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract Router {
            function withdrawFunds(address token, uint256 amount) external onlyOwner {
                IERC20(token).transfer(owner(), amount);
                totalWithdrawn += amount;
            }
        }
        """,
        "withdrawFunds",
        "reentrancy",
        "false-positive",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract Rewards {
            function claimRewards(uint256[] calldata tokenIds) external {
                for (uint256 i; i < tokenIds.length; ++i) {
                    uint256 tokenId = tokenIds[i];
                    require(ownerOf(tokenId) == msg.sender);
                    rewardDebt[tokenId] = accRewardPerShare;
                    _pay(msg.sender, pending[tokenId]);
                }
            }
        }
        """,
        "claimRewards",
        "dos-locked-funds",
        "false-positive",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract RewardsDistributor {
            function sweepDust() external {
                uint256 reserve = pendingUndistributed + owedScaled;
                uint256 dust = address(this).balance - reserve;
                bountyTreasury.deposit{value: dust}();
            }
        }
        """,
        "sweepDust",
        "access-control",
        "watch-only",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract InlineOwnerWithdraw {
            address public owner;
            function withdraw(uint256 amount) external {
                require(msg.sender == owner, "owner");
                payable(owner).transfer(amount);
            }
        }
        """,
        "withdraw",
        "access-control",
        "false-positive",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract ChecksEffects {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                balances[msg.sender] -= amount;
                (bool ok,) = msg.sender.call{value: amount}("");
                require(ok);
            }
        }
        """,
        "withdraw",
        "reentrancy",
        "false-positive",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract CostBoundRedeem {
            mapping(address => uint256) public balances;
            function redeem(uint256 amount) external {
                token.safeTransferFrom(msg.sender, address(this), amount);
                balances[msg.sender] -= amount;
                reward.safeTransfer(msg.sender, amount);
            }
        }
        """,
        "redeem",
        "access-control",
        "false-positive",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract Auction {
            function settle(uint256 orderId) external {
                Order storage order = orders[orderId];
                require(block.timestamp > order.deadline);
                order.status = Status.Settled;
                token.safeTransfer(order.owner, order.amount);
            }
        }
        """,
        "settle",
        "access-control",
        "watch-only",
    )
    assert_validation_verdict(
        eth_triage,
        """
        contract SignedClaim {
            function claim(uint256 amount, uint256 nonce, uint256 deadline, bytes calldata sig) external {
                require(block.timestamp <= deadline);
                require(!used[nonce]);
                bytes32 digest = keccak256(abi.encode(DOMAIN_SEPARATOR, block.chainid, address(this), msg.sender, amount, nonce, deadline));
                address signer = ECDSA.recover(digest, sig);
                require(hasRole(CLAIM_SIGNER_ROLE, signer));
                used[nonce] = true;
                token.safeTransfer(msg.sender, amount);
            }
        }
        """,
        "claim",
        "signature-replay",
        "false-positive",
    )
    interprocedural_validation = assert_validation_verdict(
        eth_triage,
        """
        contract WrapperClaim {
            function claim(uint256 tokenId) external {
                _claimOne(tokenId);
            }
            function _claimOne(uint256 tokenId) internal {
                address ownerAddr = _ownerOf(tokenId);
                _setFeeDebt(tokenId, feeGrowth);
                payable(ownerAddr).call{value: pending[tokenId]}("");
            }
        }
        """,
        "claim",
        "access-control",
        "false-positive",
    )
    assert_validation_test(interprocedural_validation, "interprocedural_source_context")
    assert_validation_test(interprocedural_validation, "token_owner_bound_claim")

    eth_monitor = load_module(ETH_CONTINUOUS_MONITOR, "eth_continuous_monitor_regression")
    alert_gate_dir = ROOT / "tmp" / "regression-alert-gate"
    if alert_gate_dir.exists():
        shutil.rmtree(alert_gate_dir)
    triage_dir = alert_gate_dir / "triage"
    triage_dir.mkdir(parents=True, exist_ok=True)
    alert_rows_path = triage_dir / "high-value-triage.jsonl"
    alert_rows_path.write_text(
        "\n".join(
            json.dumps(row)
            for row in [
                {
                    "address": "0x1111111111111111111111111111111111111111",
                    "triageClass": "review",
                    "validation": {"verdict": "watch-only"},
                    "reliabilityScore": 999,
                },
                {
                    "address": "0x2222222222222222222222222222222222222222",
                    "triageClass": "triage-now",
                    "validation": {"verdict": "false-positive"},
                    "reliabilityScore": 999,
                },
                {
                    "address": "0x3333333333333333333333333333333333333333",
                    "triageClass": "review",
                    "validation": {"verdict": "needs-review"},
                    "reliabilityScore": 100,
                },
                {
                    "address": "0x4444444444444444444444444444444444444444",
                    "triageClass": "review",
                    "validation": {"verdict": "candidate"},
                    "reliabilityScore": 90,
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    gated_rows = eth_monitor.alert_rows(alert_gate_dir, 5)
    if [row.get("address") for row in gated_rows] != ["0x4444444444444444444444444444444444444444"]:
        raise AssertionError(f"post-validation alert gate selected wrong rows: {gated_rows}")

    pack_address = "0x1111111111111111111111111111111111111111"
    pack_source = PACK_DIR / "sources" / "1" / pack_address / "FinanceBank.sol"
    pack_source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / "FinanceBank.sol", pack_source)
    (PACK_DIR / "scan").mkdir(parents=True, exist_ok=True)
    (PACK_DIR / "live-filter").mkdir(parents=True, exist_ok=True)
    (PACK_DIR / "live-filter" / "live-contracts.jsonl").write_text(
        json.dumps(
            {
                "address": pack_address,
                "nativeBalanceWei": str(3 * 10**17),
                "recentLogCount": 1,
                "majorTokenBalances": {},
                "reasons": ["native_eth_balance"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (PACK_DIR / "scan" / "all-signals.jsonl").write_text(
        json.dumps(
            {
                "path": str(pack_source),
                "function": "Collect",
                "line": 8,
                "category": "reentrancy",
                "severity": "critical",
                "confidence": "high",
                "funds_at_risk": True,
                "signal": "Possible external transfer before accounting update.",
                "manual_check": "Confirm whether attacker-controlled receiver can reenter.",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    run(
        [
            sys.executable,
            str(ETH_HIGH_VALUE_TRIAGE),
            "--run-dir",
            str(PACK_DIR),
        ]
    )
    pack_json = json.loads((PACK_DIR / "triage" / "candidate-evidence-packs.json").read_text(encoding="utf-8"))
    if len(pack_json) != 1:
        raise AssertionError(f"expected one candidate evidence pack, got {pack_json}")
    pack = pack_json[0]
    if pack.get("positiveGate", {}).get("name") != "positive_reentrancy_profit_path":
        raise AssertionError(f"candidate evidence pack missing positive gate: {pack}")
    if "function Collect" not in str(pack.get("source", {}).get("snippet") or ""):
        raise AssertionError(f"candidate evidence pack missing source snippet: {pack}")
    pack_summary = json.loads((PACK_DIR / "triage" / "high-value-triage-summary.json").read_text(encoding="utf-8"))
    if pack_summary.get("candidateEvidencePackCount") != 1:
        raise AssertionError(f"bad candidate evidence summary: {pack_summary}")

    manual_verdicts = [
        {
            "address": pack_address,
            "chain": "1",
            "function": "Collect",
            "category": "reentrancy",
            "verdict": "false-positive",
            "reason": "regression manual false positive",
            "ruleHint": "manual_feedback_verdict",
            "sourcePath": str(pack_source),
            "createdAt": "2026-06-18T00:00:00Z",
        }
    ]
    verdicts_file = PACK_DIR / "manual-verdicts.jsonl"
    verdicts_file.write_text(
        "\n".join(json.dumps(row) for row in manual_verdicts) + "\n",
        encoding="utf-8",
    )
    manual_out = PACK_DIR / "triage-manual"
    run(
        [
            sys.executable,
            str(ETH_HIGH_VALUE_TRIAGE),
            "--run-dir",
            str(PACK_DIR),
            "--out-dir",
            str(manual_out),
            "--verdicts-file",
            str(verdicts_file),
        ]
    )
    manual_rows = load_findings(manual_out / "high-value-triage.jsonl")
    if manual_rows[0].get("validation", {}).get("verdict") != "false-positive":
        raise AssertionError(f"manual false-positive verdict was not applied: {manual_rows[0]}")
    manual_summary = json.loads((manual_out / "high-value-triage-summary.json").read_text(encoding="utf-8"))
    if manual_summary.get("manualVerdictAppliedCount") != 1 or manual_summary.get("candidateEvidencePackCount") != 0:
        raise AssertionError(f"manual false-positive summary mismatch: {manual_summary}")

    VERDICTS_DIR.mkdir(parents=True, exist_ok=True)
    weak_address = "0x2222222222222222222222222222222222222222"
    weak_source = VERDICTS_DIR / "sources" / "1" / weak_address / "Weak.sol"
    weak_source.parent.mkdir(parents=True, exist_ok=True)
    weak_source.write_text(
        """
        contract Weak {
            function observe() external {
                emit Seen(msg.sender);
            }
        }
        """,
        encoding="utf-8",
    )
    (VERDICTS_DIR / "scan").mkdir(parents=True, exist_ok=True)
    (VERDICTS_DIR / "live-filter").mkdir(parents=True, exist_ok=True)
    (VERDICTS_DIR / "live-filter" / "live-contracts.jsonl").write_text(
        json.dumps(
            {
                "address": weak_address,
                "nativeBalanceWei": "0",
                "recentLogCount": 1,
                "majorTokenBalances": {},
                "reasons": ["recent_emitted_logs"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (VERDICTS_DIR / "scan" / "all-signals.jsonl").write_text(
        json.dumps(
            {
                "path": str(weak_source),
                "function": "observe",
                "line": 3,
                "category": "compiler",
                "severity": "low",
                "confidence": "low",
                "funds_at_risk": False,
                "signal": "Low signal row.",
                "manual_check": "No alert without manual verdict.",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    confirmed_file = VERDICTS_DIR / "manual-verdicts.jsonl"
    confirmed_file.write_text(
        json.dumps(
            {
                "address": weak_address,
                "chain": "1",
                "function": "observe",
                "category": "compiler",
                "verdict": "confirmed-candidate",
                "reason": "regression promotion",
                "ruleHint": "manual_feedback_verdict",
                "sourcePath": str(weak_source),
                "createdAt": "2026-06-18T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    run(
        [
            sys.executable,
            str(ETH_HIGH_VALUE_TRIAGE),
            "--run-dir",
            str(VERDICTS_DIR),
            "--verdicts-file",
            str(confirmed_file),
        ]
    )
    confirmed_rows = load_findings(VERDICTS_DIR / "triage" / "high-value-triage.jsonl")
    if confirmed_rows[0].get("validation", {}).get("verdict") != "candidate":
        raise AssertionError(f"manual confirmed-candidate verdict was not applied: {confirmed_rows[0]}")
    if confirmed_rows[0].get("triageClass") != "review":
        raise AssertionError(f"manual confirmed-candidate did not raise triage class: {confirmed_rows[0]}")
    confirmed_summary = json.loads((VERDICTS_DIR / "triage" / "high-value-triage-summary.json").read_text(encoding="utf-8"))
    if (
        confirmed_summary.get("manualVerdictAppliedCount") != 1
        or confirmed_summary.get("candidateEvidencePackCount") != 1
        or confirmed_summary.get("alertableCount") != 1
    ):
        raise AssertionError(f"manual confirmed-candidate summary mismatch: {confirmed_summary}")

    cli_verdicts = VERDICTS_DIR / "cli-verdicts.jsonl"
    command = [
        sys.executable,
        str(ADD_VERDICT),
        "--out",
        str(cli_verdicts),
        "--address",
        weak_address,
        "--chain",
        "1",
        "--function",
        "observe",
        "--category",
        "compiler",
        "--verdict",
        "watch-only",
        "--reason",
        "regression cli add",
        "--rule-hint",
        "manual_feedback_verdict",
        "--source-path",
        str(weak_source),
        "--created-at",
        "2026-06-18T00:00:00Z",
    ]
    first_add = json.loads(run_capture(command).stdout)
    second_add = json.loads(run_capture(command).stdout)
    if first_add.get("status") != "appended" or second_add.get("status") != "duplicate":
        raise AssertionError(f"bad verdict CLI statuses: first={first_add} second={second_add}")
    cli_rows = load_findings(cli_verdicts)
    if len(cli_rows) != 1 or cli_rows[0].get("verdict") != "watch-only":
        raise AssertionError(f"bad verdict CLI output rows: {cli_rows}")
    run_capture(
        [
            sys.executable,
            str(ADD_VERDICT),
            "--out",
            str(cli_verdicts),
            "--address",
            "0x1234",
            "--chain",
            "1",
            "--function",
            "observe",
            "--category",
            "compiler",
            "--verdict",
            "watch-only",
            "--reason",
            "bad address",
        ],
        expected_code=2,
    )

    precheck_source = PRECHECK_DIR / "sources" / "1" / STREAM_PRECHECK_ADDRESS / "StreamerVesting.sol"
    precheck_source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / "StreamerVesting.sol", precheck_source)
    precheck_json = PRECHECK_DIR / "runtime-precheck.json"
    precheck_json.write_text(
        json.dumps(
            {
                STREAM_PRECHECK_ADDRESS: {
                    "address": STREAM_PRECHECK_ADDRESS,
                    "startTimestamp": 1779831563,
                }
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    run(
        [
            sys.executable,
            str(SCANNER),
            str(precheck_source),
            "--out-dir",
            str(PRECHECK_OUT_DIR),
            "--precheck-json",
            str(precheck_json),
        ]
    )
    prechecked = load_findings(PRECHECK_OUT_DIR / "all-signals.jsonl")
    consumed_rows = [
        row
        for row in prechecked
        if row.get("function") == "initialize" and row.get("category") == "upgradeability"
    ]
    if len(consumed_rows) != 1:
        raise AssertionError(f"expected one prechecked initialize finding, got {len(consumed_rows)}")
    consumed = consumed_rows[0]
    if consumed.get("severity") not in {"low", "medium"} or consumed.get("funds_at_risk") is not False:
        raise AssertionError(f"precheck did not downgrade initialize: {consumed}")
    if not any(marker in str(consumed.get("signal") or "") for marker in ("already consumed", "state-guard")):
        raise AssertionError(f"precheck signal missing downgrade marker: {consumed}")

    solana_monitor = load_module(SOLANA_MONITOR, "solana_program_monitor_regression")
    weak_set_authority = {
        "eventType": "setAuthority",
        "authority": "7UZ4N8SzzqEKPQGLhJSUbhn78wD1J2TeadPcittuDfaZ",
        "programId": "",
        "programDataAccount": "",
        "triageClass": "review",
        "severity": "medium",
    }
    if solana_monitor.alert_rows([weak_set_authority], 5):
        raise AssertionError("malformed setAuthority event should not be selected for Telegram")
    strong_event = {
        "eventType": "upgrade",
        "programId": "HQZ8joMTEiHXFrcFRDC72LZSZuSmLaDNXJeZS2kNEzjD",
        "triageClass": "triage-now",
        "severity": "high",
    }
    if len(solana_monitor.alert_rows([strong_event], 5)) != 1:
        raise AssertionError("triage-now Solana event should remain alertable")
    close_value_event = {
        "eventType": "close",
        "programId": "5BWJbv4Tp4VqXzgFsQQ5pnq7vp8GKhg8S9u8HH8o9f2j",
        "triageClass": "watch",
        "severity": "low",
        "valueMap": {
            "valueSignalCount": 1,
            "valueSignals": [{"confidence": "direct_or_unknown_native_account", "asset": "SOL"}],
        },
    }
    solana_monitor.apply_value_classification(close_value_event, object())
    if close_value_event.get("triageClass") != "watch" or solana_monitor.alert_rows([close_value_event], 5):
        raise AssertionError(f"close value-proximity event should not alert: {close_value_event}")

    print("Regression OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

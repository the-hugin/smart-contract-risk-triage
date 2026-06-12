from __future__ import annotations

import json
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
SCANNER = ROOT / "scripts" / "smart-contract-batch-scan.py"
STREAM_PRECHECK_ADDRESS = "0x1111111111111111111111111111111111111111"

EXPECTED_SEVERITY = {
    "critical": 2,
    "high": 2,
    "medium": 16,
    "low": 14,
    "info": 0,
}

EXPECTED_CRITICALS = {
    ("tests/fixtures/FinanceBank.sol", "Collect", "reentrancy"),
    ("tests/fixtures/MockPoolManagerV12.sol", "take", "access-control"),
}

EXPECTED_STREAM_WATCHLIST = {
    ("initialize", "upgradeability"): ("medium", False),
    ("claim", "access-control"): ("low", False),
    ("sweepRemaining", "access-control"): ("medium", False),
}


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def load_findings(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def normalized_path(value: object) -> str:
    return str(value).replace("\\", "/")


def main() -> int:
    run([sys.executable, "-m", "py_compile", *map(str, sorted((ROOT / "scripts").glob("*.py")))])

    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    if PRECHECK_DIR.exists():
        shutil.rmtree(PRECHECK_DIR)
    if PRECHECK_OUT_DIR.exists():
        shutil.rmtree(PRECHECK_OUT_DIR)
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
    for key, expected in EXPECTED_SEVERITY.items():
        actual = severity.get(key, 0)
        if actual != expected:
            raise AssertionError(f"{key}: expected {expected}, got {actual}")

    criticals = {
        (
            normalized_path(row.get("path")),
            str(row.get("function")),
            str(row.get("category")),
        )
        for row in findings
        if row.get("severity") == "critical"
    }
    if criticals != EXPECTED_CRITICALS:
        raise AssertionError(f"unexpected critical findings: {sorted(criticals)}")

    stream_rows = {
        (str(row.get("function")), str(row.get("category"))): row
        for row in findings
        if normalized_path(row.get("path")).endswith("tests/fixtures/StreamerVesting.sol")
    }
    for key, expected in EXPECTED_STREAM_WATCHLIST.items():
        row = stream_rows.get(key)
        if not row:
            raise AssertionError(f"missing stream watchlist finding: {key}")
        severity, funds_at_risk = expected
        if row.get("severity") != severity or row.get("funds_at_risk") is not funds_at_risk:
            raise AssertionError(
                f"bad stream watchlist classification for {key}: "
                f"severity={row.get('severity')} funds_at_risk={row.get('funds_at_risk')}"
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
    if consumed.get("severity") != "low" or consumed.get("funds_at_risk") is not False:
        raise AssertionError(f"precheck did not downgrade initialize: {consumed}")
    if "already consumed" not in str(consumed.get("signal") or ""):
        raise AssertionError(f"precheck signal missing consumed marker: {consumed}")

    print("Regression OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

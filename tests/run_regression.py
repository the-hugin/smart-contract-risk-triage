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
SCANNER = ROOT / "scripts" / "smart-contract-batch-scan.py"

EXPECTED_SEVERITY = {
    "critical": 2,
    "high": 2,
    "medium": 14,
    "low": 13,
    "info": 0,
}

EXPECTED_CRITICALS = {
    ("tests/fixtures/FinanceBank.sol", "Collect", "reentrancy"),
    ("tests/fixtures/MockPoolManagerV12.sol", "take", "access-control"),
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

    print("Regression OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

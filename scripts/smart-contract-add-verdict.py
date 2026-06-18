#!/usr/bin/env python3
"""Append a manual smart-contract triage verdict to JSONL."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
VERDICTS = {"false-positive", "watch-only", "confirmed-candidate"}
DEFAULT_OUT = Path(__file__).resolve().parents[1] / "reports" / "smart-contract-verdicts.jsonl"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Append manual smart-contract triage verdict.")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Verdicts JSONL output path.")
    parser.add_argument("--address", required=True)
    parser.add_argument("--chain", required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--verdict", required=True, choices=sorted(VERDICTS))
    parser.add_argument("--reason", required=True)
    parser.add_argument("--rule-hint", default="")
    parser.add_argument("--source-path", default="")
    parser.add_argument("--created-at", default="")
    return parser.parse_args(argv)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def key_for(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("address") or "").lower(),
        str(row.get("chain") or ""),
        str(row.get("function") or ""),
        str(row.get("category") or ""),
        str(row.get("verdict") or ""),
    )


def build_row(args: argparse.Namespace) -> dict[str, str]:
    address = args.address.lower()
    if not ADDRESS_RE.fullmatch(address):
        raise ValueError(f"invalid EVM address: {args.address}")
    chain = str(args.chain).strip()
    if not chain:
        raise ValueError("chain is required")
    created_at = args.created_at.strip() or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return {
        "address": address,
        "chain": chain,
        "function": str(args.function).strip(),
        "category": str(args.category).strip(),
        "verdict": str(args.verdict).strip(),
        "reason": str(args.reason).strip(),
        "ruleHint": str(args.rule_hint).strip(),
        "sourcePath": str(args.source_path).strip(),
        "createdAt": created_at,
    }


def append_verdict(path: Path, row: dict[str, str]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = read_jsonl(path)
    row_key = key_for(row)
    if any(key_for(item) == row_key for item in existing):
        return "duplicate"
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return "appended"


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    out = Path(args.out).resolve()
    row = build_row(args)
    status = append_verdict(out, row)
    print(json.dumps({"status": status, "out": str(out), "row": row}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

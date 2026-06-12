#!/usr/bin/env python3
"""List recent Sourcify verified contracts without downloading sources."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SOURCIFY_BASE = "https://sourcify.dev/server"
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


@dataclass(frozen=True)
class Target:
    chain_id: str
    address: str

    @property
    def key(self) -> str:
        return f"{self.chain_id}:{self.address.lower()}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="List Sourcify verified contracts.")
    parser.add_argument("--chain-id", default="1", help="Default: 1")
    parser.add_argument("--limit", type=int, default=50000, help="Default: 50000")
    parser.add_argument("--out", required=True, help="Output targets file.")
    parser.add_argument("--jsonl", help="Optional metadata JSONL output.")
    parser.add_argument("--sort", choices=("asc", "desc"), default="desc")
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--timeout-seconds", type=float, default=35.0)
    parser.add_argument("--retries", type=int, default=4)
    return parser.parse_args(argv)


def http_json(url: str, args: argparse.Namespace) -> Any:
    last: Exception | None = None
    for attempt in range(args.retries + 1):
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "smart-contract-risk-triage-sourcify-list/0.2",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=args.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            last = exc
            if attempt >= args.retries:
                raise
            time.sleep(2**attempt)
    raise RuntimeError(f"request failed: {last}")


def list_targets(args: argparse.Namespace) -> tuple[list[Target], list[dict[str, Any]]]:
    targets: list[Target] = []
    rows_out: list[dict[str, Any]] = []
    seen: set[str] = set()
    after_match_id: str | None = None
    page_size = max(1, min(args.batch_size, 200))

    while len(targets) < args.limit:
        query = {"limit": str(page_size), "sort": args.sort}
        if after_match_id:
            query["afterMatchId"] = after_match_id
        url = (
            f"{SOURCIFY_BASE}/v2/contracts/{urllib.parse.quote(str(args.chain_id))}"
            f"?{urllib.parse.urlencode(query)}"
        )
        data = http_json(url, args)
        rows = data.get("results", data) if isinstance(data, dict) else data
        if not isinstance(rows, list) or not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            after_match_id = str(row.get("matchId", after_match_id or ""))
            address = str(row.get("address", ""))
            chain_id = str(row.get("chainId", args.chain_id))
            target = Target(chain_id, address)
            if ADDRESS_RE.match(address) and target.key not in seen:
                seen.add(target.key)
                targets.append(target)
                rows_out.append(row)
            if len(targets) >= args.limit:
                break
        if len(rows) < page_size:
            break
    return targets, rows_out


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    targets, rows = list_targets(args)
    out.write_text(
        "".join(f"{target.chain_id},{target.address}\n" for target in targets),
        encoding="utf-8",
        newline="\n",
    )
    if args.jsonl:
        jsonl = Path(args.jsonl).resolve()
        jsonl.parent.mkdir(parents=True, exist_ok=True)
        with jsonl.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Targets listed: {len(targets)}")
    print(f"Output: {out}")
    return 0 if targets else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

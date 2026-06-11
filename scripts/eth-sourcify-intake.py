#!/usr/bin/env python3
"""Download verified Ethereum contract sources from Sourcify for local scanning.

Offline after download: this script only reads public Sourcify API data and
stores source files locally. It performs no RPC calls and no transactions.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


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
    parser = argparse.ArgumentParser(
        description="Fetch Sourcify verified contract sources for batch static triage."
    )
    parser.add_argument("--chain-id", default="1", help="Chain ID. Default: 1")
    parser.add_argument(
        "--limit",
        type=int,
        default=5000,
        help="Number of contracts to fetch when --addresses-file is not provided.",
    )
    parser.add_argument(
        "--addresses-file",
        help=(
            "Optional file with one address per line. Also accepts 'chainId,address' "
            "or 'chainId address'."
        ),
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Run output directory. Sources and manifests will be written here.",
    )
    parser.add_argument(
        "--sort",
        choices=("asc", "desc"),
        default="desc",
        help="Sourcify list sort when auto-selecting contracts. Default: desc.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=200,
        help="Sourcify list page size. Max documented value is 200.",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=0.35,
        help="Delay between contract detail requests. Default: 0.35.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=35.0,
        help="HTTP timeout per request. Default: 35.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=4,
        help="Retries for 429/5xx and transient network errors. Default: 4.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Re-download contracts even when _sourcify.json already exists.",
    )
    return parser.parse_args(argv)


def http_json(url: str, args: argparse.Namespace) -> Any:
    last_error: Exception | None = None
    for attempt in range(args.retries + 1):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "evm-risk-triage-sourcify-intake/0.1",
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=args.timeout_seconds
            ) as response:
                raw = response.read()
            return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt >= args.retries:
                raise
            retry_after = exc.headers.get("Retry-After")
            delay = float(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt >= args.retries:
                raise
            time.sleep(2**attempt)
    if last_error:
        raise last_error
    raise RuntimeError(f"request failed without exception: {url}")


def read_targets_from_file(path: Path, default_chain_id: str) -> list[Target]:
    targets: list[Target] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        chain_id = default_chain_id
        address = line
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            chain_id = str(row.get("chainId", row.get("chain_id", default_chain_id)))
            address = str(row.get("address", ""))
        elif "," in line:
            left, right = [part.strip() for part in line.split(",", 1)]
            if ADDRESS_RE.match(left):
                address = left
                chain_id = right or default_chain_id
            else:
                chain_id = left
                address = right
        elif " " in line or "\t" in line:
            parts = line.split()
            if len(parts) != 2:
                raise ValueError(f"{path}:{line_no}: expected address or chainId address")
            if ADDRESS_RE.match(parts[0]):
                address, chain_id = parts[0], parts[1]
            else:
                chain_id, address = parts[0], parts[1]

        if not ADDRESS_RE.match(address):
            raise ValueError(f"{path}:{line_no}: invalid address: {address}")
        if not str(chain_id).isdigit():
            raise ValueError(f"{path}:{line_no}: invalid chainId: {chain_id}")
        targets.append(Target(str(chain_id), address))
    return dedupe_targets(targets)


def dedupe_targets(targets: Iterable[Target]) -> list[Target]:
    seen: set[str] = set()
    deduped: list[Target] = []
    for target in targets:
        if target.key in seen:
            continue
        seen.add(target.key)
        deduped.append(target)
    return deduped


def list_verified_contracts(args: argparse.Namespace) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()
    after_match_id: str | None = None
    page_size = max(1, min(args.batch_size, 200))

    while len(targets) < args.limit:
        query = {
            "limit": str(page_size),
            "sort": args.sort,
        }
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
            address = str(row.get("address", ""))
            chain_id = str(row.get("chainId", args.chain_id))
            target = Target(chain_id, address)
            if ADDRESS_RE.match(address) and target.key not in seen:
                seen.add(target.key)
                targets.append(target)
            after_match_id = str(row.get("matchId", after_match_id or ""))
            if len(targets) >= args.limit:
                break

        if len(rows) < page_size:
            break

    return targets[: args.limit]


def safe_path_parts(source_path: str) -> list[str]:
    raw_parts = re.split(r"[\\/]+", source_path)
    parts: list[str] = []
    for raw_part in raw_parts:
        part = raw_part.strip()
        if not part or part in {".", ".."}:
            continue
        part = re.sub(r"[^A-Za-z0-9._@+=-]", "_", part)
        if part in {"", ".", ".."}:
            continue
        parts.append(part[:160])
    if not parts:
        parts = ["Contract.sol"]
    return parts


def extract_sources(contract: dict[str, Any]) -> dict[str, str]:
    sources: dict[str, str] = {}
    raw_sources = contract.get("sources")
    if isinstance(raw_sources, dict):
        for source_path, value in raw_sources.items():
            if isinstance(value, dict) and isinstance(value.get("content"), str):
                sources[str(source_path)] = value["content"]
            elif isinstance(value, str):
                sources[str(source_path)] = value

    metadata = contract.get("metadata")
    metadata_sources = metadata.get("sources") if isinstance(metadata, dict) else None
    if isinstance(metadata_sources, dict):
        for source_path, value in metadata_sources.items():
            if source_path in sources:
                continue
            if isinstance(value, dict) and isinstance(value.get("content"), str):
                sources[str(source_path)] = value["content"]

    return sources


def contract_dir(out_dir: Path, target: Target) -> Path:
    return out_dir / "sources" / str(target.chain_id) / target.address.lower()


def fetch_contract(target: Target, args: argparse.Namespace) -> dict[str, Any]:
    fields = "sources,metadata,compilation,proxyResolution"
    url = (
        f"{SOURCIFY_BASE}/v2/contract/"
        f"{urllib.parse.quote(target.chain_id)}/"
        f"{urllib.parse.quote(target.address)}"
        f"?{urllib.parse.urlencode({'fields': fields})}"
    )
    return http_json(url, args)


def write_contract_sources(
    out_dir: Path, target: Target, contract: dict[str, Any]
) -> dict[str, Any]:
    target_dir = contract_dir(out_dir, target)
    source_root = target_dir / "src"
    source_root.mkdir(parents=True, exist_ok=True)

    sources = extract_sources(contract)
    written_files: list[str] = []
    for source_path, content in sources.items():
        destination = source_root.joinpath(*safe_path_parts(source_path))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
        written_files.append(str(destination.relative_to(target_dir)))

    meta = {
        "chainId": str(contract.get("chainId", target.chain_id)),
        "address": str(contract.get("address", target.address)),
        "matchId": contract.get("matchId"),
        "match": contract.get("match"),
        "creationMatch": contract.get("creationMatch"),
        "runtimeMatch": contract.get("runtimeMatch"),
        "verifiedAt": contract.get("verifiedAt"),
        "compilation": contract.get("compilation"),
        "proxyResolution": contract.get("proxyResolution"),
        "sourceCount": len(sources),
        "sourceFiles": written_files,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }
    (target_dir / "_sourcify.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    return meta


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.write_text(
        "".join(f"{line}\n" for line in lines),
        encoding="utf-8",
        newline="\n",
    )


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.addresses_file:
        targets = read_targets_from_file(Path(args.addresses_file), str(args.chain_id))
    else:
        targets = list_verified_contracts(args)

    write_lines(out_dir / "targets.txt", [f"{t.chain_id},{t.address}" for t in targets])

    index_path = out_dir / "sourcify-contracts-index.jsonl"
    failures_path = out_dir / "sourcify-failures.jsonl"
    scan_input_dirs: list[str] = []
    success_count = 0
    skipped_count = 0
    failure_count = 0

    print(f"Targets: {len(targets)}")
    for position, target in enumerate(targets, 1):
        target_dir = contract_dir(out_dir, target)
        marker = target_dir / "_sourcify.json"
        if marker.exists() and not args.overwrite:
            meta = json.loads(marker.read_text(encoding="utf-8"))
            if int(meta.get("sourceCount", 0)) > 0:
                scan_input_dirs.append(str((target_dir / "src").resolve()))
                skipped_count += 1
                continue

        try:
            contract = fetch_contract(target, args)
            meta = write_contract_sources(out_dir, target, contract)
            row = {
                "status": "ok",
                "position": position,
                "chainId": target.chain_id,
                "address": target.address,
                "sourceDir": str((target_dir / "src").resolve()),
                "sourceCount": meta["sourceCount"],
                "match": meta.get("match"),
                "runtimeMatch": meta.get("runtimeMatch"),
                "creationMatch": meta.get("creationMatch"),
                "verifiedAt": meta.get("verifiedAt"),
                "matchId": meta.get("matchId"),
            }
            append_jsonl(index_path, row)
            if int(meta["sourceCount"]) > 0:
                scan_input_dirs.append(str((target_dir / "src").resolve()))
                success_count += 1
            else:
                failure_count += 1
                append_jsonl(
                    failures_path,
                    {
                        "status": "no_sources",
                        "position": position,
                        "chainId": target.chain_id,
                        "address": target.address,
                    },
                )
        except Exception as exc:
            failure_count += 1
            append_jsonl(
                failures_path,
                {
                    "status": "error",
                    "position": position,
                    "chainId": target.chain_id,
                    "address": target.address,
                    "error": str(exc),
                },
            )
            print(f"warning: {target.key}: {exc}", file=sys.stderr)

        if position % 25 == 0 or position == len(targets):
            print(
                f"Progress: {position}/{len(targets)} "
                f"ok={success_count} skipped={skipped_count} failures={failure_count}"
            )
        if position < len(targets) and args.delay_seconds > 0:
            time.sleep(args.delay_seconds)

    write_lines(out_dir / "scan-inputs.txt", scan_input_dirs)
    summary = {
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "chainId": str(args.chain_id),
        "targetCount": len(targets),
        "successCount": success_count,
        "skippedCount": skipped_count,
        "failureCount": failure_count,
        "scanInputCount": len(scan_input_dirs),
        "outDir": str(out_dir),
        "source": "Sourcify API v2",
    }
    (out_dir / "sourcify-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )

    print(
        f"Done: ok={success_count} skipped={skipped_count} "
        f"failures={failure_count} scan_inputs={len(scan_input_dirs)}"
    )
    if not scan_input_dirs:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

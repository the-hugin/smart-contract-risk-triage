#!/usr/bin/env python3
"""Batch static triage for local smart-contract source files.

This is an offline triage helper. It does not call RPC endpoints, explorers,
or scanners. Findings are signals for manual review, not confirmed bugs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence


SOURCE_EXTENSIONS = {".sol", ".vy", ".move"}
JSON_EXTENSIONS = {".json"}
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "cache",
    "build",
    "out",
    "artifacts",
    "target",
    "__pycache__",
}

SEVERITY_SCORE = {
    "critical": 100,
    "high": 75,
    "medium": 45,
    "low": 20,
    "info": 5,
}

CONFIDENCE_SCORE = {
    "high": 18,
    "medium": 10,
    "low": 0,
}

MONEY_NAMES = {
    "withdraw",
    "withdrawal",
    "redeem",
    "claim",
    "collect",
    "payout",
    "pay",
    "sweep",
    "rescue",
    "emergency",
    "unstake",
    "unbond",
    "remove",
    "removeLiquidity",
    "burn",
    "liquidate",
    "borrow",
    "repay",
    "swap",
    "sell",
    "buy",
    "settle",
    "refund",
    "release",
}

ADMIN_NAMES = {
    "upgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "setImplementation",
    "setOracle",
    "setOwner",
    "transferOwnership",
    "setAdmin",
    "setFee",
    "pause",
    "unpause",
    "initialize",
    "init",
}

SOL_ACCESS_MARKERS = (
    "onlyOwner",
    "onlyRole",
    "onlyAdmin",
    "onlyFactory",
    "onlyFundManager",
    "onlyPoolManager",
    "onlyTreasury",
    "onlyOperator",
    "onlyStrategy",
    "onlyManagement",
    "onlyKeeper",
    "onlyAccessor",
    "isExecutor",
    "adminRequired",
    "_onlyOwnerOrSelf",
    "ifAdmin",
    "timelocked",
    "_roleRestricted",
    "_controller_",
    "_finalized_",
    "isAdmin",
    "isOwner",
    "requiresAuth",
    "_requireCallerIsContractOwner",
    "_requireFromEntryPoint",
    "auth",
    "authorized",
    "canSweep",
    "governance",
    "whenNotPaused",
)

SOL_BODY_AUTH_MARKERS = (
    "require(msg.sender",
    "require(_msgSender()",
    "if (msg.sender",
    "if (_msgSender()",
    "msg.sender !=",
    "_msgSender() !=",
    "_checkRole",
    "hasRole(",
    "owner()",
    "adminRequired",
    "OwnableUnauthorizedAccount",
    "AccessControlUnauthorizedAccount",
    "_requireCallerIsContractOwner",
    "_requireFromEntryPoint",
    "_checkRescueOwner",
    "_onlyOwnerOrSelf",
    "outbox.consume(",
    "NotRequestOwner",
    "NotOwner",
    "Unauthorized",
    "_requirePositionOwner",
    "_requireLockOwner",
    "onlyPoolManager",
    "_checkIfAdministrator",
    "timelocked()",
    "_roleRestricted(",
    "controlTower.isMarketCreator(msg.sender)",
    "NotTokenFactory",
    "factory() != msg.sender",
    "factory() == msg.sender",
)

SOL_STANDARD_TOKEN_FUNCTIONS = {
    "allowance",
    "approve",
    "balanceOf",
    "decimals",
    "getApproved",
    "isApprovedForAll",
    "name",
    "ownerOf",
    "safeTransferFrom",
    "setApprovalForAll",
    "symbol",
    "supportsInterface",
    "tokenURI",
    "totalSupply",
    "transfer",
    "transferFrom",
}

SOL_DEPENDENCY_PATH_MARKERS = (
    "/@openzeppelin/",
    "/@uniswap/",
    "/dependencies/",
    "/erc721a/",
    "/openzeppelin-contracts/",
    "/openzeppelin/contracts/",
    "/solady/",
    "/solmate/",
    "/uniswap/v3-core/",
    "/v3-core/",
    "/v4-core/",
    "/creator-token-standards/",
)

SOL_FIXTURE_PATH_MARKERS = (
    "/mock/",
    "/mocks/",
    "/test/",
    "/tests/",
    "/fixture/",
    "/fixtures/",
    "/example/",
    "/examples/",
)

SOL_STANDARD_DEPENDENCY_FILES = {
    "Address.sol",
    "AddressUpgradeable.sol",
    "BeaconProxy.sol",
    "BeforeSwapDelta.sol",
    "Clones.sol",
    "Context.sol",
    "ContextUpgradeable.sol",
    "ECDSA.sol",
    "ERC20.sol",
    "ERC20Burnable.sol",
    "ERC1967Proxy.sol",
    "ERC1967Upgrade.sol",
    "ERC721.sol",
    "ERC721A.sol",
    "ERC721C.sol",
    "ERC721OpenZeppelin.sol",
    "ERC721TL.sol",
    "Hooks.sol",
    "IERC20.sol",
    "IERC20Metadata.sol",
    "IERC1967.sol",
    "IERC721.sol",
    "IERC721A.sol",
    "Initializable.sol",
    "Ownable.sol",
    "OwnableUpgradeable.sol",
    "Proxy.sol",
    "TransparentUpgradeableProxy.sol",
    "TransferHelper.sol",
    "draft-IERC1822.sol",
}

SOL_SELF_ACCOUNTING_MARKERS = (
    "balances[msg.sender]",
    "_balances[msg.sender]",
    "balanceOf[msg.sender]",
    "shares[msg.sender]",
    "_shares[msg.sender]",
    "deposits[msg.sender]",
    "claimable[msg.sender]",
    "claimed[msg.sender]",
    "pending[msg.sender]",
    "pendingFees[msg.sender]",
    "pendingETH",
    "pendingPayout[msg.sender]",
    "claimMap[msg.sender]",
    "claimablePrize[msg.sender]",
    "ethOwed[msg.sender]",
    "_vaultBalances[msg.sender]",
    "positions[posId]",
    "shares[seriesId][msg.sender]",
    "_blorbOperators[msg.sender]",
    "ownerOf(",
    "msg.sender == owner",
    "_msgSender() == owner",
    "MerkleProof.verify",
    "merkleProof.verify",
    "NotRequestOwner",
    "_requirePositionOwner",
    "_requireLockOwner",
)

SOL_PUBLIC_BUSINESS_FUNCTIONS = {
    "buy",
    "buywithbootstrap",
    "deposit",
    "deposittoken",
    "deposittovault",
    "enter",
    "invest",
    "mint",
    "provideLiquidity",
    "purchase",
    "purchasewitheth",
    "sell",
    "sellwithbootstrap",
    "swap",
}

MOVE_AUTH_MARKERS = (
    "assert!",
    "AdminCap",
    "OwnerCap",
    "TreasuryCap",
    "Capability",
    "Cap<",
    "acl::",
    "role",
    "permission",
    "ctx.sender",
    "tx_context::sender",
)


@dataclass(frozen=True)
class FunctionBlock:
    name: str
    start_line: int
    end_line: int
    header: str
    lines: list[tuple[int, str]]
    visibility: str
    language: str

    @property
    def body_text(self) -> str:
        return "\n".join(line for _, line in self.lines)


@dataclass
class Finding:
    severity: str
    confidence: str
    funds_at_risk: bool
    category: str
    path: str
    line: int
    function: str
    signal: str
    evidence: str
    manual_check: str
    score: int = 0

    def finalize_score(self) -> "Finding":
        score = SEVERITY_SCORE[self.severity] + CONFIDENCE_SCORE[self.confidence]
        if self.funds_at_risk:
            score += 30
        if self.category in {
            "access-control",
            "upgradeability",
            "reentrancy",
            "signature-replay",
            "oracle",
            "accounting",
        }:
            score += 12
        self.score = score
        return self


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline batch triage for local smart-contract files."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="Files or directories to scan.",
    )
    parser.add_argument(
        "--input-list",
        action="append",
        default=[],
        help="Text file with one file or directory path per line.",
    )
    parser.add_argument(
        "--out-dir",
        help="Output directory. Defaults to reports/smart-contract-scan-<timestamp>.",
    )
    parser.add_argument(
        "--include-json",
        action="store_true",
        help="Also inspect JSON ABI/build artifacts. Source files are scanned by default.",
    )
    parser.add_argument(
        "--include-deps",
        action="store_true",
        help="Do not skip common dependency/build directories.",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to skip. Can be used multiple times.",
    )
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=4.0,
        help="Skip files larger than this size. Default: 4 MB.",
    )
    parser.add_argument(
        "--critical-limit",
        type=int,
        default=200,
        help="Maximum findings in critical-review.md. Default: 200.",
    )
    parser.add_argument(
        "--precheck-json",
        help=(
            "Optional read-only runtime precheck JSON keyed by contract address. "
            "Used only to downgrade already-initialized Safe/pool signals."
        ),
    )
    return parser.parse_args(argv)


def read_input_paths(args: argparse.Namespace) -> list[Path]:
    paths = [Path(item).expanduser() for item in args.inputs]
    for list_path_raw in args.input_list:
        list_path = Path(list_path_raw).expanduser()
        for raw_line in list_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            paths.append(Path(line).expanduser())
    return paths


def load_precheck_states(path_raw: str | None) -> dict[str, dict[str, object]]:
    if not path_raw:
        return {}
    path = Path(path_raw).expanduser()
    data = json.loads(path.read_text(encoding="utf-8"))
    states: dict[str, dict[str, object]] = {}
    if isinstance(data, dict):
        iterable = data.items()
    elif isinstance(data, list):
        iterable = ((item.get("address"), item) for item in data if isinstance(item, dict))
    else:
        return states
    for raw_address, raw_state in iterable:
        if not isinstance(raw_address, str) or not isinstance(raw_state, dict):
            continue
        address = raw_address.lower()
        if re.fullmatch(r"0x[a-f0-9]{40}", address):
            states[address] = dict(raw_state)
    return states


def address_from_path_label(path_label: str) -> str | None:
    normalized = path_label.replace("\\", "/").lower()
    match = re.search(r"/sources/\d+/(0x[a-f0-9]{40})(?:/|$)", f"/{normalized}")
    if match:
        return match.group(1)
    match = re.search(r"\b0x[a-f0-9]{40}\b", normalized)
    return match.group(0) if match else None


def should_skip(path: Path, excluded_dirs: set[str]) -> bool:
    return any(part in excluded_dirs for part in path.parts)


def collect_files(args: argparse.Namespace) -> list[Path]:
    allowed_exts = set(SOURCE_EXTENSIONS)
    if args.include_json:
        allowed_exts |= JSON_EXTENSIONS

    excluded_dirs = set(args.exclude_dir)
    if not args.include_deps:
        excluded_dirs |= DEFAULT_EXCLUDED_DIRS

    max_bytes = int(args.max_file_mb * 1024 * 1024)
    files: list[Path] = []
    seen: set[Path] = set()

    for raw_path in read_input_paths(args):
        path = raw_path.resolve()
        if not path.exists():
            print(f"warning: input does not exist: {path}", file=sys.stderr)
            continue
        candidates: Iterable[Path]
        if path.is_file():
            candidates = [path]
        else:
            candidates = path.rglob("*")

        for candidate in candidates:
            if not candidate.is_file():
                continue
            if should_skip(candidate, excluded_dirs):
                continue
            if candidate.suffix.lower() not in allowed_exts:
                continue
            if candidate.stat().st_size > max_bytes:
                print(f"warning: skipped large file: {candidate}", file=sys.stderr)
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(resolved)

    files.sort(key=lambda item: str(item).lower())
    return files


def detect_language(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".sol":
        return "solidity"
    if suffix == ".move":
        return "move"
    if suffix == ".vy":
        return "vyper"
    if suffix == ".json":
        return "json"
    return "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_sourcify_compiler_version(path: Path) -> str | None:
    for parent in (path.parent, *path.parents):
        meta_path = parent / "_sourcify.json"
        if not meta_path.exists():
            continue
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        compilation = data.get("compilation")
        if isinstance(compilation, dict):
            version = compilation.get("compilerVersion")
            if isinstance(version, str) and version:
                return version
        return None
    return None


def find_sourcify_runtime_source(path: Path) -> str | None:
    sources = find_sourcify_runtime_sources(path)
    return sources[0] if sources else None


def find_sourcify_runtime_sources(path: Path) -> tuple[str, ...]:
    for parent in (path.parent, *path.parents):
        meta_path = parent / "_sourcify.json"
        if not meta_path.exists():
            continue
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ()
        sources: list[str] = []
        compilation = data.get("compilation")
        if isinstance(compilation, dict):
            fully_qualified = compilation.get("fullyQualifiedName")
            if isinstance(fully_qualified, str) and ":" in fully_qualified:
                source_name, _ = fully_qualified.rsplit(":", 1)
                sources.append(source_name.replace("\\", "/").lower())
        proxy_resolution = data.get("proxyResolution")
        if isinstance(proxy_resolution, dict):
            implementations = proxy_resolution.get("implementations")
            if isinstance(implementations, list):
                for implementation in implementations:
                    if not isinstance(implementation, dict):
                        continue
                    name = implementation.get("name")
                    if isinstance(name, str) and name:
                        sources.append(f"{name.lower()}.sol")
        return tuple(dict.fromkeys(sources))
    return ()


def find_sourcify_runtime_contracts(path: Path) -> tuple[str, ...]:
    for parent in (path.parent, *path.parents):
        meta_path = parent / "_sourcify.json"
        if not meta_path.exists():
            continue
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        names: list[str] = []
        compilation = data.get("compilation")
        if isinstance(compilation, dict):
            fully_qualified = compilation.get("fullyQualifiedName")
            if isinstance(fully_qualified, str) and ":" in fully_qualified:
                _, contract_name = fully_qualified.rsplit(":", 1)
                names.append(contract_name)
            name = compilation.get("name")
            if isinstance(name, str):
                names.append(name)
        return tuple(dict.fromkeys(names))
    return ()


def source_matches_runtime(path_label: str, runtime_source: str | Sequence[str] | None) -> bool:
    if not runtime_source:
        return True
    normalized = path_label.replace("\\", "/").lower()
    runtime_sources = (
        (runtime_source,) if isinstance(runtime_source, str) else tuple(runtime_source)
    )
    for source in runtime_sources:
        runtime = source.lstrip("/").lower()
        if normalized.endswith(runtime):
            return True
        if "/" not in runtime and Path(normalized).name == runtime:
            return True
    return False


def is_fixture_or_example_source(path_label: str) -> bool:
    normalized_path = path_label.replace("\\", "/").lower()
    normalized = f"/{normalized_path}"
    name = Path(path_label).name.lower()
    return any(marker in normalized for marker in SOL_FIXTURE_PATH_MARKERS) or name.startswith("mock")


def solidity_version_before_08(version: str | None) -> bool:
    if not version:
        return False
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return False
    major = int(match.group(1))
    minor = int(match.group(2))
    return major == 0 and minor < 8


def source_pragma_before_08(text: str) -> bool:
    for match in re.finditer(r"\bpragma\s+solidity\s+([^;]+);", text):
        spec = match.group(1)
        if re.search(r"\b0\.[0-7]\.\d+", spec):
            return True
        if "<0.8" in spec.replace(" ", ""):
            return True
    return False


def relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def strip_line_comment(line: str, language: str) -> str:
    if language in {"solidity", "vyper"}:
        return line.split("//", 1)[0]
    if language == "move":
        return line.split("//", 1)[0]
    return line


def strip_source_comments(lines: list[str], language: str) -> list[str]:
    if language not in {"solidity", "vyper", "move"}:
        return lines
    stripped: list[str] = []
    in_block = False
    for line in lines:
        index = 0
        output: list[str] = []
        while index < len(line):
            if in_block:
                end = line.find("*/", index)
                if end == -1:
                    index = len(line)
                    continue
                in_block = False
                index = end + 2
                continue

            block_start = line.find("/*", index)
            line_start = line.find("//", index)
            next_markers = [
                pos for pos in (block_start, line_start) if pos != -1
            ]
            if not next_markers:
                output.append(line[index:])
                break
            marker = min(next_markers)
            output.append(line[index:marker])
            if marker == line_start:
                break
            in_block = True
            index = marker + 2
        stripped.append("".join(output))
    return stripped


def extract_function_name(line: str, language: str) -> tuple[str, str] | None:
    clean = strip_line_comment(line, language)
    if language == "solidity":
        if re.search(r"\bconstructor\s*\(", clean):
            return "constructor", "constructor"
        if re.search(r"\breceive\s*\(", clean):
            return "receive", "external"
        if re.search(r"\bfallback\s*\(", clean):
            return "fallback", "external"
        match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean)
        if match:
            visibility = "unknown"
            for candidate in ("external", "public", "internal", "private"):
                if re.search(rf"\b{candidate}\b", clean):
                    visibility = candidate
                    break
            return match.group(1), visibility
    if language == "move":
        match = re.search(
            r"\b(public(?:\([^)]+\))?\s+)?(entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)",
            clean,
        )
        if match:
            visibility = "public" if match.group(1) else "private"
            if match.group(2):
                visibility = f"{visibility} entry"
            return match.group(3), visibility
    if language == "vyper":
        match = re.search(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean)
        if match:
            visibility = "external" if "@external" in clean else "unknown"
            return match.group(1), visibility
    return None


def extract_functions(lines: list[str], language: str) -> list[FunctionBlock]:
    functions: list[FunctionBlock] = []
    active_name: str | None = None
    active_visibility = "unknown"
    start_line = 0
    header_parts: list[str] = []
    body_lines: list[tuple[int, str]] = []
    brace_depth = 0
    pending_header = False

    for index, line in enumerate(lines, start=1):
        detected = None if active_name else extract_function_name(line, language)
        if detected:
            active_name, active_visibility = detected
            start_line = index
            header_parts = [line.strip()]
            body_lines = [(index, line)]
            clean = strip_line_comment(line, language)
            if language == "solidity" and "{" not in clean and ";" in clean:
                active_name = None
                continue
            brace_depth = clean.count("{") - clean.count("}")
            pending_header = "{" not in clean
            if brace_depth <= 0 and not pending_header:
                functions.append(
                    FunctionBlock(
                        name=active_name,
                        start_line=start_line,
                        end_line=index,
                        header=" ".join(header_parts),
                        lines=body_lines,
                        visibility=active_visibility,
                        language=language,
                    )
                )
                active_name = None
            continue

        if active_name:
            body_lines.append((index, line))
            clean = strip_line_comment(line, language)
            if pending_header:
                header_parts.append(line.strip())
                if language == "solidity" and "{" not in clean and ";" in clean:
                    active_name = None
                    active_visibility = "unknown"
                    start_line = 0
                    header_parts = []
                    body_lines = []
                    brace_depth = 0
                    pending_header = False
                    continue
                if "{" in clean:
                    pending_header = False
            brace_depth += clean.count("{") - clean.count("}")
            if brace_depth <= 0 and not pending_header:
                functions.append(
                    FunctionBlock(
                        name=active_name,
                        start_line=start_line,
                        end_line=index,
                        header=" ".join(header_parts),
                        lines=body_lines,
                        visibility=active_visibility,
                        language=language,
                    )
                )
                active_name = None
                active_visibility = "unknown"
                start_line = 0
                header_parts = []
                body_lines = []
                brace_depth = 0

    return functions


def contains_any(text: str, needles: Iterable[str], *, lower: bool = False) -> bool:
    haystack = text.lower() if lower else text
    for needle in needles:
        candidate = needle.lower() if lower else needle
        if candidate in haystack:
            return True
    return False


def is_money_function(name: str, body: str) -> bool:
    lowered = name.lower()
    return any(marker.lower() in lowered for marker in MONEY_NAMES)


def is_standard_token_function(name: str) -> bool:
    return name in SOL_STANDARD_TOKEN_FUNCTIONS


def is_standard_dependency_file(path_label: str) -> bool:
    normalized = "/" + path_label.replace("\\", "/").lstrip("/").lower()
    if not any(marker in normalized for marker in SOL_DEPENDENCY_PATH_MARKERS):
        return False
    return Path(path_label).name in SOL_STANDARD_DEPENDENCY_FILES


def is_admin_function(name: str, body: str) -> bool:
    lowered = name.lower()
    exact_names = {
        "init",
        "initialize",
        "reinitialize",
        "upgrade",
        "upgradeto",
        "upgradetoandcall",
        "setimplementation",
        "transferownership",
        "renounceownership",
        "pause",
        "unpause",
    }
    prefixes = (
        "set",
        "update",
        "configure",
        "upgrade",
        "pause",
        "unpause",
        "initialize",
        "reinitialize",
    )
    return lowered in exact_names or lowered.startswith(prefixes)


def is_non_runtime_bundle_source(
    path_label: str, runtime_source: str | Sequence[str] | None
) -> bool:
    return bool(runtime_source and not source_matches_runtime(path_label, runtime_source))


def enclosing_contract_name(lines: list[str], start_line: int) -> str | None:
    for line in reversed(lines[: max(0, start_line - 1)]):
        clean = strip_line_comment(line, "solidity")
        match = re.search(r"\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", clean)
        if match:
            return match.group(1)
    return None


def is_non_runtime_same_file_contract(
    block: FunctionBlock,
    lines: list[str],
    runtime_contracts: Sequence[str] | None,
) -> bool:
    if not runtime_contracts:
        return False
    contract_name = enclosing_contract_name(lines, block.start_line)
    return bool(contract_name and contract_name not in set(runtime_contracts))


def is_standard_safe_setup(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    if block.name != "setup":
        return False
    normalized = path_label.replace("\\", "/").lower()
    haystack = f"{normalized}\n{file_text}".lower()
    return (
        "gnosissafeproxy" in haystack
        or "gnosissafe.sol" in haystack
        or "checknsignatures" in haystack
    ) and all(
        marker in block.header.lower()
        for marker in ("owners", "threshold")
    )


def is_standard_proxy_initializer(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    if block.name.lower() not in {"initialize", "init"}:
        return False
    normalized = path_label.replace("\\", "/").lower()
    haystack = f"{normalized}\n{file_text}".lower()
    return (
        "initializableupgradeabilityproxy" in haystack
        or "transparentupgradeableproxy" in haystack
        or "erc1967proxy" in haystack
    ) and (
        "_implementation() == address(0)" in haystack
        or "implementation_slot" in haystack
        or "eip1967.proxy.implementation" in haystack
    )


def is_standard_amm_source(file_text: str, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    haystack = f"{normalized}\n{file_text}".lower()
    markers = (
        "contract pancakepair",
        "contract uniswapv3pool",
    "contract pancakev3pool",
    "contract algebrapool",
    "contract ethervistapair",
        "uniswapv2pair",
        "iuniswapv3pool",
        "slot0",
        "getreserves",
    )
    return any(marker in haystack for marker in markers)


def is_standard_amm_function(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    if not is_standard_amm_source(file_text, path_label):
        return False
    return block.name.lower() in {
        "initialize",
        "burn",
        "mint",
        "swap",
        "collect",
        "flash",
        "skim",
        "sync",
        "getreserves",
        "slot0",
        "getspotprice",
        "getspotpricesansfee",
        "setfeeprotocol",
        "movepricetowardstarget",
    }


def is_payout_or_request_bound(body: str) -> bool:
    lowered = body.lower()
    merkle_bound = "merkleproof.verify" in lowered and "msg.sender" in lowered
    request_owner = (
        "notrequestowner" in body
        or "r.owner != msg.sender" in body
        or "d.owner != msg.sender" in body
        or "_requirepositionowner" in lowered
        or "_requirelockowner" in lowered
    )
    escrow_bound = any(
        marker in lowered
        for marker in (
            "claimed[msg.sender]",
            "claimable[msg.sender]",
            "pending[msg.sender]",
            "referralaccrued[msg.sender]",
            "bonusescrowed[msg.sender]",
        )
    )
    return merkle_bound or request_owner or escrow_bound


def is_payment_splitter_release(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    haystack = f"{normalized}\n{file_text}".lower()
    lowered = block.body_text.lower()
    return (
        ("paymentsplitter.sol" in haystack or "contract paymentsplitter" in haystack)
        and block.name.lower() == "release"
        and "_shares[account]" in lowered
        and ("_released" in lowered or "_erc20released" in lowered)
        and "payment" in lowered
        and "releasable" in lowered
    )


def is_vault_allowance_bookkeeping_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    if "_vaultallowance[msg.sender]" not in lowered and "_adjustallowances(" not in lowered:
        return False
    if ".call{value" in lowered or ".transfer(msg.sender" in lowered or ".safetransfer(msg.sender" in lowered:
        return False
    return "msg.value" in lowered or "_vaultallowance[msg.sender]" in lowered


def is_vault_allowance_guarded_transfer_flow(block: FunctionBlock) -> bool:
    haystack = f"{block.header}\n{block.body_text}".lower()
    return (
        "_vaultallowance[msg.sender]" in haystack
        and "-=" in haystack
        and "nonreentrant" in haystack
    )


def is_notary_commitment_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    has_recover_or_hash = "commitmenthash" in lowered or "ecdsa.recover" in lowered
    has_notary = "notary" in lowered
    has_state_bound = any(
        marker in lowered
        for marker in (
            "nonce",
            "claimedamount",
            "claimed[",
            "stakedamount",
            "stakechannelnonce",
            "reservechannelbalance",
        )
    )
    return has_recover_or_hash and has_notary and has_state_bound


def is_inbound_transfer_only_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    if "transferfrom" not in lowered:
        return False
    outgoing_markers = (
        ".call{value",
        ".send(",
        ".transfer(msg.sender",
        ".safetransfer(msg.sender",
        ".transfer(_msgsender()",
        ".safetransfer(_msgsender()",
    )
    return not any(marker in lowered for marker in outgoing_markers)


def is_recipient_or_approved_withdrawal_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    name = block.name.lower()
    if name == "withdrawmax" and "withdraw({ streamid: streamid" in lowered:
        return True
    return (
        name.startswith("withdraw")
        and "_ownerof(" in lowered
        and (
            "_iscallerstreamrecipientorapproved" in lowered
            or "withdrawaladdressnotrecipient" in lowered
            or "to != recipient" in lowered
        )
    )


def is_user_funded_launchpad_flow(block: FunctionBlock, path_label: str) -> bool:
    lowered = block.body_text.lower()
    normalized = path_label.replace("\\", "/").lower()
    name = block.name.lower()
    if not any(marker in normalized for marker in ("launchpad", "bondingcurve", "bonding-curve")):
        return False
    if name.startswith("buy"):
        return "msg.value" in lowered and "min" in lowered and "deadline" in lowered
    if name.startswith("sell"):
        return "safetransferfrom(msg.sender" in lowered and "min" in lowered and "deadline" in lowered
    return False


def is_swap_aggregator_user_flow(block: FunctionBlock, path_label: str) -> bool:
    lowered = block.body_text.lower()
    normalized = path_label.replace("\\", "/").lower()
    name = block.name.lower()
    router_like = (
        "router" in normalized
        or "aggregator" in normalized
        or "wrapper" in normalized
        or name.startswith(("swap", "_single", "_split", "_sequential"))
    )
    if not router_like:
        return False
    if any(marker in lowered for marker in (".transfer(msg.sender", ".safetransfer(msg.sender", "token.balanceof(address(this))")):
        return False
    return any(
        marker in lowered
        for marker in (
            "amountoutmin",
            "minamountout",
            "deadline",
            "recipient",
            "receiver",
            "permit2",
            "swaprouter",
            "negative slippage",
            "negative_slippage",
        )
    )


def is_hook_fee_callback_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    name = block.name.lower()
    return (
        "hook" in normalized
        and name in {"beforeswap", "_beforeswap", "afterswap", "_afterswap"}
        and ("poolmanager" in lowered or "basehook" in normalized)
    )


def is_self_delegatecall_wrapper(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return "address(this)" in lowered and ".delegatecall(" in lowered and "abi.encodecall(" in lowered


def is_tax_or_router_maintenance_swap(block: FunctionBlock, path_label: str) -> bool:
    lowered = block.body_text.lower()
    normalized = path_label.replace("\\", "/").lower()
    name = block.name.lower()
    if name not in {
        "swaptokensforeth",
        "manualswap",
        "swapback",
        "_swaptokensforeth",
        "_swaptax",
        "swapfeesmanually",
    }:
        return False
    if (
        name == "swapback"
        and any(marker in lowered or marker in normalized for marker in ("tax", "fee", "marketing", "devwallet"))
        and solidity_effective_visibility(block) in {"private", "internal"}
    ):
        return True
    if (
        name in {"_swaptax", "swapfeesmanually"}
        and any(marker in lowered or marker in normalized for marker in ("tax", "fee", "treasury", "marketing"))
        and (
            solidity_effective_visibility(block) in {"private", "internal"}
            or re.search(r"\bonly[A-Za-z0-9_]*\b", block.header)
        )
    ):
        return True
    if "uniswap" not in lowered and "router" not in lowered and "pancake" not in lowered:
        return False
    return (
        solidity_effective_visibility(block) in {"private", "internal"}
        or "onlyowner" in block.header.lower()
        or "owner()" in lowered
        or "marketing" in lowered
        or "tax" in normalized
    )


def is_fixed_masterwallet_transferfrom_sweeper(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    header = block.header.lower()
    name = block.name.lower()
    if "truefinsweeper" not in normalized and "masterwallet" not in lowered:
        return False
    if name in {"sweepbatch", "sweepbatchsupportedtoken"}:
        return "_sweepbatchfortoken(" in lowered and (
            "tokenexists" in lowered or "usdttoken" in lowered
        )
    if name not in {"sweepwallet", "_sweepbatchfortoken"}:
        return False
    has_wallet_gate = (
        "onlyapproved" in header
        or "approvedwallets" in lowered
    ) and "issweepenabled" in lowered
    has_allowance = "allowance(" in lowered and ("allowed <" in lowered or "allowed < bal" in lowered)
    has_fixed_recipient = "masterwallet" in lowered and "msg.sender" not in lowered
    has_transferfrom_call = "0x23b872dd" in lowered or "transferfrom" in lowered
    has_success_check = "callsuccess" in lowered and "returndata" in lowered and "transferred" in lowered
    return (
        has_wallet_gate
        and has_allowance
        and has_fixed_recipient
        and has_transferfrom_call
        and has_success_check
    )


def is_owner_only_registry_loop(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    header = block.header.lower()
    name = block.name.lower()
    if not any(marker in header for marker in ("onlyowner", "onlyadmin")) or not has_loop(block.body_text):
        return False
    if name not in {
        "addsubs",
        "removesubs",
        "removesupportedtoken",
        "registerandfundwalletsbatch",
        "removetokens",
        "addtokens",
    }:
        return False
    return any(
        marker in lowered
        for marker in (
            "_subs.",
            "supportedtokens",
            "tokenexists",
            "approvedwallets",
            "amfiusers",
            "gas_fee_amount",
            "_tokeninfomap",
            "_tokenaddressarray",
        )
    )


def is_owner_bound_cell_claim_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    name = block.name.lower()
    if "cellhook.sol" not in normalized and "celldish.sol" not in normalized:
        return False
    if name == "claim":
        return "_claim(_idof(msg.sender),msg.sender)" in re.sub(r"\s+", "", lowered)
    if name == "claimeth":
        compact = re.sub(r"\s+", "", lowered)
        return "_claimeth(_idof(msg.sender),msg.sender)" in compact and "_sendeth(msg.sender" in compact
    if name in {"_claim", "_claimeth"}:
        return (
            "c.owner != caller" in lowered
            and "notowner" in lowered
            and "fee_warmup" in lowered
            and ("claimable[id]" in lowered or "_draineth(id)" in lowered)
        )
    return False


def is_cell_hook_erc20_transfer_override(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    name = block.name.lower()
    return (
        "cellhook.sol" in normalized
        and name in {"transfer", "transferfrom"}
        and ("super.transfer(" in lowered or "super.transferfrom(" in lowered)
        and "_afterbalance(" in lowered
    )


def is_cell_bucket_accounting(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    return (
        "celldish.sol" in normalized
        and block.name.lower() == "_removefrombucket"
        and "bucketcells" in lowered
        and "bucketpos" in lowered
        and "livecells" in lowered
    )


def is_account_levels_test_setter(block: FunctionBlock, path_label: str) -> bool:
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        block.name.lower() == "setaccountlevel"
        and "accountlevels[user]=level" in compact
    )


def is_legacy_constructor_like(block: FunctionBlock, file_text: str, old_compiler: bool) -> bool:
    if not old_compiler:
        return False
    name = block.name
    if name in {"constructor", "receive", "fallback"}:
        return False
    return bool(re.search(rf"\bcontract\s+{re.escape(name)}\b", file_text))


def is_ens_deed_destroy_cleanup(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/deed.sol")
        and block.name.lower() == "destroydeed"
        and "if(active)throw" in compact
        and "owner.send(this.balance)" in compact
        and "selfdestruct(burn)" in compact
    )


def is_ens_deed_selfdestruct_source(file_text: str, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", file_text.lower())
    return (
        normalized.endswith("/deed.sol")
        and "contractdeed{" in compact
        and "functiondestroydeed()" in compact
        and "if(active)throw" in compact
        and "owner.send(this.balance)" in compact
        and "selfdestruct(burn)" in compact
    )


def is_pixel_selling_guarded_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    compact = re.sub(r"\s+", "", lowered)
    name = block.name.lower()
    if not normalized.endswith("/pixelselling.sol"):
        return False
    if name in {"setimage", "setmessage", "setsaleimg"}:
        return "l.owner==msg.sender" in compact and "locations[id]" in compact
    if name in {"setsaleshare", "collectprovisions"}:
        return "s.owner==msg.sender" in compact and "shares[id]" in compact
    if name == "buyemptylocation":
        return "l.owner==0x0" in compact and "msg.value==latestprice" in compact
    if name == "buyimagepriv":
        return (
            "l.sale==true" in compact
            and "(l.saleto==msg.sender||l.saleto==0x0)" in compact
            and "msg.value==l.price" in compact
        )
    if name == "buysharepriv":
        return (
            "s.sale==true" in compact
            and "(s.saleto==msg.sender||s.saleto==0x0)" in compact
            and "msg.value==s.price" in compact
        )
    return False


def is_crowdsale_finalize_fixed_master_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    compact = re.sub(r"\s+", "", lowered)
    return (
        block.name.lower() == "finalize"
        and "funding=false" in compact
        and "master.send(this.balance)" in compact
        and "fundingend" in lowered
        and "tokencreationmin" in lowered
        and "tokencreationcap" in lowered
    )


def is_token_trader_user_purchase_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    if not normalized.endswith("/tokentrader.sol"):
        return False
    name = block.name.lower()
    fixed_price_buy = (
        name in {"buy", "takerbuyasset"}
        and "msg.value/sellprice" in compact
        and "erc20(asset).balanceof(address(this))" in compact
        and "msg.sender.send(change)" in compact
        and "erc20(asset).transfer(msg.sender" in compact
    )
    owner_withdraw = (
        name in {"withdraw", "makerwithdrawether"}
        and "onlyowner" in block.header.lower()
        and (
            "owner.send(_value)" in compact
            or "owner.transfer(_value)" in compact
            or "owner.send(ethers)" in compact
            or "owner.transfer(ethers)" in compact
        )
    )
    return fixed_price_buy or owner_withdraw


def is_plain_storage_getter(block: FunctionBlock) -> bool:
    if solidity_has_external_transfer(block.body_text) or ".call" in block.body_text:
        return False
    compact = re.sub(r"\s+", " ", block.body_text.strip())
    if not re.search(r"\breturn\s+[A-Za-z_][\w.\[\]]*\s*;?\s*}?\s*$", compact):
        return False
    return not any(marker in compact for marker in ("=", "++", "--", ".transfer", ".send"))


def is_legacy_blockcdn_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    if not normalized.endswith("/blockcdn.sol"):
        return False
    if name == "buyblockcdn":
        return "balances[msg.sender]+=token" in compact and "fundvalue[msg.sender]+=msg.value" in compact
    if name in {"refund", "refundbyother"}:
        return (
            "iffundedmini)throw" in compact or "if(isfundedmini)throw" in compact
        ) and (
            "fundvalue[msg.sender]=0" in compact or "fundvalue[_fundaddr]=0" in compact
        )
    if name == "transfer":
        return "balances[msg.sender]-=_value" in compact and "balances[_to]+=_value" in compact
    return False


def is_singulardtv_soft_withdraw_credit(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/singulardtvfund.sol")
        and block.name.lower() == "softwithdrawrevenuefor"
        and "calcrevenue(foraddress)" in compact
        and "revenueattimeofwithdraw[foraddress]=totalrevenue" in compact
        and "owed[foraddress]+=value" in compact
        and not solidity_has_external_transfer(block.body_text)
    )


def is_fixed_price_user_token_buyback(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/bokkypoobahsetherrefundableprize.sol")
        and block.name.lower() == "selltokens"
        and "balances[msg.sender]-=amountoftokens" in compact
        and "_totalsupply-=amountoftokens" in compact
        and "amountoftokens*sellprice()/1ether" in compact
        and "msg.sender.send(etherstosend)" in compact
    )


def is_exchange_order_readonly_check(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    exchange_files = (
        "/etherdelta.sol",
        "/dex.sol",
        "/decentrex.sol",
        "/azexchange.sol",
        "/axnet.sol",
        "/ethererc.sol",
        "/exchangewhitelist.sol",
    )
    if not normalized.endswith(exchange_files):
        return False
    if name == "availablevolume":
        return (
            "ecrecover" in compact
            and "block.number<=expires" in compact
            and "orderfills" in compact
            and "returnavailable" in compact
            and not solidity_has_external_transfer(block.body_text)
        )
    if name == "testtrade":
        return (
            "constant" in block.header.lower()
            and "ecrecover" in compact
            and "block.number>expires" in compact
            and "orderfills" in compact
            and not solidity_has_external_transfer(block.body_text)
        )
    return False


def is_user_owned_burn_redeem_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    if normalized.endswith("/bondtokencollateralizedeth.sol") and name in {"burn", "burnall"}:
        return "_burn(msg.sender,amount)" in compact or "amount=balanceof(msg.sender)" in compact
    if normalized.endswith("/head.sol") and name == "_burn":
        return "account" in compact and "_balances[account]" in compact and "_totalsupply" in compact
    return False


def is_inbound_balance_delta_accounting(block: FunctionBlock) -> bool:
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        "balancebefore" in compact
        and "safetransferfrom(msg.sender,address(this)" in compact
        and (
            "actualreceived=tokencontract.balanceof(address(this))-balancebefore" in compact
            or "actualreceived=balanceafter-balancebefore" in compact
        )
    )


def is_bittrex_userwallet_controller_helper(
    block: FunctionBlock, file_text: str, path_label: str
) -> bool:
    haystack = f"{path_label}\n{file_text}".replace("\\", "/").lower()
    return (
        "contract userwallet" in haystack
        and "contract controller is abstractsweeperlist" in haystack
        and block.name.lower() in {"sweeperof", "logsweep"}
        and not solidity_has_external_transfer(block.body_text)
    )


def is_opyn_otoken_user_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    if not normalized.endswith("/otoken.sol"):
        return False
    if name in {
        "buyotokens",
        "createandsellethcollateraloption",
        "addandsellethcollateraloption",
        "createandsellerc20collateraloption",
        "addandsellerc20collateraloption",
    }:
        return True
    if name in {"transfercollateral", "transferunderlying"}:
        return "internal" in block.header.lower()
    return False


def is_legacy_e4token_segmented_payout_loop(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/e4token.sol")
        and block.name.lower() == "dopayout"
        and "internal" in block.header.lower()
        and "paids<_numpays" in compact
        and "lastpayoutindex" in compact
        and "holderaccounts[a].balance+=namount" in compact
        and "payoutbalance-=int(namount)" in compact
        and not solidity_has_external_transfer(block.body_text)
    )


def is_ownable_delegate_proxy_upgrade_call(
    block: FunctionBlock, file_text: str, path_label: str
) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/ownabledelegateproxy.sol")
        and block.name.lower() == "upgradetoandcall"
        and "onlyproxyowner" in block.header.lower()
        and "modifieronlyproxyowner()" in compact_file
        and "msg.sender==proxyowner()" in compact_file
        and "require(address(this).delegatecall(data))" in compact
    )


def is_ante_pool_factory_initializer(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/antepool.sol")
        and block.name.lower() == "initialize"
        and "notinitialized" in block.header.lower()
        and "msg.sender==factory" in compact
        and "_initialized=true" in compact
    )


def is_layerzero_readlib_fee_or_verification_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    if not normalized.endswith("/readlib1002.sol"):
        return False
    if name == "withdrawfee":
        return "fee=fees[msg.sender]" in compact and "fees[msg.sender]=fee-_amount" in compact
    if name == "_verifyandreclaimstorage":
        return "_checkverifiable(" in compact and "requireddvncount" in compact and "optionaldvncount" in compact
    return False


def is_teambrella_multisig_wallet_flow(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    if not normalized.endswith("/teambrellawallet.sol"):
        return False
    if name == "realtransfer":
        return "private" in block.header.lower() and "tos[i].transfer(values[i])" in compact
    return (
        name in {"safer_ecrecover", "ecrecovery", "ecverify"}
        and "checksignatures" in compact_file
        and "m_opnum" in compact_file
    )


def is_safu_presale_liquidity_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/safuinvestmentspresale.sol")
        and block.name.lower() == "addliquidityandlocklptokens"
        and "uniliquidityadded=true" in compact
        and "uniswaprouter.addliquidityeth" in compact
        and "safuliqlockaddress" in compact
    )


def is_legacy_lottery_user_or_owner_flow(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    if not normalized.endswith("/cethereumlotterynet.sol"):
        return False
    if name == "usergetprize":
        return (
            "players[msg.sender][a].paid=true" in compact
            and "games[a].prizepot-=gamebalance" in compact
            and "msg.sender.send(balance)" in compact
        )
    if name == "useraddticket":
        return (
            "ticketprice" in compact
            and "msg.value" in compact
            and "ticketscount>70" in compact
            and "players[msg.sender][currentgameid].tickets" in compact
        )
    if name == "adminclosecontract":
        return "onlyowner" in block.header.lower() and "owner.send(contractbalance)" in compact
    return False


def is_third_party_refund_to_beneficiary(block: FunctionBlock) -> bool:
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    return (
        name in {"refundbyother", "refundfor", "refundbyaddr", "refundaddress"}
        or "refundbyother" in name
    ) and (
        "fundvalue[_fundaddr]" in compact
        and "fundvalue[_fundaddr]=0" in compact
        and "_fundaddr.send(value)" in compact
    )


def is_fixed_owner_timelock_unlock(block: FunctionBlock) -> bool:
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        block.name.lower() in {"unlocketh", "unlock", "release"}
        and "block.timestamp>_endoflockup" in compact
        and "_contractowner.transfer(address(this).balance)" in compact
    )


def is_bittrex_userwallet_sweep_flow(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    haystack = f"{path_label}\n{file_text}".replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    name = block.name.lower()
    return (
        "contract defaultsweeper" in haystack
        and "modifier cansweep" in haystack
        and "contract userwallet" in haystack
        and name == "sweep"
        and (
            "sweeperlist.sweeperof(_token).delegatecall(msg.data)" in compact
            or (
                "cansweep" in block.header.lower()
                and "controller.destination()" in compact
                and ("destination.send(amountinwei)" in compact or "token.transfer(destination" in compact)
            )
        )
    )


def is_parity_v1_wallet_fixed_library_delegatecall(
    block: FunctionBlock, file_text: str, path_label: str
) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    compact_body = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/wallet.sol")
        and "contractwalletiswalletevents" in compact_file
        and "addressconstant_walletlibrary=0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4" in compact_file
        and block.name.lower() in {"hasconfirmed", "isowner"}
        and "return_walletlibrary.delegatecall(msg.data)" in compact_body
    )


def is_consensys_multisig_owner_management_loop(
    block: FunctionBlock, file_text: str, path_label: str
) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    header = block.header.lower()
    return (
        (
            normalized.endswith("/multisigwalletwithdailylimit.sol")
            and "contractmultisigwalletwithdailylimitismultisigwallet" in compact_file
            or normalized.endswith("/multisigwallet.sol")
            and "contractmultisigwallet{" in compact_file
            or normalized.endswith("/tokenmanager.sol")
            and "contracttokenmanagerismultisigwallet" in compact_file
        )
        and "modifieronlywallet()" in compact_file
        and "address[]publicowners" in compact_file
        and block.name.lower() in {"removeowner", "replaceowner"}
        and "onlywallet" in header
    )


def is_openzeppelin_beacon_proxy_helper(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    filename = Path(path_label).name.lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    lowered = block.body_text.lower()
    name = block.name.lower()
    return (
        filename == "beaconproxy.sol"
        and "contractbeaconproxyisproxy,erc1967upgrade" in compact_file
        and name in {"functioncallwithvalue", "functiondelegatecall"}
        and "verifycallresultfromtarget" in lowered
    )


def is_rocket_minipool_delegate_fallback(
    block: FunctionBlock, file_text: str, path_label: str
) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    compact_body = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/rocketminipool.sol")
        and "contractrocketminipoolisrocketminipoolstoragelayout" in compact_file
        and "getcontractaddress(\"rocketminipooldelegate\")" in compact_file
        and block.name.lower() == "fallback"
        and "delegatecontract=uselatestdelegate?getcontractaddress(\"rocketminipooldelegate\"):rocketminipooldelegate" in compact_body
        and "require(contractexists(delegatecontract)" in compact_body
        and "delegatecontract.delegatecall(_input)" in compact_body
    )


def is_legacy_wallet_owner_delegate_deposit(
    block: FunctionBlock, file_text: str, path_label: str
) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact_file = re.sub(r"\s+", "", file_text.lower())
    compact_body = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/wallet.sol")
        and "contractwalletismultisig,multiowned,daylimit" in compact_file
        and block.name.lower() == "deposit"
        and "address(m_owners[1])!=sender" in compact_body
        and "address(m_owners[1]).delegatecall()" in compact_body
    )


def is_public_ico_status_update(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    compact = re.sub(r"\s+", "", lowered)
    return (
        block.name.lower() == "updateicostatus"
        and "icostatus" in lowered
        and "fundingdeadline" in lowered
        and "getnumtokenspurchased()" in compact
        and "getnumgames()" in compact
        and not solidity_has_external_transfer(block.body_text)
    )


def is_ico_refund_request_flow(block: FunctionBlock) -> bool:
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        block.name.lower() == "requestrefund"
        and "nrequester=msg.sender" in compact
        and "holderaccounts[nrequester]" in compact
        and (
            "nrequester.send(nrefund)" in compact
            or "msg.sender.send(nrefund)" in compact
            or "nrequester.call.gas(rfgas).value(nrefund)()" in compact
        )
    )


def is_merkle_bound_user_position_update(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    compact = re.sub(r"\s+", "", lowered)
    return (
        block.name.lower() == "updateuserposition"
        and "_verifymerkleproof(" in lowered
        and "_verifymerkleproof(msg.sender" in compact
        and "lastupdateversion" in lowered
    )


def is_public_decay_update(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return (
        block.name.lower() == "updatedecay"
        and "_computedecay()" in lowered
        and "lastupdateblock" in lowered
        and not solidity_has_external_transfer(block.body_text)
    )


def is_safu_presale_cancel_guarded(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    compact = re.sub(r"\s+", "", block.body_text.lower())
    return (
        normalized.endswith("/safuinvestmentspresale.sol")
        and block.name.lower() == "cancelandtransfertokenstopresalecreator"
        and "presalecreatoraddress!=msg.sender" in compact
        and "safudevaddress!=msg.sender" in compact
        and "presalecancelled=true" in compact
        and "token.transfer(presalecreatoraddress" in compact
    )


def is_checked_low_level_call_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    compact = re.sub(r"\s+", "", lowered)
    return any(
        marker in lowered
        for marker in (
            "require(success",
            "require(aggsuccess",
            "require(!requiresuccess || success",
            "if (!success)",
            "if(!success)",
            "if (!msg.sender.send(",
            "if(!msg.sender.send(",
            "if (!master.send(",
            "if(!master.send(",
            "if (!owner.send(",
            "if(!owner.send(",
            "revert swapfailed",
            '"swap failed"',
            '"transfer failed"',
        )
    ) or "returnsuccess&&" in compact


def is_standard_low_level_helper(block: FunctionBlock, path_label: str) -> bool:
    filename = Path(path_label).name.lower()
    lowered = block.body_text.lower()
    name = block.name.lower()
    if filename == "transferhelper.sol":
        return name.startswith("safe") and "success &&" in lowered
    if filename == "safeerc20.sol":
        return "_calloptionalreturn" in name and "success &&" in lowered
    if (
        name in {"functioncallwithvalue", "functiondelegatecall", "functioncall", "functionstaticcall"}
        and "internal" in block.header.lower()
        and ("verifycallresult" in lowered or "_verifycallresult" in lowered)
        and (
            "address: low-level" in lowered
            or "address: call to non-contract" in lowered
            or "address: delegate call to non-contract" in lowered
            or "iscontract(target)" in re.sub(r"\s+", "", lowered)
        )
    ):
        return True
    return False


def is_user_paid_mint_loop(block: FunctionBlock, file_text: str) -> bool:
    lowered = block.body_text.lower()
    haystack = f"{file_text}\n{block.body_text}".lower()
    if "mint" not in block.name.lower() or not has_loop(block.body_text):
        return False
    has_mint_call = "_safemint(" in lowered or "_mint(" in lowered
    has_user_quantity = "quantity" in lowered or "amount" in lowered
    has_payment = "msg.value" in lowered or "transferfrom(msg.sender" in lowered or "safetransferfrom(msg.sender" in lowered
    has_cap = any(
        marker in haystack
        for marker in (
            "maxsupply",
            "maxsupplylimit",
            "maxnftsperwallet",
            "maxmint",
            "supply limit",
            "totalsupply()",
            "totalminted",
        )
    )
    return has_mint_call and has_user_quantity and has_payment and has_cap


def is_bounded_internal_money_loop(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    lowered = block.body_text.lower()
    haystack = f"{path_label}\n{file_text}".replace("\\", "/").lower()
    visibility = solidity_effective_visibility(block)
    if visibility not in {"private", "internal"}:
        return False
    if solidity_has_external_transfer(block.body_text):
        return False
    if "tracked_assets_limit" in haystack and "trackedassets" in lowered and "vaultlib" in haystack:
        return True
    if (
        block.name.lower().startswith("_burn")
        and ("qty" in lowered or "quantity" in lowered)
        and ("_burn(" in lowered or "_burnupeg(" in lowered or "ownerupegs" in lowered)
    ):
        return True
    return False


def is_standard_checked_erc20_accounting(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    name = block.name.lower()
    if name == "_burn":
        return (
            "accountbalance" in lowered
            and "require(accountbalance >= amount" in lowered
            and "_balances[account] = accountbalance - amount" in lowered
            and "_totalsupply" in lowered
        )
    if name == "_transfer":
        return (
            "frombalance" in lowered
            and "require(frombalance >= amount" in lowered
            and "_balances[from] = frombalance - amount" in lowered
            and "_balances[to] +=" in lowered
        )
    return False


def is_standard_erc721_burn_accounting(block: FunctionBlock, path_label: str) -> bool:
    normalized = path_label.replace("\\", "/").lower()
    lowered = block.body_text.lower()
    name = block.name.lower()
    if name not in {"_burn", "_burnwithtracking"}:
        return False
    erc721a_markers = (
        "_packedaddressdata",
        "_packedownerships",
        "bitpos_number_burned",
        "burned",
    )
    if (
        "erc721a.sol" not in normalized
        and "erc721tl.sol" not in normalized
        and not any(marker in lowered for marker in erc721a_markers)
    ):
        return False
    return any(
        marker in lowered
        for marker in (
            "_packedownershipof(",
            "_isapprovedorowner(",
            "_requireowned(",
            "ownerof(",
            "_beforetokentransfers(",
            "_aftertokentransfers(",
        )
    )


def is_standard_amm_accounting_flow(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    if is_standard_amm_source(file_text, path_label):
        return True
    normalized = path_label.replace("\\", "/").lower()
    haystack = f"{normalized}\n{file_text}".lower()
    lowered = block.body_text.lower()
    return (
        Path(path_label).name.lower() in {"swapcalculation.sol", "pricemovementmath.sol"}
        and any(marker in haystack for marker in ("algebrapool", "pricemovementmath", "tickmath"))
        and any(marker in lowered for marker in ("movepricetowardstarget", "limitsqrtprice", "currentliquidity"))
    )


def is_checked_stream_accounting(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    haystack = f"{path_label}\n{file_text}".replace("\\", "/").lower()
    lowered = block.body_text.lower()
    if "sablierlockup.sol" not in haystack:
        return False
    if block.name.lower() == "_create":
        return "aggregatemount" in lowered or ("aggregateamount[token] += depositamount" in lowered)
    if block.name.lower() == "_cancel":
        return (
            "streamedamount >= amounts.deposited" in lowered
            and "senderamount = amounts.deposited - streamedamount" in lowered
            and "aggregateamount[token] -= senderamount" in lowered
        )
    if block.name.lower() == "_withdraw":
        return "aggregateamount[token] -= amount" in lowered and "safetransfer" in lowered
    return False


def is_private_nonreentrant_deposit_forward(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    header = block.header.lower()
    return (
        block.name.lower() == "deposit"
        and solidity_effective_visibility(block) == "private"
        and "nonreentrant" in header
        and "msg.value" in lowered
        and ".send(" in lowered
        and "require(success" in lowered
    )


def is_standard_safe_gas_refund(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    if block.name.lower() != "handlepayment":
        return False
    normalized = path_label.replace("\\", "/").lower()
    haystack = f"{normalized}\n{file_text}".lower()
    visibility = solidity_effective_visibility(block)
    return (
        ("gnosissafe.sol" in haystack or "contract gnosissafe" in haystack)
        and "checksignatures" in haystack
        and "tx.origin" in block.body_text
        and visibility in {"private", "internal"}
    )


def tx_origin_is_token_launch_limit(block: FunctionBlock, path_label: str) -> bool:
    if "tx.origin" not in block.body_text:
        return False
    if block.name.lower() not in {"_transfer", "_update"}:
        return False
    lowered = block.body_text.lower()
    normalized = path_label.replace("\\", "/").lower()
    return (
        any(marker in lowered for marker in (
            "transferdelayenabled",
            "_holderlasttransfertimestamp",
            "tokensfrompoolperorigin",
            "maxwallet",
            "maxwalletsize",
            "maxtxamount",
            "launchblock",
            "launch_period",
        ))
        and any(marker in normalized or marker in lowered for marker in ("token", "asteroid", "launch"))
    )


def is_approved_executor_delegatecall_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return (
        ".delegatecall(" in lowered
        and "_validateexecutor(" in lowered
        and "executor" in lowered
        and ("if (!success)" in lowered or "if(!success)" in lowered)
    )


def is_sablier_price_gated_oracle_flow(block: FunctionBlock, file_text: str, path_label: str) -> bool:
    haystack = f"{path_label}\n{file_text}\n{block.body_text}".replace("\\", "/").lower()
    return (
        "sablierlockup" in haystack
        and any(marker in haystack for marker in (
            "lockup_price_gated",
            "pricegated",
            "safeoracle",
            "unlockparams.oracle",
            "create_lpg",
        ))
    )


def is_factory_gated_initializer(block: FunctionBlock) -> bool:
    if block.name.lower() not in {"init", "initialize"}:
        return False
    haystack = f"{block.header}\n{block.body_text}".lower()
    return (
        "onlyfactory" in haystack
        or "msg.sender == factory" in haystack
        or "caller is not factory" in haystack
    )


def is_entrypoint_or_message_gated(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return (
        "_requirefromentrypoint" in lowered
        or "outbox.consume(" in lowered
        or ".consume(" in lowered and "l2tol1msg" in lowered
    )


def is_secret_or_commitment_gated_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    if not solidity_has_external_transfer(block.body_text):
        return False
    commitment_gate = (
        "keccak256(abi.encode(" in lowered
        or "keccak256(abi.encodepacked(" in lowered
        or "ecrecover(" in lowered
    )
    rejects_mismatch = "revert" in lowered or "require(" in lowered
    return commitment_gate and rejects_mismatch and "msg.sender" not in lowered


def is_scheduled_upgrade_executor(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return (
        block.name.lower() == "upgrade"
        and "shouldupgrade()" in lowered
        and "_upgradeto(" in lowered
        and "finalizeupgrade()" in lowered
    )


def is_post_expiry_maintenance_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return (
        block.name.lower() in {"setpostexpirydata", "settlepostexpirydata"}
        and ("isexpired()" in lowered or "expiry" in lowered)
        and not solidity_has_external_transfer(block.body_text)
    )


def is_self_scoped_market_initialization(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    return (
        "msg.sender" in lowered
        and not solidity_has_external_transfer(block.body_text)
        and (
            "accountanttocurve[msg.sender]" in lowered
            or "positions[msg.sender]" in lowered
            or "markets[msg.sender]" in lowered
            or "ismarketcreator(msg.sender)" in lowered
        )
    )


def is_view_or_pure_function(block: FunctionBlock) -> bool:
    header = block.header.lower()
    return bool(re.search(r"\b(view|pure|constant)\b", header))


def is_plain_storage_setter(block: FunctionBlock) -> bool:
    if block.name.lower() != "set":
        return False
    body = block.body_text
    if solidity_has_external_transfer(body) or ".call" in body:
        return False
    meaningful = [
        line.strip()
        for _, line in block.lines
        if line.strip()
        and not line.strip().startswith(("//", "function", "}", "{"))
    ]
    return len(meaningful) <= 2 and any("=" in line for line in meaningful)


def is_self_scoped_operator_or_metadata_config(block: FunctionBlock) -> bool:
    lowered = f"{block.header}\n{block.body_text}".lower()
    self_scoped_markers = (
        "_blorboperators[msg.sender]",
        "operatorapprovals[msg.sender]",
        "setoperator(address op, bool ok)",
        "_onlyownerorself()",
        "adminrequired",
        "_owns(msg.sender",
        "ownerof(tokenid) == claimant",
        "ownerof[id]",
    )
    metadata_names = (
        "updatehero",
        "setblorboperator",
        "updatepublicdrop",
        "updateallowlist",
        "updatetokengateddrop",
        "updatedropuri",
        "updatecreatorpayoutaddress",
        "updateallowedfeerecipient",
        "updatesignedmintvalidationparams",
        "updatepayer",
        "setrenderer",
    )
    return any(marker in lowered for marker in self_scoped_markers) or block.name.lower() in metadata_names


def is_low_priority_public_config(block: FunctionBlock) -> bool:
    lowered = block.name.lower()
    body = block.body_text.lower()
    if solidity_has_external_transfer(block.body_text):
        return False
    return lowered in {
        "setswapbacksettings",
        "settargetliquidity",
        "burn_lp",
        "setmaxwalletpercent_base1000",
        "setmaxtxpercent_base1000",
    } or (
        lowered.startswith(("set", "update"))
        and any(marker in body for marker in ("swapenabled", "swapthreshold", "targetliquidity"))
    )


def is_fixed_recipient_money_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    fixed_recipient_markers = (
        "owneraddress",
        "ownerpayout",
        "marketingfeereceiver",
        "listingwallet",
        "feesink",
        "protocol_guild",
        "uniswapv2",
        "yodlfeetreasury",
        "treasury",
        "feecollector",
        "platformfeecollector",
        "swapethereum",
        "beneficiary",
        "dead_address",
        "address(0xdead)",
        "address(0xdead)",
        "poolmanager",
        "tradervault",
        "burn(",
    )
    if not any(marker in lowered for marker in fixed_recipient_markers):
        return False
    if re.search(
        r"(msg\.sender|_msgsender\(\))\s*\.\s*call\s*\{\s*value\s*:",
        lowered,
    ):
        return False
    caller_profit_markers = (
        ".transfer(msg.sender",
        ".safetransfer(msg.sender",
        "msg.sender.send",
        ".transfer(_msgsender()",
        ".safetransfer(_msgsender()",
    )
    if any(marker in lowered for marker in caller_profit_markers):
        return False
    transfer_markers = (
        ".call{value",
        ".send(",
        ".transfer(",
        ".safeTransfer(",
        ".transferFrom(",
        ".burn(",
    )
    return contains_any(block.body_text, transfer_markers)


def is_keeper_incentive_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    if not (
        "msg.sender" in lowered
        and (
            "bounty" in lowered
            or "keeperreward" in lowered
            or "keeper_reward" in lowered
            or "finder_fee" in lowered
            or "finderfee" in lowered
        )
    ):
        return False
    has_preconditions = any(
        marker in lowered
        for marker in (
            "cooldown",
            "threshold",
            "cap",
            "max_refund",
            "per_block",
            "last",
            "block.timestamp",
            "block.number",
        )
    )
    has_non_caller_route = any(
        marker in lowered
        for marker in (
            "treasury",
            "burn",
            "donate",
            "poolmanager",
            "dead",
            "protocol",
            "vortex",
        )
    )
    return has_preconditions and has_non_caller_route


def is_debt_backed_liquidation_flow(block: FunctionBlock) -> bool:
    if "liquidat" not in block.name.lower():
        return False
    lowered = block.body_text.lower()
    if "msg.sender" not in lowered:
        return False
    has_debt_or_margin_check = any(
        marker in lowered
        for marker in (
            "notunderwater",
            "healthy",
            "liquidation_threshold",
            "maintenance_margin",
            "debt",
            "collateralafter",
        )
    )
    has_cost_or_repayment = any(
        marker in lowered
        for marker in (
            "msg.value < debt",
            "repayamountmismatch",
            "msg.value",
            "debtamount",
            "collateral",
        )
    )
    has_state_close = (
        "delete positions" in lowered
        or "delete _positions" in lowered
        or "totaldebt" in lowered
        or "collaterallocked" in lowered
    )
    return has_debt_or_margin_check and has_cost_or_repayment and has_state_close


def is_cost_bound_payout(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    payout_to_caller = (
        ".safetransfer(msg.sender" in lowered
        or ".transfer(msg.sender" in lowered
        or "msg.sender.send" in lowered
        or ".call{value" in lowered and "msg.sender" in lowered
    )
    return payout_to_caller and (
        "burnfrom(msg.sender" in lowered
        or "burn(msg.sender" in lowered
        or "burnpair(" in lowered
        or "burnpositive(" in lowered
        or "burnnegative(" in lowered
        or "safetransferfrom(msg.sender" in lowered
        or "transferfrom(msg.sender" in lowered
        or "safetransferfrom(msg.sender, address(this)" in lowered
        or "safetransferfrom(msg.sender,address(this)" in lowered
        or "shares[seriesid][msg.sender]" in lowered
        or "pos.owner != msg.sender" in lowered
        or "positions[posid]" in lowered
    )


def is_user_funded_redemption_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    name = block.name.lower()
    pulls_from_caller = (
        "safetransferfrom(msg.sender, address(this)" in lowered
        or "safetransferfrom(msg.sender,address(this)" in lowered
        or "transferfrom(msg.sender, address(this)" in lowered
        or "transferfrom(msg.sender,address(this)" in lowered
    )
    redemption_like = any(marker in name for marker in ("redeem", "unstake", "withdraw", "remove", "swap"))
    return pulls_from_caller and redemption_like


def is_inbound_deposit_flow(block: FunctionBlock) -> bool:
    lowered = block.name.lower()
    if not (lowered.startswith("deposit") or lowered in {"stake", "topupdividendasset"}):
        return False
    body = block.body_text.lower()
    inbound_to_contract = (
        "msg.value" in body
        or "address(this)" in body and (
            "transferfrom" in body
            or "safetransferfrom" in body
        )
    )
    outbound_from_contract = (
        ".call{value" in body
        or ".send(" in body
        or ".transfer(" in body
        or ".safetransfer(" in body
    ) and "address(this)" not in body
    return inbound_to_contract and not outbound_from_contract


def is_game_or_round_settlement_flow(block: FunctionBlock) -> bool:
    lowered = block.body_text.lower()
    name = block.name.lower()
    if not any(marker in name for marker in ("settle", "claim", "draw", "jackpot")):
        return False
    return any(
        marker in lowered
        for marker in (
            "lastbuyer",
            "winner",
            "round",
            "draw",
            "jackpot",
            "vrf",
            "pendingeth",
            "claimprize",
            "claimmany",
        )
    ) and any(
        marker in lowered
        for marker in (
            "msg.sender",
            "winner",
            "lastbuyer",
            "pending",
            "claim",
        )
    )


def tx_origin_is_eoa_gate_or_event(block: FunctionBlock) -> bool:
    saw_tx_origin = False
    for _, line in block.lines:
        lowered = line.strip().lower()
        if "tx.origin" not in lowered:
            continue
        saw_tx_origin = True
        if lowered.startswith("//"):
            continue
        if lowered.startswith("emit ") or " emit " in lowered:
            continue
        if re.search(r"require\s*\(\s*tx\.origin\s*==\s*msg\.sender\b", lowered):
            continue
        if re.search(r"require\s*\(\s*msg\.sender\s*==\s*tx\.origin\b", lowered):
            continue
        if (
            ("msg.sender != tx.origin" in lowered or "tx.origin != msg.sender" in lowered)
            and ("revert" in lowered or "return" in lowered)
        ):
            continue
        return False
    return saw_tx_origin


def tx_origin_is_hook_attribution(block: FunctionBlock, path_label: str) -> bool:
    if "tx.origin" not in block.body_text:
        return False
    lowered = block.body_text.lower()
    name = block.name.lower()
    normalized_path = path_label.replace("\\", "/").lower()
    hook_like = (
        "hook" in normalized_path
        or "basehook" in lowered
        or "onlypoolmanager" in block.header.lower()
        or "onlypoolmanager" in lowered
        or "poolmanager.take(" in lowered
    )
    callback_like = name in {
        "beforeswap",
        "_beforeswap",
        "afterswap",
        "_afterswap",
        "_resolveswapper",
        "_enforcebuylimits",
    }
    if not hook_like or not callback_like:
        return False
    dangerous_patterns = (
        r"require\s*\([^;]*tx\.origin[^;]*(owner|admin|treasury|operator|manager)",
        r"require\s*\([^;]*(owner|admin|treasury|operator|manager)[^;]*tx\.origin",
        r"tx\.origin\s*\.\s*call\s*\{\s*value\s*:",
        r"\.transfer\s*\(\s*tx\.origin\b",
        r"\.safetransfer\s*\(\s*tx\.origin\b",
        r"\.transferfrom\s*\([^;]*tx\.origin",
        r"owner\s*=\s*tx\.origin",
        r"admin\s*=\s*tx\.origin",
    )
    return not any(re.search(pattern, lowered) for pattern in dangerous_patterns)


def solidity_effective_visibility(block: FunctionBlock) -> str:
    if block.visibility != "unknown":
        return block.visibility
    for candidate in ("external", "public", "internal", "private"):
        if re.search(rf"\b{candidate}\b", block.header):
            return candidate
    return block.visibility


def solidity_has_access_control(block: FunctionBlock) -> bool:
    header = block.header
    body = block.body_text
    header_lower = header.lower()
    if contains_any(header, SOL_ACCESS_MARKERS) or any(
        marker.lower() in header_lower for marker in SOL_ACCESS_MARKERS
    ):
        return True
    if re.search(r"\bonly[A-Za-z0-9_]*\b", header, flags=re.IGNORECASE):
        return True
    if contains_any(body, SOL_BODY_AUTH_MARKERS):
        return True
    if re.search(
        r"\b(require|if)\s*\([^;]*(is[A-Za-z0-9_]*|allowed|authorized|roles?|markets?|vaults?|guardians?|operators?)\s*\[[^;\]]*(msg\.sender|_msgSender\(\))",
        body,
        flags=re.IGNORECASE,
    ):
        return True
    if re.search(r"\brevert\s+[A-Za-z0-9_]*Only\b", body):
        return True
    return False


def solidity_has_self_accounting_guard(block: FunctionBlock) -> bool:
    body = block.body_text
    if contains_any(body, SOL_SELF_ACCOUNTING_MARKERS):
        return True
    owner_patterns = (
        r"require\s*\([^;]*(msg\.sender|_msgSender\(\))[^;]*(owner|account|user|recipient)",
        r"require\s*\([^;]*(owner|account|user|recipient)[^;]*(msg\.sender|_msgSender\(\))",
        r"require\s*\([^;]*(balances?|shares?|deposits?|claimable|pending)\s*\[[^]]*(msg\.sender|_msgSender\(\))",
        r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[\s*(msg\.sender|_msgSender\(\))\s*\]",
        r"\bget[A-Za-z0-9_]*ByAddress\s*\(\s*(msg\.sender|_msgSender\(\))\s*\)",
    )
    return any(re.search(pattern, body) for pattern in owner_patterns)


def is_public_business_function(name: str, body: str) -> bool:
    lowered = name.lower()
    if lowered in {item.lower() for item in SOL_PUBLIC_BUSINESS_FUNCTIONS}:
        return True
    return (
        lowered.startswith(("buy", "sell", "mint", "purchase"))
        and not requires_admin_guard(name)
    )


def requires_admin_guard(name: str) -> bool:
    lowered = name.lower()
    return any(
        marker in lowered
        for marker in (
            "sweep",
            "rescue",
            "emergency",
            "upgrade",
            "set",
            "admin",
            "owner",
            "pause",
        )
    )


def solidity_has_external_transfer(body: str) -> bool:
    patterns = (
        ".call{value",
        ".call(",
        ".send(",
        ".transfer(",
        ".safeTransfer(",
        ".safeTransferFrom(",
        ".transferFrom(",
    )
    return contains_any(body, patterns)


def solidity_has_reentrancy_guard(block: FunctionBlock) -> bool:
    header = block.header
    body = block.body_text
    if contains_any(header + body, ("nonReentrant", "reentrancyGuard")):
        return True
    return bool(
        re.search(
            r"\b(lock|locked|noReentrant|preventReentrant)\b",
            header,
            flags=re.IGNORECASE,
        )
    )


def solidity_has_state_write_after_transfer(block: FunctionBlock) -> tuple[bool, int]:
    transfer_re = re.compile(
        r"(\.call\s*(\{|<|\()|\.send\s*\(|\.transfer\s*\(|safeTransfer|transferFrom)"
    )
    state_write_re = re.compile(
        r"\b("
        r"balances?|shares?|assets?|totalSupply|supply|debt|credit|positions?|"
        r"liquidity|rewards?|claimable|pending|owed|accounting"
        r")\b[^;\n]*(=|\+=|-=|\+\+|--)"
    )
    first_transfer_line = 0
    for line_no, line in block.lines:
        if first_transfer_line == 0 and transfer_re.search(line):
            first_transfer_line = line_no
            continue
        if first_transfer_line and state_write_re.search(line):
            return True, first_transfer_line
    return False, first_transfer_line


def solidity_transfer_kind_at_line(block: FunctionBlock, line_number: int) -> str:
    for line_no, line in block.lines:
        if line_no != line_number:
            continue
        if ".call" in line:
            return "call"
        if ".send(" in line or ".transfer(" in line:
            return "native-stipend"
        if "safeTransfer" in line or "transferFrom" in line:
            return "token"
        return "unknown"
    return "unknown"


def add_finding(findings: list[Finding], finding: Finding) -> None:
    findings.append(finding.finalize_score())


def scan_solidity_file(
    path_label: str,
    lines: list[str],
    compiler_version: str | None = None,
    runtime_source: str | Sequence[str] | None = None,
    runtime_contracts: Sequence[str] | None = None,
    precheck_state: dict[str, object] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    scan_lines = strip_source_comments(lines, "solidity")
    text = "\n".join(scan_lines)
    functions = extract_functions(scan_lines, "solidity")
    old_compiler = solidity_version_before_08(compiler_version) or source_pragma_before_08(text)
    standard_dependency = is_standard_dependency_file(path_label)
    non_runtime_bundle_source = is_non_runtime_bundle_source(path_label, runtime_source)
    non_runtime_fixture_source = non_runtime_bundle_source and is_fixture_or_example_source(path_label)

    for block in functions:
        if standard_dependency:
            continue

        body = block.body_text
        name_lower = block.name.lower()
        visibility = solidity_effective_visibility(block)
        public_like = visibility in {"public", "external", "unknown"}
        money_path = is_money_function(block.name, body) or solidity_has_external_transfer(body)
        admin_path = is_admin_function(block.name, body) and name_lower not in {
            "initialize",
            "init",
        }
        has_access_control = solidity_has_access_control(block)
        has_self_guard = solidity_has_self_accounting_guard(block)
        payout_or_request_bound = is_payout_or_request_bound(body)
        fixed_recipient_flow = is_fixed_recipient_money_flow(block)
        cost_bound_payout = is_cost_bound_payout(block)
        inbound_deposit_flow = is_inbound_deposit_flow(block)
        inbound_transfer_only_flow = is_inbound_transfer_only_flow(block)
        recipient_or_approved_withdrawal = is_recipient_or_approved_withdrawal_flow(block)
        user_funded_launchpad_flow = is_user_funded_launchpad_flow(block, path_label)
        entrypoint_or_message_gated = is_entrypoint_or_message_gated(block)
        secret_or_commitment_gated_flow = is_secret_or_commitment_gated_flow(block)
        notary_commitment_flow = is_notary_commitment_flow(block)
        scheduled_upgrade_executor = is_scheduled_upgrade_executor(block)
        post_expiry_maintenance_flow = is_post_expiry_maintenance_flow(block)
        self_scoped_market_initialization = is_self_scoped_market_initialization(block)
        standard_amm_source = is_standard_amm_source(text, path_label)
        standard_amm_function = is_standard_amm_function(block, text, path_label)
        payment_splitter_release = is_payment_splitter_release(block, text, path_label)
        vault_allowance_bookkeeping = is_vault_allowance_bookkeeping_flow(block)
        vault_allowance_guarded_transfer = is_vault_allowance_guarded_transfer_flow(block)
        swap_aggregator_user_flow = is_swap_aggregator_user_flow(block, path_label)
        hook_fee_callback_flow = is_hook_fee_callback_flow(block, path_label)
        self_delegatecall_wrapper = is_self_delegatecall_wrapper(block)
        tax_or_router_maintenance_swap = is_tax_or_router_maintenance_swap(block, path_label)
        fixed_masterwallet_transferfrom_sweeper = is_fixed_masterwallet_transferfrom_sweeper(block, path_label)
        owner_only_registry_loop = is_owner_only_registry_loop(block)
        owner_bound_cell_claim_flow = is_owner_bound_cell_claim_flow(block, path_label)
        cell_hook_erc20_transfer_override = is_cell_hook_erc20_transfer_override(block, path_label)
        cell_bucket_accounting = is_cell_bucket_accounting(block, path_label)
        non_runtime_same_file_contract = is_non_runtime_same_file_contract(
            block, scan_lines, runtime_contracts
        )
        account_levels_test_setter = (
            non_runtime_same_file_contract and is_account_levels_test_setter(block, path_label)
        )
        legacy_constructor_like = is_legacy_constructor_like(block, text, old_compiler)
        ens_deed_destroy_cleanup = is_ens_deed_destroy_cleanup(block, path_label)
        pixel_selling_guarded_flow = is_pixel_selling_guarded_flow(block, path_label)
        crowdsale_finalize_fixed_master_flow = is_crowdsale_finalize_fixed_master_flow(block)
        token_trader_user_purchase_flow = is_token_trader_user_purchase_flow(block, path_label)
        legacy_lottery_user_or_owner_flow = is_legacy_lottery_user_or_owner_flow(block, path_label)
        legacy_blockcdn_flow = is_legacy_blockcdn_flow(block, path_label)
        singulardtv_soft_withdraw_credit = is_singulardtv_soft_withdraw_credit(block, path_label)
        fixed_price_user_token_buyback = is_fixed_price_user_token_buyback(block, path_label)
        exchange_order_readonly_check = is_exchange_order_readonly_check(block, path_label)
        user_owned_burn_redeem_flow = is_user_owned_burn_redeem_flow(block, path_label)
        inbound_balance_delta_accounting = is_inbound_balance_delta_accounting(block)
        bittrex_userwallet_controller_helper = is_bittrex_userwallet_controller_helper(
            block, text, path_label
        )
        opyn_otoken_user_flow = is_opyn_otoken_user_flow(block, path_label)
        legacy_e4token_segmented_payout_loop = is_legacy_e4token_segmented_payout_loop(
            block, path_label
        )
        third_party_refund_to_beneficiary = is_third_party_refund_to_beneficiary(block)
        fixed_owner_timelock_unlock = is_fixed_owner_timelock_unlock(block)
        bittrex_userwallet_sweep_flow = is_bittrex_userwallet_sweep_flow(block, text, path_label)
        public_ico_status_update = is_public_ico_status_update(block)
        ico_refund_request_flow = is_ico_refund_request_flow(block)
        merkle_bound_user_position_update = is_merkle_bound_user_position_update(block)
        parity_v1_wallet_fixed_library_delegatecall = is_parity_v1_wallet_fixed_library_delegatecall(
            block, text, path_label
        )
        consensys_multisig_owner_management_loop = is_consensys_multisig_owner_management_loop(
            block, text, path_label
        )
        openzeppelin_beacon_proxy_helper = is_openzeppelin_beacon_proxy_helper(block, text, path_label)
        rocket_minipool_delegate_fallback = is_rocket_minipool_delegate_fallback(
            block, text, path_label
        )
        legacy_wallet_owner_delegate_deposit = is_legacy_wallet_owner_delegate_deposit(
            block, text, path_label
        )
        ownable_delegate_proxy_upgrade_call = is_ownable_delegate_proxy_upgrade_call(
            block, text, path_label
        )
        ante_pool_factory_initializer = is_ante_pool_factory_initializer(block, path_label)
        layerzero_readlib_fee_or_verification_flow = is_layerzero_readlib_fee_or_verification_flow(
            block, path_label
        )
        teambrella_multisig_wallet_flow = is_teambrella_multisig_wallet_flow(
            block, text, path_label
        )
        safu_presale_liquidity_flow = is_safu_presale_liquidity_flow(block, path_label)
        public_decay_update = is_public_decay_update(block)
        safu_presale_cancel_guarded = is_safu_presale_cancel_guarded(block, path_label)
        checked_low_level_call_flow = is_checked_low_level_call_flow(block)
        standard_low_level_helper = is_standard_low_level_helper(block, path_label)
        user_paid_mint_loop = is_user_paid_mint_loop(block, text)
        bounded_internal_money_loop = is_bounded_internal_money_loop(block, text, path_label)
        standard_checked_erc20_accounting = is_standard_checked_erc20_accounting(block)
        standard_erc721_burn_accounting = is_standard_erc721_burn_accounting(block, path_label)
        standard_amm_accounting_flow = is_standard_amm_accounting_flow(block, text, path_label)
        checked_stream_accounting = is_checked_stream_accounting(block, text, path_label)
        private_nonreentrant_deposit_forward = is_private_nonreentrant_deposit_forward(block)
        token_launch_origin_limit = tx_origin_is_token_launch_limit(block, path_label)
        approved_executor_delegatecall = is_approved_executor_delegatecall_flow(block)
        sablier_price_gated_oracle_flow = is_sablier_price_gated_oracle_flow(block, text, path_label)
        view_or_pure = is_view_or_pure_function(block)
        plain_storage_setter = is_plain_storage_setter(block)
        plain_storage_getter = is_plain_storage_getter(block)
        self_scoped_config = is_self_scoped_operator_or_metadata_config(block)
        low_priority_config = is_low_priority_public_config(block)
        keeper_incentive_flow = is_keeper_incentive_flow(block)
        debt_backed_liquidation_flow = is_debt_backed_liquidation_flow(block)
        user_funded_redemption_flow = is_user_funded_redemption_flow(block)
        game_or_round_settlement_flow = is_game_or_round_settlement_flow(block)
        eoa_origin_only = tx_origin_is_eoa_gate_or_event(block)
        hook_tx_origin_attribution = tx_origin_is_hook_attribution(block, path_label)
        has_money_guard = has_access_control or (
            (has_self_guard or payout_or_request_bound) and not requires_admin_guard(block.name)
        ) or any(
            (
                fixed_recipient_flow,
                cost_bound_payout,
                inbound_deposit_flow,
                inbound_transfer_only_flow,
                recipient_or_approved_withdrawal,
                user_funded_launchpad_flow,
                entrypoint_or_message_gated,
                secret_or_commitment_gated_flow,
                notary_commitment_flow,
                post_expiry_maintenance_flow,
                self_scoped_market_initialization,
                self_scoped_config,
                keeper_incentive_flow,
                debt_backed_liquidation_flow,
                user_funded_redemption_flow,
                game_or_round_settlement_flow,
                payment_splitter_release,
                vault_allowance_bookkeeping,
                vault_allowance_guarded_transfer,
                swap_aggregator_user_flow,
                hook_fee_callback_flow,
                self_delegatecall_wrapper,
                approved_executor_delegatecall,
                tax_or_router_maintenance_swap,
                fixed_masterwallet_transferfrom_sweeper,
                owner_bound_cell_claim_flow,
                cell_hook_erc20_transfer_override,
                ens_deed_destroy_cleanup,
                pixel_selling_guarded_flow,
                crowdsale_finalize_fixed_master_flow,
                token_trader_user_purchase_flow,
                legacy_lottery_user_or_owner_flow,
                legacy_blockcdn_flow,
                singulardtv_soft_withdraw_credit,
                fixed_price_user_token_buyback,
                exchange_order_readonly_check,
                user_owned_burn_redeem_flow,
                inbound_balance_delta_accounting,
                bittrex_userwallet_controller_helper,
                opyn_otoken_user_flow,
                legacy_e4token_segmented_payout_loop,
                layerzero_readlib_fee_or_verification_flow,
                teambrella_multisig_wallet_flow,
                safu_presale_liquidity_flow,
                third_party_refund_to_beneficiary,
                fixed_owner_timelock_unlock,
                bittrex_userwallet_sweep_flow,
                public_ico_status_update,
                ico_refund_request_flow,
                merkle_bound_user_position_update,
                public_decay_update,
                safu_presale_cancel_guarded,
            )
        )

        if (
            public_like
            and money_path
            and not has_money_guard
            and not view_or_pure
            and not legacy_constructor_like
            and not plain_storage_setter
            and not plain_storage_getter
            and not low_priority_config
            and not (eoa_origin_only and not solidity_has_external_transfer(body))
            and not is_standard_token_function(block.name)
            and not standard_amm_function
        ):
            if non_runtime_fixture_source:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Money-path function appears in a non-runtime mock/test Sourcify bundle source."
                manual_check = (
                    "Confirm this source file is the deployed runtime or inherited by "
                    "the deployed runtime before treating balances on the address as at risk."
                )
            elif non_runtime_bundle_source:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Money-path function appears in a non-runtime Sourcify bundle source."
                manual_check = (
                    "Confirm this source file is inherited by the deployed runtime "
                    "before applying live balances from the verified address."
                )
            else:
                severity = (
                    "high"
                    if is_public_business_function(block.name, body)
                    else "critical"
                    if solidity_has_external_transfer(body)
                    else "high"
                )
                confidence = "medium"
                funds_at_risk = True
                signal = "Public/external money-path function has no obvious admin/user ownership guard."
                manual_check = (
                    "Confirm owner/role/position ownership checks and whether this "
                    "path can transfer protocol or user funds."
                )
            add_finding(
                findings,
                Finding(
                    severity=severity,
                    confidence=confidence,
                    funds_at_risk=funds_at_risk,
                    category="access-control",
                    path=path_label,
                    line=block.start_line,
                    function=block.name,
                    signal=signal,
                    evidence=block.header,
                    manual_check=manual_check,
                ),
            )

        if (
            public_like
            and admin_path
            and not has_access_control
            and not view_or_pure
            and not is_standard_token_function(block.name)
        ):
            if account_levels_test_setter:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "AccountLevelsTest setter is outside the deployed Sourcify runtime contract."
                manual_check = (
                    "Keep as same-file bundle noise unless the deployed runtime FQN is "
                    "AccountLevelsTest."
                )
            elif pixel_selling_guarded_flow:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "PixelSelling metadata/sale setter is scoped to the current item owner."
                manual_check = (
                    "Keep as an owner-scoped state-change signal unless another path can "
                    "take ownership or withdraw another user's balance."
                )
            elif (
                name_lower.startswith("initialize")
                and "initializer" in block.header.lower()
            ):
                severity = "medium"
                confidence = "low"
                funds_at_risk = True
                signal = "Initializer-style function requires live initialized-state precheck."
                manual_check = (
                    "Call a read-only owner/threshold/initialized getter or inspect proxy "
                    "storage before escalating."
                )
            elif public_ico_status_update or merkle_bound_user_position_update or public_decay_update:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Public update function is bounded by deterministic state or caller proof."
                manual_check = (
                    "Keep as a state/accounting watchlist unless proof verification or "
                    "state-transition conditions can be bypassed."
                )
            elif plain_storage_setter or self_scoped_config or low_priority_config:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Public config-like function has no obvious access control."
                manual_check = (
                    "Keep as a low-priority configuration signal unless runtime state "
                    "shows this controls fund movement, fees, ownership, or pausing."
                )
            elif is_standard_safe_setup(block, text, path_label):
                safe_threshold = 0
                if precheck_state:
                    try:
                        safe_threshold = int(precheck_state.get("safeThreshold") or 0)
                    except (TypeError, ValueError):
                        safe_threshold = 0
                if safe_threshold > 0:
                    severity = "low"
                    confidence = "low"
                    funds_at_risk = False
                    signal = "Gnosis Safe setup is already consumed by read-only threshold precheck."
                    manual_check = "getThreshold() returned nonzero; keep as a checked setup signal."
                else:
                    severity = "medium"
                    confidence = "low"
                    funds_at_risk = True
                    signal = "Gnosis Safe setup requires live threshold precheck before escalation."
                    manual_check = "Call getThreshold() read-only; nonzero threshold means setup is already consumed."
            elif scheduled_upgrade_executor:
                severity = "medium"
                confidence = "low"
                funds_at_risk = True
                signal = "Upgrade executor appears to require a pre-scheduled implementation."
                manual_check = (
                    "Confirm shouldUpgrade() can only become true through authorized "
                    "governance/timelock scheduling before escalating as arbitrary upgrade."
                )
            elif post_expiry_maintenance_flow:
                severity = "medium"
                confidence = "low"
                funds_at_risk = False
                signal = "Post-expiry maintenance function has no direct custody transfer."
                manual_check = (
                    "Keep as maintenance/precheck unless it can reset ownership, mint, "
                    "or redirect balances after expiry."
                )
            elif self_scoped_market_initialization:
                severity = "medium"
                confidence = "low"
                funds_at_risk = False
                signal = "Initialization/configuration is scoped to msg.sender or an authorized creator."
                manual_check = (
                    "Confirm caller-scoped state cannot initialize another live market "
                    "or grant mint/burn rights to attacker-controlled contracts."
                )
            elif notary_commitment_flow:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Public settlement path is guarded by notary-signed commitment state."
                manual_check = (
                    "Confirm the commitment hash includes chain/domain and nonce or "
                    "claimed-state before escalating as unguarded admin logic."
                )
            elif non_runtime_bundle_source:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Admin-like function appears in a non-runtime Sourcify bundle source."
                manual_check = "Confirm the source file is inherited or deployed runtime before escalating."
            else:
                severity = "critical"
                confidence = "medium"
                funds_at_risk = True
                signal = "Public/external admin or upgrade function has no obvious access control."
                manual_check = (
                    "Check whether this can change implementation, oracle, fees, "
                    "owner, pause state, or withdrawal rules."
                )
            add_finding(
                findings,
                Finding(
                    severity=severity,
                    confidence=confidence,
                    funds_at_risk=funds_at_risk,
                    category="upgradeability",
                    path=path_label,
                    line=block.start_line,
                    function=block.name,
                    signal=signal,
                    evidence=block.header,
                    manual_check=manual_check,
                ),
            )

        if name_lower in {"initialize", "init"} and public_like:
            guarded = contains_any(block.header + body, ("initializer", "reinitializer"))
            if not guarded or not has_access_control:
                funds_at_risk = True
                pool_initialized = bool(precheck_state and precheck_state.get("poolInitialized"))
                if standard_amm_function and pool_initialized:
                    severity = "low"
                    confidence = "low"
                    funds_at_risk = False
                    signal = "AMM/pool initializer is already consumed by read-only pool-state precheck."
                    manual_check = "Pool price/state is nonzero and factory/token metadata is readable."
                elif ante_pool_factory_initializer:
                    severity = "low"
                    confidence = "low"
                    funds_at_risk = False
                    signal = "AntePool initializer is constrained to the constructor-set factory."
                    manual_check = "Confirm factory deployment path only if pool factory control is in scope."
                elif has_access_control:
                    severity = "medium"
                    confidence = "low"
                    signal = "Initializer has access control but lacks an obvious initializer/state guard."
                    manual_check = (
                        "Confirm the authorized initializer cannot be replayed in live "
                        "state and whether proxy/implementation state is already consumed."
                    )
                elif is_factory_gated_initializer(block):
                    severity = "medium"
                    confidence = "low"
                    signal = "Factory-gated initializer requires factory/state precheck before escalation."
                    manual_check = (
                        "Confirm factory is immutable/current and initialization cannot be "
                        "called by arbitrary accounts."
                    )
                elif is_standard_proxy_initializer(block, text, path_label):
                    severity = "medium"
                    confidence = "low"
                    signal = "Standard proxy initializer requires implementation-slot precheck."
                    manual_check = (
                        "Read EIP-1967 implementation storage or proxy metadata; "
                        "nonzero implementation usually means initialized."
                    )
                elif standard_amm_function:
                    severity = "medium"
                    confidence = "low"
                    signal = "AMM/pool initializer requires factory and pool-state precheck."
                    manual_check = (
                        "Read factory/token0/token1/reserves or slot0 before escalating "
                        "as an uninitialized pool."
                    )
                elif non_runtime_bundle_source:
                    severity = "low"
                    confidence = "low"
                    funds_at_risk = False
                    signal = "Initializer appears in a non-runtime Sourcify bundle source."
                    manual_check = (
                        "Confirm the source file is the deployed runtime or inherited "
                        "by the deployed runtime before escalating."
                    )
                else:
                    severity = "critical"
                    confidence = "medium"
                    signal = "Initializer is public/external and lacks an obvious initializer/access guard."
                    manual_check = (
                        "Confirm the implementation and proxy cannot be initialized "
                        "or reinitialized by an attacker."
                    )
                add_finding(
                    findings,
                    Finding(
                        severity=severity,
                        confidence=confidence,
                        funds_at_risk=funds_at_risk,
                        category="upgradeability",
                        path=path_label,
                        line=block.start_line,
                        function=block.name,
                        signal=signal,
                        evidence=block.header,
                        manual_check=manual_check,
                    ),
                )

        risky_order, transfer_line = solidity_has_state_write_after_transfer(block)
        if risky_order and money_path and not (
            standard_amm_function
            or notary_commitment_flow
            or vault_allowance_bookkeeping
            or vault_allowance_guarded_transfer
            or non_runtime_bundle_source
            or private_nonreentrant_deposit_forward
            or legacy_blockcdn_flow
            or fixed_price_user_token_buyback
            or user_owned_burn_redeem_flow
            or inbound_balance_delta_accounting
            or opyn_otoken_user_flow
            or layerzero_readlib_fee_or_verification_flow
            or safu_presale_liquidity_flow
        ):
            guarded = solidity_has_reentrancy_guard(block)
            transfer_kind = solidity_transfer_kind_at_line(block, transfer_line)
            gas_forwarding_call = transfer_kind == "call"
            native_stipend = transfer_kind == "native-stipend"
            entrypoint_like = visibility in {"public", "external", "unknown"}
            legacy_unchecked_math = (
                old_compiler and not guarded and gas_forwarding_call and entrypoint_like
            )
            if not guarded and gas_forwarding_call and entrypoint_like:
                severity = "critical"
                confidence = "high" if legacy_unchecked_math else "medium"
                signal = (
                    "Pre-0.8 external transfer before accounting update."
                    if legacy_unchecked_math
                    else "Possible external transfer before accounting update."
                )
            elif native_stipend:
                severity = "medium"
                confidence = "low"
                signal = "Native send/transfer before accounting update; gas stipend limits reentrancy."
            else:
                severity = "high"
                confidence = "medium"
                signal = "Possible external transfer before accounting update."
            funds_at_risk = True
            if non_runtime_fixture_source:
                severity = "medium"
                confidence = "low"
                funds_at_risk = False
                signal = "Reentrancy-like ordering appears in a non-runtime mock/test Sourcify bundle source."
            add_finding(
                findings,
                Finding(
                    severity=severity,
                    confidence=confidence,
                    funds_at_risk=funds_at_risk,
                    category="reentrancy",
                    path=path_label,
                    line=transfer_line or block.start_line,
                    function=block.name,
                    signal=signal,
                    evidence=(
                        "External call/transfer appears before a balance/share/accounting write."
                    ),
                    manual_check=(
                        "Confirm whether an attacker-controlled receiver can reenter "
                        "before balances, shares, or claimable amounts are reduced."
                        + (
                            " Compiler appears pre-0.8, so repeated subtraction may wrap instead of reverting."
                            if legacy_unchecked_math
                            else ""
                        )
                    ),
                ),
            )

        if ".delegatecall" in body:
            arbitrary = re.search(r"delegatecall\s*\([^)]*(target|to|addr|implementation)", body)
            if scheduled_upgrade_executor:
                delegate_severity = "medium"
                delegate_confidence = "low"
                delegate_funds = True
                delegate_signal = "delegatecall finalizes a scheduled upgrade path."
                delegate_manual = (
                    "Confirm the scheduled implementation and finalizeUpgrade() caller "
                    "requirements, rather than treating this as arbitrary delegatecall."
                )
            elif name_lower == "constructor":
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "delegatecall appears in constructor-time setup."
                delegate_manual = "Confirm constructor target is fixed/validated and not callable after deployment."
            elif self_delegatecall_wrapper:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "delegatecall targets this contract as a batch wrapper."
                delegate_manual = "Confirm delegatecall cannot target arbitrary code and preserves the wrapped function auth checks."
            elif approved_executor_delegatecall:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "delegatecall is constrained to an approved executor and checks failure."
                delegate_manual = "Confirm executor activation/timelock and owner/governance path before escalating."
            elif parity_v1_wallet_fixed_library_delegatecall:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "Parity v1 Wallet fixed-library view helper delegates to a known library address."
                delegate_manual = (
                    "Read-only check library code and initialized owner slots before treating "
                    "this as a drain; absent library code implies frozen funds, not caller-controlled withdrawal."
                )
            elif openzeppelin_beacon_proxy_helper:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "OpenZeppelin BeaconProxy helper delegates through checked internal proxy code."
                delegate_manual = "Confirm beacon/implementation slot only if proxy initialization or admin path is also suspicious."
            elif rocket_minipool_delegate_fallback:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "Rocket Pool minipool fallback delegates to the network minipool delegate contract."
                delegate_manual = "Confirm RocketStorage delegate address only if network storage control is in scope."
            elif legacy_wallet_owner_delegate_deposit:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "Legacy wallet deposit path delegates to the fixed first owner address."
                delegate_manual = "Keep as owner-controlled legacy wallet behavior unless owner storage can be changed by an external caller."
            elif ownable_delegate_proxy_upgrade_call:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "OwnableDelegateProxy upgradeToAndCall is restricted to proxy owner."
                delegate_manual = "Confirm proxyOwner storage only if upgrade ownership is in scope."
            elif standard_low_level_helper:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "delegatecall appears inside a standard checked low-level helper."
                delegate_manual = "Confirm helper reachability only if the public caller can choose the implementation target."
            elif bittrex_userwallet_sweep_flow:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "Bittrex UserWallet sweep delegates into a sweeper with controller authorization checks."
                delegate_manual = "Confirm sweeperList/controller storage still points to the expected controller."
            elif non_runtime_bundle_source:
                delegate_severity = "low"
                delegate_confidence = "low"
                delegate_funds = False
                delegate_signal = "delegatecall appears in a non-runtime Sourcify bundle source."
                delegate_manual = "Confirm runtime reachability before escalating delegatecall risk."
            else:
                delegate_severity = "critical" if public_like and arbitrary else "high"
                delegate_confidence = "medium"
                delegate_funds = True
                delegate_signal = "delegatecall used in a callable function."
                delegate_manual = (
                    "Confirm target control, storage collision risk, and whether "
                    "delegatecall can mutate custody/accounting state."
                )
            add_finding(
                findings,
                Finding(
                    severity=delegate_severity,
                    confidence=delegate_confidence,
                    funds_at_risk=delegate_funds,
                    category="delegatecall",
                    path=path_label,
                    line=find_line(block.lines, "delegatecall"),
                    function=block.name,
                    signal=delegate_signal,
                    evidence=snippet_for(block.lines, "delegatecall"),
                    manual_check=delegate_manual,
                ),
            )

        if re.search(r"\btx\.origin\b", body):
            if is_standard_safe_gas_refund(block, text, path_label):
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "Gnosis Safe gas-refund path uses tx.origin as default refund receiver."
                manual_check = (
                    "Confirm this is private/internal Safe payment logic behind signature "
                    "threshold checks, not authorization."
                )
            elif non_runtime_bundle_source:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "tx.origin appears in a non-runtime Sourcify bundle source."
                manual_check = "Confirm this file is inherited by the deployed runtime before escalating."
            elif token_launch_origin_limit:
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "tx.origin appears in token launch/transfer-delay limiting logic."
                manual_check = (
                    "Keep as wallet-composability/anti-bot watchlist unless tx.origin "
                    "authorizes ownership, withdrawal, or third-party spending."
                )
            elif hook_tx_origin_attribution:
                severity = "medium" if money_path else "low"
                confidence = "low"
                funds_at_risk = False
                signal = "tx.origin appears to be hook trader attribution, not authorization."
                manual_check = (
                    "Keep as a composability/attribution watchlist unless tx.origin "
                    "is used as owner/admin, recipient, or withdrawal authorization."
                )
            elif tx_origin_is_eoa_gate_or_event(block):
                severity = "medium" if money_path else "low"
                confidence = "low"
                funds_at_risk = False
                signal = "tx.origin appears to be used as an EOA gate or event label."
                manual_check = (
                    "Keep as a composability/phishing watchlist signal unless tx.origin "
                    "controls ownership, withdrawal authorization, or recipient choice."
                )
            elif has_access_control and (
                swap_aggregator_user_flow
                or "isowner" in block.header.lower()
                or "isexecutor" in block.header.lower()
            ):
                severity = "medium"
                confidence = "low"
                funds_at_risk = False
                signal = "tx.origin appears in an owner-gated or user-swap helper path."
                manual_check = (
                    "Keep as a composability/phishing watchlist unless tx.origin can "
                    "authorize third-party withdrawal without owner or user approval."
                )
            elif swap_aggregator_user_flow and "permit2" in body.lower():
                severity = "low"
                confidence = "low"
                funds_at_risk = False
                signal = "tx.origin appears in a Permit2-backed user swap helper."
                manual_check = (
                    "Keep as a wallet-composability watchlist unless Permit2 signature "
                    "domain, owner, nonce, or deadline checks are missing."
                )
            else:
                severity = "critical" if money_path and not entrypoint_or_message_gated else "medium"
                confidence = "high"
                funds_at_risk = money_path and not entrypoint_or_message_gated
                signal = "tx.origin is used inside function logic."
                manual_check = (
                    "Check whether authorization, withdrawal approval, or owner "
                    "checks depend on tx.origin."
                )
            add_finding(
                findings,
                Finding(
                    severity=severity,
                    confidence=confidence,
                    funds_at_risk=funds_at_risk,
                    category="authorization",
                    path=path_label,
                    line=find_line(block.lines, "tx.origin"),
                    function=block.name,
                    signal=signal,
                    evidence=snippet_for(block.lines, "tx.origin"),
                    manual_check=manual_check,
                ),
            )

        unchecked_call_kind = low_level_call_primary_kind(block.lines)
        if unchecked_call_kind:
            unchecked_native_stipend = unchecked_call_kind == "native-stipend"
            unchecked_guarded = (
                non_runtime_bundle_source
                or standard_amm_function
                or recipient_or_approved_withdrawal
                or user_funded_launchpad_flow
                or hook_fee_callback_flow
                or tax_or_router_maintenance_swap
                or fixed_masterwallet_transferfrom_sweeper
                or checked_low_level_call_flow
                or standard_low_level_helper
                or openzeppelin_beacon_proxy_helper
                or ens_deed_destroy_cleanup
                or token_trader_user_purchase_flow
                or legacy_lottery_user_or_owner_flow
                or legacy_blockcdn_flow
                or singulardtv_soft_withdraw_credit
                or fixed_price_user_token_buyback
                or user_owned_burn_redeem_flow
                or opyn_otoken_user_flow
                or layerzero_readlib_fee_or_verification_flow
                or teambrella_multisig_wallet_flow
                or safu_presale_liquidity_flow
                or third_party_refund_to_beneficiary
                or fixed_owner_timelock_unlock
                or bittrex_userwallet_sweep_flow
                or ico_refund_request_flow
                or merkle_bound_user_position_update
            )
            add_finding(
                findings,
                Finding(
                    severity=(
                        "low"
                        if unchecked_guarded
                        else
                        "medium"
                        if unchecked_native_stipend
                        else "high"
                        if money_path
                        else "medium"
                    ),
                    confidence="low" if unchecked_native_stipend or unchecked_guarded else "medium",
                    funds_at_risk=money_path and not unchecked_guarded,
                    category="unchecked-call",
                    path=path_label,
                    line=find_low_level_call_line(block.lines),
                    function=block.name,
                    signal=(
                        "Native send/transfer result may be ignored."
                        if unchecked_native_stipend
                        else "Low-level call may not have a clear success check."
                    ),
                    evidence=snippet_for_low_level_call(block.lines),
                    manual_check=(
                        "Confirm call return value is checked and failure cannot "
                        "silently corrupt payout/accounting state."
                    ),
                ),
            )

        if token_transfer_without_safeerc20(block.lines, text) and not standard_amm_function:
            token_transfer_guarded = (
                has_money_guard
                or fixed_recipient_flow
                or cost_bound_payout
                or inbound_deposit_flow
                or inbound_transfer_only_flow
                or recipient_or_approved_withdrawal
                or user_funded_launchpad_flow
                or entrypoint_or_message_gated
                or secret_or_commitment_gated_flow
                or notary_commitment_flow
                or post_expiry_maintenance_flow
                or self_scoped_market_initialization
                or self_scoped_config
                or keeper_incentive_flow
                or debt_backed_liquidation_flow
                or user_funded_redemption_flow
                or game_or_round_settlement_flow
                or payment_splitter_release
                or vault_allowance_bookkeeping
                or vault_allowance_guarded_transfer
                or swap_aggregator_user_flow
                or non_runtime_bundle_source
                or tax_or_router_maintenance_swap
                or fixed_masterwallet_transferfrom_sweeper
                or owner_bound_cell_claim_flow
                or cell_hook_erc20_transfer_override
                or token_trader_user_purchase_flow
                or legacy_blockcdn_flow
                or fixed_price_user_token_buyback
                or user_owned_burn_redeem_flow
                or inbound_balance_delta_accounting
                or opyn_otoken_user_flow
                or layerzero_readlib_fee_or_verification_flow
                or safu_presale_liquidity_flow
                or bittrex_userwallet_sweep_flow
                or ico_refund_request_flow
                or merkle_bound_user_position_update
                or safu_presale_cancel_guarded
                or non_runtime_fixture_source
            )
            if non_runtime_fixture_source:
                transfer_signal = "ERC20-style transfer appears in a non-runtime mock/test bundle source."
                transfer_manual = (
                    "Confirm this file is part of the deployed runtime before escalating "
                    "token-transfer behavior against live balances."
                )
            elif token_transfer_guarded:
                transfer_signal = "ERC20-style transfer appears in a guarded or fixed-recipient path."
                transfer_manual = (
                    "Check non-standard ERC20 return values, fee-on-transfer tokens, "
                    "and whether actual balance delta is used for accounting."
                )
            else:
                transfer_signal = "ERC20-style transfer is used without obvious SafeERC20 usage."
                transfer_manual = (
                    "Check non-standard ERC20 return values, fee-on-transfer tokens, "
                    "and whether actual balance delta is used for accounting."
                )
            add_finding(
                findings,
                Finding(
                    severity="low" if token_transfer_guarded else "high" if money_path else "medium",
                    confidence="low" if token_transfer_guarded else "medium",
                    funds_at_risk=money_path and not token_transfer_guarded,
                    category="token-transfer",
                    path=path_label,
                    line=find_token_transfer_line(block.lines),
                    function=block.name,
                    signal=transfer_signal,
                    evidence=snippet_for_token_transfer(block.lines),
                    manual_check=transfer_manual,
                ),
            )

        if signature_without_replay_guards(body):
            sig_severity = "critical" if money_path else "high"
            sig_confidence = "medium"
            sig_funds = money_path
            sig_signal = "Signature recovery appears without full replay/domain guards."
            if non_runtime_fixture_source:
                sig_severity = "medium"
                sig_confidence = "low"
                sig_funds = False
                sig_signal = "Signature recovery appears in a non-runtime mock/test Sourcify bundle source."
            elif (
                not money_path
                and (
                    view_or_pure
                    or not public_like
                    or exchange_order_readonly_check
                    or teambrella_multisig_wallet_flow
                )
            ):
                sig_severity = "low"
                sig_confidence = "low"
                sig_funds = False
                sig_signal = "Signature recovery appears in a read-only or helper path."
            add_finding(
                findings,
                Finding(
                    severity=sig_severity,
                    confidence=sig_confidence,
                    funds_at_risk=sig_funds,
                    category="signature-replay",
                    path=path_label,
                    line=find_signature_line(block.lines),
                    function=block.name,
                    signal=sig_signal,
                    evidence=snippet_for_signature(block.lines),
                    manual_check=(
                        "Confirm nonce, deadline, chainId, contract address, signer, "
                        "and consumed-order state are included and enforced."
                    ),
                ),
            )

        if oracle_without_freshness(body) and not standard_amm_source:
            oracle_severity = "critical" if money_path else "high"
            oracle_confidence = "medium"
            oracle_funds = money_path
            if (
                entrypoint_or_message_gated
                or debt_backed_liquidation_flow
                or non_runtime_bundle_source
                or sablier_price_gated_oracle_flow
                or standard_amm_accounting_flow
                or view_or_pure
            ):
                oracle_severity = "low"
                oracle_confidence = "low"
                oracle_funds = False
            add_finding(
                findings,
                Finding(
                    severity=oracle_severity,
                    confidence=oracle_confidence,
                    funds_at_risk=oracle_funds,
                    category="oracle",
                    path=path_label,
                    line=find_oracle_line(block.lines),
                    function=block.name,
                    signal="Oracle/spot-price read appears without clear freshness or manipulation checks.",
                    evidence=snippet_for_oracle(block.lines),
                    manual_check=(
                        "Check TWAP/median/staleness/decimals handling before mint, "
                        "redeem, borrow, liquidate, or payout decisions."
                    ),
                ),
            )

        if has_loop(body) and money_path and not (
            view_or_pure
            or plain_storage_getter
            or fixed_recipient_flow
            or keeper_incentive_flow
            or debt_backed_liquidation_flow
            or user_funded_redemption_flow
            or game_or_round_settlement_flow
            or notary_commitment_flow
            or vault_allowance_bookkeeping
            or vault_allowance_guarded_transfer
            or non_runtime_bundle_source
            or recipient_or_approved_withdrawal
            or user_funded_launchpad_flow
            or standard_amm_source
            or swap_aggregator_user_flow
            or hook_fee_callback_flow
            or self_delegatecall_wrapper
            or tax_or_router_maintenance_swap
            or fixed_masterwallet_transferfrom_sweeper
            or owner_only_registry_loop
            or consensys_multisig_owner_management_loop
            or legacy_lottery_user_or_owner_flow
            or legacy_blockcdn_flow
            or inbound_balance_delta_accounting
            or legacy_e4token_segmented_payout_loop
            or layerzero_readlib_fee_or_verification_flow
            or teambrella_multisig_wallet_flow
            or safu_presale_liquidity_flow
            or user_paid_mint_loop
            or bounded_internal_money_loop
        ):
            add_finding(
                findings,
                Finding(
                    severity="high",
                    confidence="medium",
                    funds_at_risk=True,
                    category="dos-locked-funds",
                    path=path_label,
                    line=find_loop_line(block.lines),
                    function=block.name,
                    signal="Loop appears inside a money-path function.",
                    evidence=snippet_for_loop(block.lines),
                    manual_check=(
                        "Check whether a large storage array or failing receiver can "
                        "block withdraw/claim/redeem for users."
                    ),
                ),
            )

        if "unchecked" in body and money_path:
            accounting_guarded = (
                standard_amm_source
                or standard_amm_accounting_flow
                or payment_splitter_release
                or user_paid_mint_loop
                or standard_checked_erc20_accounting
                or standard_erc721_burn_accounting
                or user_owned_burn_redeem_flow
                or inbound_balance_delta_accounting
                or layerzero_readlib_fee_or_verification_flow
                or cell_bucket_accounting
                or checked_stream_accounting
            )
            add_finding(
                findings,
                Finding(
                    severity="low" if accounting_guarded else "medium",
                    confidence="low" if accounting_guarded else "medium",
                    funds_at_risk=not accounting_guarded,
                    category="accounting",
                    path=path_label,
                    line=find_line(block.lines, "unchecked"),
                    function=block.name,
                    signal=(
                        "unchecked arithmetic appears in a guarded standard accounting path."
                        if accounting_guarded
                        else "unchecked block appears in money-path logic."
                    ),
                    evidence=snippet_for(block.lines, "unchecked"),
                    manual_check=(
                        "Check overflow/underflow and rounding around balances, shares, "
                        "rewards, or debt."
                    ),
                ),
            )

        if (
            missing_slippage_or_deadline(block.name, body)
            and (
                solidity_has_external_transfer(body)
                or contains_any(body.lower(), (".swap", "swap(", "poolmanager.", "getreserves", "slot0"))
            )
            and not standard_amm_source
            and not (
                fixed_recipient_flow
                or cost_bound_payout
                or inbound_deposit_flow
                or inbound_transfer_only_flow
                or recipient_or_approved_withdrawal
                or user_funded_launchpad_flow
                or plain_storage_setter
                or self_scoped_config
                or low_priority_config
                or keeper_incentive_flow
                or debt_backed_liquidation_flow
                or secret_or_commitment_gated_flow
                or post_expiry_maintenance_flow
                or self_scoped_market_initialization
                or hook_tx_origin_attribution
                or user_funded_redemption_flow
                or game_or_round_settlement_flow
                or payment_splitter_release
                or vault_allowance_bookkeeping
                or vault_allowance_guarded_transfer
                or swap_aggregator_user_flow
                or non_runtime_bundle_source
                or hook_fee_callback_flow
                or tax_or_router_maintenance_swap
                or token_trader_user_purchase_flow
                or fixed_price_user_token_buyback
                or opyn_otoken_user_flow
                or safu_presale_liquidity_flow
            )
        ):
            add_finding(
                findings,
                Finding(
                    severity="high",
                    confidence="medium",
                    funds_at_risk=True,
                    category="mev-slippage",
                    path=path_label,
                    line=block.start_line,
                    function=block.name,
                    signal="Swap/redeem path lacks obvious slippage or deadline controls.",
                    evidence=block.header,
                    manual_check=(
                        "Check minOut/maxIn/deadline parameters and whether user funds "
                        "can be extracted by price movement or MEV."
                    ),
                ),
            )

    for line_no, line in enumerate(scan_lines, start=1):
        if "selfdestruct" in line:
            deed_cleanup_source = is_ens_deed_selfdestruct_source(text, path_label)
            destruct_severity = "low" if non_runtime_bundle_source or deed_cleanup_source else "high"
            destruct_confidence = "low" if non_runtime_bundle_source or deed_cleanup_source else "high"
            destruct_funds = not (non_runtime_bundle_source or deed_cleanup_source)
            if deed_cleanup_source:
                destruct_signal = "selfdestruct is behind the inactive ENS Deed cleanup path."
            elif non_runtime_bundle_source:
                destruct_signal = "selfdestruct appears in a non-runtime Sourcify bundle source."
            else:
                destruct_signal = "selfdestruct appears in contract code."
            add_finding(
                findings,
                Finding(
                    severity=destruct_severity,
                    confidence=destruct_confidence,
                    funds_at_risk=destruct_funds,
                    category="dangerous-primitive",
                    path=path_label,
                    line=line_no,
                    function="<file>",
                    signal=destruct_signal,
                    evidence=line.strip(),
                    manual_check="Confirm whether this can destroy custody or upgrade implementation code.",
                ),
            )
        if re.search(r"\bpragma\s+solidity\s+\^", line):
            add_finding(
                findings,
                Finding(
                    severity="low",
                    confidence="high",
                    funds_at_risk=False,
                    category="compiler",
                    path=path_label,
                    line=line_no,
                    function="<file>",
                    signal="Floating Solidity pragma is used.",
                    evidence=line.strip(),
                    manual_check="Pin compiler in release builds and compare optimizer/evm settings.",
                ),
            )
    return findings


def low_level_call_primary_kind(lines: list[tuple[int, str]]) -> str | None:
    for index, (_, line) in enumerate(lines):
        if ".call(" not in line and ".call{" not in line and ".send(" not in line:
            continue
        clean = line.strip()
        if clean.startswith("//"):
            continue
        if "require(" in clean or "if (" in clean or "assert(" in clean:
            continue
        result_name = extract_call_result_name(clean)
        if result_name and call_result_checked(lines[index + 1 : index + 5], result_name):
            continue
        if ".send(" in clean:
            return "native-stipend"
        return "call"
    return None


def low_level_call_without_clear_check(lines: list[tuple[int, str]]) -> bool:
    return low_level_call_primary_kind(lines) is not None


def extract_call_result_name(line: str) -> str | None:
    match = re.search(r"\bbool\s+([A-Za-z_][A-Za-z0-9_]*)", line)
    if match:
        return match.group(1)
    match = re.search(r"\(([^,)]+),", line)
    if match:
        name = match.group(1).strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            return name
    return None


def call_result_checked(lines: list[tuple[int, str]], result_name: str) -> bool:
    escaped = re.escape(result_name)
    patterns = (
        rf"require\s*\(\s*{escaped}\b",
        rf"assert\s*\(\s*{escaped}\b",
        rf"if\s*\(\s*!{escaped}\b",
        rf"if\s*\(\s*{escaped}\b",
        rf"revert\s+",
    )
    for _, line in lines:
        if any(re.search(pattern, line) for pattern in patterns):
            return True
    return False


def token_transfer_without_safeerc20(
    lines: list[tuple[int, str]], file_text: str
) -> bool:
    body = "\n".join(line for _, line in lines)
    if "SafeERC20" in file_text or "safeTransfer" in body or "safeTransferFrom" in body:
        return False
    token_transfer_re = re.compile(r"\.\s*(transfer|transferFrom)\s*\(")
    for _, line in lines:
        clean = line.strip()
        if "payable(" in clean or clean.startswith("function "):
            continue
        if not token_transfer_re.search(clean):
            continue
        if is_native_value_transfer_line(clean):
            continue
        return True
    return False


def is_native_value_transfer_line(line: str) -> bool:
    if re.search(r"\.\s*transferFrom\s*\(", line):
        return False
    args = extract_first_call_arguments(line, "transfer")
    if args is None:
        return False
    return count_top_level_arguments(args) <= 1


def extract_first_call_arguments(line: str, name: str) -> str | None:
    match = re.search(rf"\.\s*{re.escape(name)}\s*\(", line)
    if not match:
        return None
    start = match.end()
    depth = 1
    for index in range(start, len(line)):
        char = line[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[start:index]
    return None


def count_top_level_arguments(argument_text: str) -> int:
    stripped = argument_text.strip()
    if not stripped:
        return 0
    depth = 0
    count = 1
    for char in stripped:
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            count += 1
    return count


def signature_has_commitment_state_guards(body: str) -> bool:
    lowered = body.lower()
    if "commitmenthash" not in lowered:
        return False
    has_state_guard = any(
        marker in lowered
        for marker in (
            "nonce",
            "claimedamount",
            "claimed[",
            "spentamount",
            "channelnonce",
            "reservechannelbalance",
        )
    )
    has_signer_guard = any(marker in lowered for marker in ("notary", "signer", "hasrole", "owner"))
    return has_state_guard and has_signer_guard and "recover" in lowered and "require" in lowered


def signature_has_standard_safe_owner_guards(body: str) -> bool:
    lowered = body.lower()
    return all(
        marker in lowered
        for marker in (
            "requiredsignatures",
            "currentowner",
            "owners[currentowner]",
            "lastowner",
        )
    )


def signature_has_eip712_deadline_signer_guards(body: str) -> bool:
    lowered = body.lower()
    has_domain = any(
        marker in lowered
        for marker in (
            "_hashtypeddatav4",
            "domainseparator",
            "domain_separator",
            "eip712domain",
            "verifyingcontract",
            "address(this)",
            "block.chainid",
            "'\\x19\\x01'",
            '"\\x19\\x01"',
        )
    )
    has_expiry = "deadline" in lowered or "block.timestamp" in lowered or "expires" in lowered
    has_signer = any(
        marker in lowered
        for marker in (
            "clientfeereceiver",
            "signer",
            "owner()",
            "recoveredaddress == owner",
            "recoveredaddress==owner",
            "verifyingsigner",
            "trusted",
        )
    )
    return has_domain and has_expiry and has_signer and "recover" in lowered


def signature_is_idempotent_owner_config(body: str) -> bool:
    lowered = body.lower()
    if "owner()" not in lowered or "trading" not in lowered or "recover" not in lowered:
        return False
    if solidity_has_external_transfer(body):
        return False
    return any(marker in lowered for marker in ("domain_separator", "domainseparator", "eip712domain", "block.chainid"))


def signature_without_replay_guards(body: str) -> bool:
    lowered = body.lower()
    has_recover = (
        "ecrecover" in lowered
        or ".recover(" in body
        or "recovercalldata" in lowered
        or "ecdsa" in lowered
    )
    if not has_recover:
        return False
    if signature_has_commitment_state_guards(body):
        return False
    if signature_has_standard_safe_owner_guards(body):
        return False
    if signature_has_eip712_deadline_signer_guards(body):
        return False
    if signature_is_idempotent_owner_config(body):
        return False
    guard_groups = (
        (
            "domainseparator",
            "typeddata",
            "chainid",
            "chain.id",
            "verifyingcontract",
            "address(this)",
            "commitmenthash",
        ),
        (
            "nonce",
            "filled",
            "used",
            "consumed",
            "claimed",
            "executed",
            "invalidnonce",
        ),
        (
            "deadline",
            "expires",
            "expiration",
            "validuntil",
            "validafter",
            "block.timestamp",
        ),
        (
            "hasrole",
            "onlyrole",
            "trusted",
            "verifyingsigner",
            "signeraddress",
            "solver_role",
            "isowner",
            "notary",
        ),
        (
            "msg.sender",
            "caller",
            "userop",
            "request.user",
            "claimant",
            "claimer",
            "staker",
            "depositor",
        ),
    )
    present = sum(
        1
        for group in guard_groups
        if any(marker in lowered for marker in group)
    )
    return present < 3


def oracle_without_freshness(body: str) -> bool:
    oracle_markers = (
        "latestAnswer",
        "latestRoundData",
        "getReserves",
        "slot0",
        ".consult(",
        "getPrice",
        "priceOracle",
        "oracle.",
    )
    if not contains_any(body, oracle_markers):
        return False
    freshness_markers = (
        "updatedAt",
        "answeredInRound",
        "heartbeat",
        "stale",
        "maxDelay",
        "twap",
        "timeWeighted",
        "observation",
        "decimals",
    )
    return not contains_any(body, freshness_markers, lower=True)


def has_loop(body: str) -> bool:
    return bool(re.search(r"\b(for|while)\s*\(", body))


def missing_slippage_or_deadline(name: str, body: str) -> bool:
    lowered = f"{name}\n{body}".lower()
    if not any(
        marker in lowered for marker in ("swap", "redeem", "liquidat", "buy", "sell")
    ):
        return False
    controls = (
        "minout",
        "amountoutmin",
        "minimum",
        "maxin",
        "amountinmax",
        "slippage",
        "deadline",
        "limit",
    )
    return not any(control in lowered for control in controls)


def find_line(lines: list[tuple[int, str]], needle: str) -> int:
    lowered = needle.lower()
    for line_no, line in lines:
        if lowered in line.lower():
            return line_no
    return lines[0][0] if lines else 1


def snippet_for(lines: list[tuple[int, str]], needle: str) -> str:
    lowered = needle.lower()
    for _, line in lines:
        if lowered in line.lower():
            return line.strip()
    return ""


def find_low_level_call_line(lines: list[tuple[int, str]]) -> int:
    for line_no, line in lines:
        if ".call(" in line or ".call{" in line or ".send(" in line:
            return line_no
    return lines[0][0] if lines else 1


def snippet_for_low_level_call(lines: list[tuple[int, str]]) -> str:
    for _, line in lines:
        if ".call(" in line or ".call{" in line or ".send(" in line:
            return line.strip()
    return ""


def find_token_transfer_line(lines: list[tuple[int, str]]) -> int:
    for line_no, line in lines:
        clean = line.strip()
        if "payable(" in clean or clean.startswith("function "):
            continue
        if re.search(r"\.\s*(transfer|transferFrom)\s*\(", clean):
            return line_no
    return lines[0][0] if lines else 1


def snippet_for_token_transfer(lines: list[tuple[int, str]]) -> str:
    for _, line in lines:
        clean = line.strip()
        if "payable(" in clean or clean.startswith("function "):
            continue
        if re.search(r"\.\s*(transfer|transferFrom)\s*\(", clean):
            return clean
    return ""


def find_signature_line(lines: list[tuple[int, str]]) -> int:
    for line_no, line in lines:
        if "ecrecover" in line or ".recover(" in line or "ECDSA" in line:
            return line_no
    return lines[0][0] if lines else 1


def snippet_for_signature(lines: list[tuple[int, str]]) -> str:
    for _, line in lines:
        if "ecrecover" in line or ".recover(" in line or "ECDSA" in line:
            return line.strip()
    return ""


def find_oracle_line(lines: list[tuple[int, str]]) -> int:
    markers = ("latestAnswer", "latestRoundData", "getReserves", "slot0", "oracle")
    for line_no, line in lines:
        if contains_any(line, markers):
            return line_no
    return lines[0][0] if lines else 1


def snippet_for_oracle(lines: list[tuple[int, str]]) -> str:
    markers = ("latestAnswer", "latestRoundData", "getReserves", "slot0", "oracle")
    for _, line in lines:
        if contains_any(line, markers):
            return line.strip()
    return ""


def find_loop_line(lines: list[tuple[int, str]]) -> int:
    for line_no, line in lines:
        if re.search(r"\b(for|while)\s*\(", line):
            return line_no
    return lines[0][0] if lines else 1


def snippet_for_loop(lines: list[tuple[int, str]]) -> str:
    for _, line in lines:
        if re.search(r"\b(for|while)\s*\(", line):
            return line.strip()
    return ""


def scan_move_file(path_label: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    functions = extract_functions(lines, "move")

    for block in functions:
        body = block.body_text
        full = block.header + "\n" + body
        public_like = "public" in block.visibility
        entry_like = "entry" in block.visibility
        money_path = is_money_function(block.name, body) or contains_any(
            body,
            (
                "coin::",
                "balance::",
                "transfer::public_transfer",
                "transfer::transfer",
                "vault",
                "pool",
                "liquidity",
            ),
        )
        has_auth = contains_any(full, MOVE_AUTH_MARKERS)

        if public_like and money_path and not has_auth:
            add_finding(
                findings,
                Finding(
                    severity="critical" if entry_like else "high",
                    confidence="medium",
                    funds_at_risk=True,
                    category="access-control",
                    path=path_label,
                    line=block.start_line,
                    function=block.name,
                    signal="Public Move money-path function has no obvious assert/capability guard.",
                    evidence=block.header,
                    manual_check=(
                        "Confirm ownership/capability checks for objects, positions, "
                        "coins, vaults, and admin operations."
                    ),
                ),
            )

        if contains_any(body, ("transfer::public_transfer", "coin::from_balance")) and public_like:
            add_finding(
                findings,
                Finding(
                    severity="high" if has_auth else "critical",
                    confidence="medium",
                    funds_at_risk=True,
                    category="move-transfer",
                    path=path_label,
                    line=find_line(block.lines, "transfer::"),
                    function=block.name,
                    signal="Move public function transfers assets or materializes coins.",
                    evidence=snippet_for(block.lines, "transfer::")
                    or snippet_for(block.lines, "coin::from_balance"),
                    manual_check=(
                        "Check recipient control, object ownership, capability use, "
                        "and whether assets can be redirected or withdrawn."
                    ),
                ),
            )

        if has_loop(body) and money_path:
            add_finding(
                findings,
                Finding(
                    severity="high",
                    confidence="medium",
                    funds_at_risk=True,
                    category="dos-locked-funds",
                    path=path_label,
                    line=find_loop_line(block.lines),
                    function=block.name,
                    signal="Loop appears inside Move money-path logic.",
                    evidence=snippet_for_loop(block.lines),
                    manual_check=(
                        "Check vector length growth, shared-object contention, and "
                        "whether claims/withdrawals can become too expensive or blocked."
                    ),
                ),
            )

        if contains_any(body, ("vector::length", "vector::borrow"), lower=True) and contains_any(
            body, ("reward", "fee", "claim", "collect", "position"), lower=True
        ):
            add_finding(
                findings,
                Finding(
                    severity="medium",
                    confidence="low",
                    funds_at_risk=True,
                    category="accounting",
                    path=path_label,
                    line=find_line(block.lines, "vector::"),
                    function=block.name,
                    signal="Reward/fee/position logic uses vectors; check length/index accounting.",
                    evidence=snippet_for(block.lines, "vector::"),
                    manual_check=(
                        "Check rewarder vector length changes, index alignment, and "
                        "collect-before/after-liquidity-change edge cases."
                    ),
                ),
            )

    return findings


def scan_vyper_file(path_label: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    text = "\n".join(lines)
    for line_no, line in enumerate(lines, start=1):
        lowered = line.lower()
        money_signal = any(marker.lower() in lowered for marker in MONEY_NAMES)
        if "raw_call(" in lowered or "send(" in lowered:
            context = "\n".join(lines[max(0, line_no - 4) : min(len(lines), line_no + 10)]).lower()
            static_oracle_rate_call = (
                "raw_call(" in lowered
                and "is_static_call=true" in context
                and ("rate_oracles" in text.lower() or "oracle_response" in context)
                and "assert len(" in context
            )
            add_finding(
                findings,
                Finding(
                    severity="low" if static_oracle_rate_call else "high" if money_signal else "medium",
                    confidence="low" if static_oracle_rate_call else "medium",
                    funds_at_risk=money_signal and not static_oracle_rate_call,
                    category="external-call",
                    path=path_label,
                    line=line_no,
                    function="<line>",
                    signal=(
                        "Vyper raw_call is a static oracle/rate read with response-length check."
                        if static_oracle_rate_call
                        else "Vyper raw_call/send appears in source."
                    ),
                    evidence=line.strip(),
                    manual_check="Check success handling and accounting order around payouts.",
                ),
            )
        if "selfdestruct(" in lowered:
            add_finding(
                findings,
                Finding(
                    severity="high",
                    confidence="high",
                    funds_at_risk=True,
                    category="dangerous-primitive",
                    path=path_label,
                    line=line_no,
                    function="<line>",
                    signal="Vyper selfdestruct appears in source.",
                    evidence=line.strip(),
                    manual_check="Confirm whether this can destroy custody or implementation code.",
                ),
            )
    if "nonreentrant" not in text.lower() and contains_any(text, MONEY_NAMES, lower=True):
        add_finding(
            findings,
            Finding(
                severity="medium",
                confidence="low",
                funds_at_risk=True,
                category="reentrancy",
                path=path_label,
                line=1,
                function="<file>",
                signal="Vyper file has money-path names and no obvious nonreentrant marker.",
                evidence="file-level heuristic",
                manual_check="Review withdrawal/claim/redeem functions for checks-effects-interactions.",
            ),
        )
    return findings


def scan_json_file(path_label: str, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        add_finding(
            findings,
            Finding(
                severity="info",
                confidence="low",
                funds_at_risk=False,
                category="inventory",
                path=path_label,
                line=1,
                function="<json>",
                signal="JSON file could not be parsed.",
                evidence=str(exc),
                manual_check="Confirm whether this file is a contract artifact.",
            ),
        )
        return findings

    abi = data.get("abi") if isinstance(data, dict) else None
    if not isinstance(abi, list):
        return findings
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        name = str(item.get("name", ""))
        state = str(item.get("stateMutability", ""))
        if state in {"view", "pure"}:
            continue
        if any(marker.lower() in name.lower() for marker in MONEY_NAMES | ADMIN_NAMES):
            add_finding(
                findings,
                Finding(
                    severity="medium",
                    confidence="low",
                    funds_at_risk=any(marker.lower() in name.lower() for marker in MONEY_NAMES),
                    category="abi-surface",
                    path=path_label,
                    line=1,
                    function=name,
                    signal="ABI exposes state-changing money/admin function; source required.",
                    evidence=f"{name}({state})",
                    manual_check="Map this ABI entry to source and review access control/accounting.",
                ),
            )
    return findings


def scan_file(
    path: Path, base: Path, precheck_states: dict[str, dict[str, object]] | None = None
) -> tuple[dict[str, object], list[Finding]]:
    language = detect_language(path)
    path_label = relpath(path, base)
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()
    inventory = {
        "path": path_label,
        "absolute_path": str(path),
        "language": language,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "line_count": len(lines),
    }
    if language == "solidity":
        precheck_state = (precheck_states or {}).get(address_from_path_label(path_label) or "")
        findings = scan_solidity_file(
            path_label,
            lines,
            compiler_version=find_sourcify_compiler_version(path),
            runtime_source=find_sourcify_runtime_sources(path),
            runtime_contracts=find_sourcify_runtime_contracts(path),
            precheck_state=precheck_state,
        )
    elif language == "move":
        findings = scan_move_file(path_label, lines)
    elif language == "vyper":
        findings = scan_vyper_file(path_label, lines)
    elif language == "json":
        findings = scan_json_file(path_label, path)
    else:
        findings = []
    return inventory, findings


def write_jsonl(path: Path, rows: Iterable[object]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def render_critical_review(
    findings: list[Finding],
    inventories: list[dict[str, object]],
    args: argparse.Namespace,
) -> str:
    counts = severity_counts(findings)
    high_priority = [
        finding
        for finding in findings
        if finding.severity in {"critical", "high"} or finding.funds_at_risk
    ]
    high_priority.sort(key=lambda item: (-item.score, item.path, item.line))
    high_priority = high_priority[: args.critical_limit]

    lines = [
        "# Smart Contract Critical Review Queue",
        "",
        "Mode: offline static triage. Findings are review signals, not confirmed bugs.",
        "",
        "## Summary",
        "",
        f"- Files scanned: {len(inventories)}",
        f"- Findings: {len(findings)}",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        f"- Info: {counts['info']}",
        "",
        "## Review Priority",
        "",
        "Money-path signals are prioritized. Keep all other signals in all-signals.jsonl.",
        "",
    ]

    if not high_priority:
        lines.extend(["No high-priority findings produced by the current heuristics.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(high_priority, start=1):
        funds = "yes" if finding.funds_at_risk else "no"
        lines.extend(
            [
                f"### {index}. {finding.severity.upper()} - {finding.category}",
                "",
                f"- File: `{finding.path}:{finding.line}`",
                f"- Function: `{finding.function}`",
                f"- Confidence: {finding.confidence}",
                f"- Funds at risk: {funds}",
                f"- Score: {finding.score}",
                f"- Signal: {finding.signal}",
                f"- Evidence: `{finding.evidence[:240]}`",
                f"- Manual check: {finding.manual_check}",
                "",
            ]
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.inputs and not args.input_list:
        print("error: provide at least one input path or --input-list", file=sys.stderr)
        return 2

    base = Path.cwd().resolve()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = (
        Path(args.out_dir).resolve()
        if args.out_dir
        else (base / "reports" / f"smart-contract-scan-{timestamp}").resolve()
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    precheck_states = load_precheck_states(args.precheck_json)
    files = collect_files(args)
    inventories: list[dict[str, object]] = []
    findings: list[Finding] = []
    for file_path in files:
        try:
            inventory, file_findings = scan_file(file_path, base, precheck_states)
        except OSError as exc:
            print(f"warning: failed to scan {file_path}: {exc}", file=sys.stderr)
            continue
        inventories.append(inventory)
        findings.extend(file_findings)

    findings.sort(key=lambda item: (-item.score, item.path, item.line))
    finding_rows = [asdict(finding) for finding in findings]

    write_jsonl(out_dir / "contracts-manifest.jsonl", inventories)
    write_jsonl(out_dir / "all-signals.jsonl", finding_rows)
    (out_dir / "critical-review.md").write_text(
        render_critical_review(findings, inventories, args),
        encoding="utf-8",
        newline="\n",
    )

    counts = severity_counts(findings)
    print(f"Scanned files: {len(inventories)}")
    print(f"Findings: {len(findings)}")
    print(
        "Severity: "
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
    )
    print(f"Output: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

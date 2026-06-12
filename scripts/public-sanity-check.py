#!/usr/bin/env python3
"""Check that the public repository stays safe to publish."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".sol",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

REQUIRED_GITIGNORE_ENTRIES = {
    "runs/",
    "tmp/",
    "input/",
    "output/",
    "reports/",
    "evidence/",
    ".env",
    ".env.*",
    "secrets/",
}

FORBIDDEN_TEXT_PATTERNS = {
    "windows-project-path": re.compile(r"[A-Z]:\\(?:Users|Projects)\\", re.IGNORECASE),
    "private-vps-root": re.compile("/root" + r"/apps/"),
    "local-secret-helper": re.compile(r"\bupdate\.py\b", re.IGNORECASE),
    "codex-local-context": re.compile(r"\bcodex-pentest\b|\bpentest-smart-contract-scanner\b", re.IGNORECASE),
    "bot-token-assignment": re.compile(r"\b(?:BOT_TOKEN|CHAT_ID)\s*=\s*['\"][^'\"]{8,}['\"]"),
    "api-key-assignment": re.compile(r"\b(?:api[_-]?key|secret|token)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
}

README_MARKERS = {
    "comprehensive",
    "powerful",
    "seamless",
    "wide range",
    "important to note",
    "in conclusion",
    "plays a crucial",
    "robust",
    "leverage",
    "not only",
    "various",
    "significant",
}


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def tracked_files() -> list[Path]:
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"failed to list tracked files: {exc}")
    return [ROOT / line.strip() for line in output.splitlines() if line.strip()]


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def scan_public_text(files: list[Path]) -> None:
    findings: list[str] = []
    for path in files:
        if not is_text_file(path):
            continue
        rel = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(f"{rel}: file is not valid UTF-8")
            continue
        for name, pattern in FORBIDDEN_TEXT_PATTERNS.items():
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(f"{rel}:{line_no}: {name}")
    if findings:
        fail("public text scan failed:\n" + "\n".join(findings))


def check_readme_markers() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    hits = sorted(marker for marker in README_MARKERS if marker in readme)
    if hits:
        fail("README contains generic marker phrase(s): " + ", ".join(hits))


def load_json(rel_path: str) -> dict[str, object]:
    path = ROOT / rel_path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{rel_path}: failed to parse JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{rel_path}: root must be an object")
    return data


def check_monitor_config(rel_path: str) -> None:
    data = load_json(rel_path)
    defaults = data.get("defaults")
    if not isinstance(defaults, dict):
        fail(f"{rel_path}: defaults must be an object")
    monitor = defaults.get("monitor")
    if not isinstance(monitor, dict):
        fail(f"{rel_path}: defaults.monitor must be an object")
    if monitor.get("telegramAlerts") is not False:
        fail(f"{rel_path}: public default telegramAlerts must be false")
    chains = data.get("chains")
    if not isinstance(chains, list) or not chains:
        fail(f"{rel_path}: chains must be a non-empty list")
    for chain in chains:
        if not isinstance(chain, dict):
            fail(f"{rel_path}: chain entries must be objects")
        chain_monitor = chain.get("monitor")
        if isinstance(chain_monitor, dict) and chain_monitor.get("telegramAlerts") is True:
            fail(f"{rel_path}: chain {chain.get('slug')} enables telegramAlerts")


def check_gitignore() -> None:
    entries = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = sorted(REQUIRED_GITIGNORE_ENTRIES - entries)
    if missing:
        fail(".gitignore is missing: " + ", ".join(missing))


def main() -> int:
    files = tracked_files()
    scan_public_text(files)
    check_readme_markers()
    check_monitor_config("config/smart-contract-evm-chains.json")
    check_monitor_config("config/smart-contract-non-evm-chains.json")
    check_gitignore()
    print("Public sanity OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

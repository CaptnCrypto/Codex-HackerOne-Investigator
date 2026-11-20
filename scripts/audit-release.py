#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SECRET_PATTERNS = {
    "AWS access key": re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "GitHub token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "Slack token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "JWT": re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

PRIVATE_MARKERS = (
    b"/home/" + b"cyber/",
    b"bugbountytrial" + b"acme",
    b"capt." + b"ncrypto",
    b"weare" + b"hackerone.com",
)

STAGE_FIVE_RUNTIME = {
    "vm_bridge.py",
    "vm_client.py",
    "files-vm-request-broker",
    "files-vm-broker-client",
}


def audit(root: Path) -> list[str]:
    failures: list[str] = []
    files = sorted(
        path
        for path in root.rglob("*")
        if ".git" not in path.relative_to(root).parts
        and (path.is_file() or path.is_symlink())
    )
    for path in files:
        relative = path.relative_to(root)
        if path.is_symlink():
            failures.append(f"symlink refused: {relative}")
            continue
        raw = path.read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            failures.append(f"oversized file: {relative}")
        if b"\x00" in raw:
            failures.append(f"binary file: {relative}")
        for marker in PRIVATE_MARKERS:
            if marker in raw:
                failures.append(f"private case marker: {relative}")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(raw):
                failures.append(f"{label} pattern: {relative}")

    names = {path.name for path in files}
    for name in sorted(STAGE_FIVE_RUNTIME.intersection(names)):
        failures.append(f"unfinished Stage 5 runtime included: {name}")

    for name in ("allowlist.template.json", "broker-disabled.template.json"):
        path = root / "config" / name
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append(f"invalid public configuration {name}: {type(exc).__name__}")
            continue
        if config.get("enabled") is not False:
            failures.append(f"public configuration enabled: {name}")
        if config.get("broker", {}).get("execution_enabled") is not False:
            failures.append(f"public broker execution enabled: {name}")
        if config.get("targets") != []:
            failures.append(f"public target list is not empty: {name}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit the public release tree for unsafe material")
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args(argv).root.resolve(strict=True)
    failures = audit(root)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    count = sum(
        1
        for path in root.rglob("*")
        if ".git" not in path.relative_to(root).parts and path.is_file()
    )
    print(f"release audit passed: {count} regular files; disabled configs; no matched secrets or private markers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

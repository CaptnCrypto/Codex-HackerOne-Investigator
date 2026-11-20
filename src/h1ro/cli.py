from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .client import APIError, HTTPSJSONTransport, HackerOneClient
from .security import CredentialSecurityError, read_credentials
from .workflow import synchronize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="h1-ro",
        description="Read-only HackerOne program synchronizer for a private investigation case.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    sync = subparsers.add_parser("sync", help="perform the allowlisted read-only synchronization")
    sync.add_argument(
        "--case-root",
        type=Path,
        required=True,
        help="private case root containing CASE-INFO.txt",
    )
    sync.add_argument(
        "--credentials-dir",
        type=Path,
        default=Path.home() / ".config" / "hackerone",
        help="directory containing 0600 username and token files",
    )
    sync.add_argument("--timeout", type=float, default=20.0, help="HTTPS timeout in seconds (5-60)")
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    if args.command != "sync":
        return 2
    try:
        username, token = read_credentials(args.credentials_dir)
        transport = HTTPSJSONTransport(username, token, timeout=args.timeout)
        client = HackerOneClient(transport)
        outputs = synchronize(client, args.case_root)
    except (CredentialSecurityError, APIError, RuntimeError, ValueError) as exc:
        print(f"h1-ro: {exc}", file=sys.stderr)
        return 1
    # Output paths only. Never echo credentials or response bodies.
    print(json.dumps({key: str(value) for key, value in outputs.items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

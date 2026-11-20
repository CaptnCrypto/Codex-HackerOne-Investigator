from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .rate_limit import RateLimitError, SharedRateLimiter
from .scope_guard import ScopeGuard, ScopeGuardError, load_config


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="files-preflight",
        description="Offline Files.com scope and shared-rate preflight; performs no HTTP requests.",
    )
    commands = result.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-config")
    validate.add_argument("config", type=Path)
    check = commands.add_parser("check-url")
    check.add_argument("config", type=Path)
    acquire = commands.add_parser("acquire-rate-slot")
    acquire.add_argument("state_file", type=Path)
    acquire.add_argument("--requests-per-second", type=float, default=1.5)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate-config":
            ScopeGuard(load_config(args.config))
            print("configuration valid and enabled")
        elif args.command == "check-url":
            value = sys.stdin.readline().rstrip("\r\n")
            ScopeGuard(load_config(args.config)).authorize_url(value)
            print("URL authorized by exact-host guard")
        elif args.command == "acquire-rate-slot":
            SharedRateLimiter(
                args.state_file,
                requests_per_second=args.requests_per_second,
            ).acquire()
            print("shared rate slot granted; no network request was sent")
        return 0
    except (ScopeGuardError, RateLimitError) as exc:
        print(f"files-preflight: denied: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

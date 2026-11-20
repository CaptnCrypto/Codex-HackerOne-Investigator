from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from pathlib import Path
from typing import Callable


MAX_SAFETY_RATE = 1.5


class RateLimitError(RuntimeError):
    pass


def current_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RateLimitError("cannot determine host boot identifier") from exc
    if not value:
        raise RateLimitError("host boot identifier is empty")
    return value


class SharedRateLimiter:
    """Cross-process fixed-interval limiter backed by a locked private state file."""

    def __init__(
        self,
        state_path: Path,
        *,
        requests_per_second: float = MAX_SAFETY_RATE,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        boot_id: str | None = None,
    ) -> None:
        if (
            not isinstance(requests_per_second, (int, float))
            or isinstance(requests_per_second, bool)
            or not 0 < requests_per_second <= MAX_SAFETY_RATE
        ):
            raise RateLimitError("requested rate exceeds the 1.5 requests/second safety cap")
        self.state_path = state_path
        self.interval = 1.0 / requests_per_second
        self.clock = clock
        self.sleeper = sleeper
        self.boot_id = boot_id or current_boot_id()

    def acquire(self) -> float:
        parent = self.state_path.parent
        try:
            info = parent.stat()
        except OSError as exc:
            raise RateLimitError("rate-state directory is not accessible") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise RateLimitError("rate-state directory must be a user-owned directory")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RateLimitError("rate-state directory permissions must be 0700 or stricter")

        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.state_path, flags, 0o600)
        except OSError as exc:
            raise RateLimitError("cannot safely open rate-state file") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise RateLimitError("rate-state file must be a user-owned regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise RateLimitError("rate-state file permissions must be 0600 or stricter")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            state = self._read_state(descriptor)
            now = self.clock()
            last = None
            if state is not None and state["boot_id"] == self.boot_id:
                last = state["last_grant_monotonic"]
                if last > now:
                    raise RateLimitError("rate-state clock is ahead of the current clock")
            if last is not None:
                delay = self.interval - (now - last)
                if delay > 0:
                    self.sleeper(delay)
            granted = self.clock()
            self._write_state(descriptor, granted)
            return granted
        finally:
            os.close(descriptor)

    def _read_state(self, descriptor: int) -> dict[str, object] | None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, 4096)
        if not raw:
            return None
        try:
            value = json.loads(raw)
            boot_id = value["boot_id"]
            last = value["last_grant_monotonic"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RateLimitError("rate-state file is malformed") from exc
        if not isinstance(boot_id, str) or not isinstance(last, (int, float)) or isinstance(last, bool):
            raise RateLimitError("rate-state file is malformed")
        return {"boot_id": boot_id, "last_grant_monotonic": float(last)}

    def _write_state(self, descriptor: int, granted: float) -> None:
        payload = json.dumps(
            {
                "boot_id": self.boot_id,
                "last_grant_monotonic": granted,
            },
            separators=(",", ":"),
        ).encode("ascii")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, payload)
        os.fsync(descriptor)

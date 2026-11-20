from __future__ import annotations

import os
import stat
from pathlib import Path


class CredentialSecurityError(RuntimeError):
    pass


def _read_secret_file(path: Path, *, max_bytes: int = 4096) -> str:
    """Read one credential without following links or accepting loose permissions."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CredentialSecurityError(f"cannot securely open credential file {path.name}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CredentialSecurityError(f"credential path is not a regular file: {path.name}")
        if info.st_uid != os.geteuid():
            raise CredentialSecurityError(f"credential file has an unexpected owner: {path.name}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise CredentialSecurityError(f"credential file permissions are too broad: {path.name}")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise CredentialSecurityError(f"credential file is unexpectedly large: {path.name}")
    finally:
        os.close(fd)

    try:
        value = data.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise CredentialSecurityError(f"credential file is not UTF-8 text: {path.name}") from exc
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise CredentialSecurityError(f"credential file must contain one non-empty line: {path.name}")
    return value


def read_credentials(directory: Path) -> tuple[str, str]:
    directory = directory.expanduser()
    if directory.is_symlink():
        raise CredentialSecurityError("credential directory must not be a symlink")
    directory = directory.resolve(strict=True)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise CredentialSecurityError("credential path is not a directory")
    if info.st_uid != os.geteuid():
        raise CredentialSecurityError("credential directory has an unexpected owner")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise CredentialSecurityError("credential directory permissions are too broad")
    return _read_secret_file(directory / "username"), _read_secret_file(directory / "token")


def ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"refusing symlinked output directory: {path}")
    os.chmod(path, 0o700)


def atomic_write(path: Path, content: str) -> None:
    ensure_private_directory(path.parent)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise

from __future__ import annotations

import json
import os
import re
import stat
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


TRIAL_HOST_RE = re.compile(r"^(?P<label>[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.files\.com$")
HOSTING_HOST_RE = re.compile(
    r"^(?P<label>[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.hosted-by-files\.com$"
)
RESERVED_FILES_LABELS = frozenset(
    {
        "app",
        "developers",
        "mail",
        "status",
        "www",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ScopeGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthorizedTarget:
    host: str
    path_prefixes: tuple[str, ...]
    approved_exact_urls: tuple[str, ...]
    ownership: str
    trial_reference: str
    verified_at: datetime


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ScopeGuardError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScopeGuardError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ScopeGuardError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _read_private_file(path: Path) -> bytes:
    parent = path.parent
    if parent.is_symlink():
        raise ScopeGuardError("configuration directory must not be a symlink")
    try:
        parent_info = parent.stat()
    except OSError as exc:
        raise ScopeGuardError("configuration directory is not accessible") from exc
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise ScopeGuardError("configuration directory must be user-owned mode 0700")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ScopeGuardError("configuration must be a readable non-symlink file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ScopeGuardError("configuration must be a regular file")
        if info.st_uid != os.getuid():
            raise ScopeGuardError("configuration must be owned by the invoking user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ScopeGuardError("configuration permissions must be 0600 or stricter")
        raw = os.read(descriptor, 64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ScopeGuardError("configuration exceeds the 64 KiB safety limit")
        return raw
    finally:
        os.close(descriptor)


def load_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_private_file(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScopeGuardError("configuration is not valid readable JSON") from exc
    if not isinstance(value, dict):
        raise ScopeGuardError("configuration top level must be an object")
    return value


class ScopeGuard:
    """Exact-host, default-deny guard for researcher-owned Files.com trials."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if config.get("version") != 1:
            raise ScopeGuardError("unsupported configuration version")
        if config.get("enabled") is not True:
            raise ScopeGuardError("scope guard is disabled pending manual approval")

        policy = config.get("policy_verification")
        if not isinstance(policy, dict):
            raise ScopeGuardError("policy verification is missing")
        if not SHA256_RE.fullmatch(str(policy.get("policy_sha256", ""))):
            raise ScopeGuardError("fresh policy SHA-256 is missing or invalid")
        verified_at = _parse_timestamp(policy.get("verified_at"), "policy verified_at")
        expires_at = _parse_timestamp(policy.get("expires_at"), "policy expires_at")

        approval = config.get("researcher_approval")
        if not isinstance(approval, dict) or approval.get("approved") is not True:
            raise ScopeGuardError("researcher approval is absent")
        if not isinstance(approval.get("approval_reference"), str) or not approval[
            "approval_reference"
        ].strip():
            raise ScopeGuardError("researcher approval reference is absent")
        approved_at = _parse_timestamp(approval.get("approved_at"), "approval approved_at")

        current = now().astimezone(timezone.utc)
        if verified_at > current or approved_at > current:
            raise ScopeGuardError("verification or approval timestamp is in the future")
        if expires_at <= current:
            raise ScopeGuardError("policy verification has expired")

        rate = config.get("rate_limit", {}).get("requests_per_second")
        if not isinstance(rate, (int, float)) or isinstance(rate, bool):
            raise ScopeGuardError("rate limit must be numeric")
        if not 0 < float(rate) <= 1.5:
            raise ScopeGuardError("rate limit must be within the 1.5 requests/second safety cap")

        targets = config.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ScopeGuardError("no exact researcher-owned targets are approved")
        parsed_targets: dict[str, AuthorizedTarget] = {}
        for raw in targets:
            target = self._validate_target(raw, current=current)
            if target.host in parsed_targets:
                raise ScopeGuardError("duplicate exact target host")
            parsed_targets[target.host] = target
        self.targets = parsed_targets
        self.requests_per_second = float(rate)

    @staticmethod
    def _validate_target(raw: Any, *, current: datetime) -> AuthorizedTarget:
        if not isinstance(raw, dict):
            raise ScopeGuardError("each target must be an object")
        if raw.get("approved") is not True:
            raise ScopeGuardError("every target requires explicit researcher approval")
        host = raw.get("host")
        if not isinstance(host, str) or host != host.lower():
            raise ScopeGuardError("target host must be a lowercase exact hostname")
        if "*" in host or host.endswith("."):
            raise ScopeGuardError("wildcard and trailing-dot hosts are forbidden")

        trial_match = TRIAL_HOST_RE.fullmatch(host)
        hosting_match = HOSTING_HOST_RE.fullmatch(host)
        ownership = raw.get("ownership")
        if trial_match:
            if trial_match.group("label") in RESERVED_FILES_LABELS:
                raise ScopeGuardError("shared Files.com hosts are not researcher-owned trials")
            expected_ownership = "researcher-owned-files-trial"
        elif hosting_match:
            expected_ownership = "researcher-owned-public-hosting"
        else:
            raise ScopeGuardError("target is not an exact supported trial hostname")
        if ownership != expected_ownership:
            raise ScopeGuardError("target ownership declaration does not match hostname type")

        trial_reference = raw.get("trial_reference")
        if not isinstance(trial_reference, str) or not trial_reference.strip():
            raise ScopeGuardError("target trial reference is missing")
        target_verified_at = _parse_timestamp(raw.get("verified_at"), "target verified_at")
        if target_verified_at > current:
            raise ScopeGuardError("target verification timestamp is in the future")

        prefixes = raw.get("path_prefixes")
        if not isinstance(prefixes, list) or not prefixes:
            raise ScopeGuardError("target must define at least one path prefix")
        clean_prefixes: list[str] = []
        for prefix in prefixes:
            if (
                not isinstance(prefix, str)
                or not prefix.startswith("/")
                or "?" in prefix
                or "#" in prefix
                or "\\" in prefix
            ):
                raise ScopeGuardError("path prefixes must be absolute URL paths")
            clean_prefixes.append(prefix)

        exact_urls = raw.get("approved_exact_urls", [])
        if not isinstance(exact_urls, list) or any(
            not isinstance(value, str) for value in exact_urls
        ):
            raise ScopeGuardError("approved exact URLs must be a list of strings")
        if len(set(exact_urls)) != len(exact_urls):
            raise ScopeGuardError("approved exact URLs must be unique")
        for value in exact_urls:
            if not value or any(ord(ch) < 32 for ch in value):
                raise ScopeGuardError("approved exact URL is empty or contains control characters")
            try:
                parsed = urllib.parse.urlsplit(value)
                port = parsed.port
            except ValueError as exc:
                raise ScopeGuardError("approved exact URL authority is invalid") from exc
            if (
                parsed.scheme != "https"
                or parsed.hostname != host
                or parsed.username is not None
                or parsed.password is not None
                or port not in (None, 443)
                or parsed.fragment
                or not parsed.query
            ):
                raise ScopeGuardError(
                    "approved exact URLs must use the target HTTPS host, a query, and no userinfo or fragment"
                )
            decoded_exact_path = urllib.parse.unquote(parsed.path or "/")
            if "\\" in decoded_exact_path or any(
                segment in {".", ".."} for segment in decoded_exact_path.split("/")
            ):
                raise ScopeGuardError("approved exact URL path is ambiguous or traversing")
            if not any(_path_matches(decoded_exact_path, prefix) for prefix in clean_prefixes):
                raise ScopeGuardError("approved exact URL is outside the target path prefixes")
        return AuthorizedTarget(
            host,
            tuple(clean_prefixes),
            tuple(exact_urls),
            ownership,
            trial_reference.strip(),
            target_verified_at,
        )

    def authorize_url(self, value: str) -> AuthorizedTarget:
        if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
            raise ScopeGuardError("URL is missing or contains control characters")
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ScopeGuardError("URL authority is invalid") from exc
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or parsed.fragment
        ):
            raise ScopeGuardError("only HTTPS port 443 URLs without userinfo or fragments are allowed")
        host = parsed.hostname
        if host is None or host != host.lower() or parsed.netloc.endswith("."):
            raise ScopeGuardError("URL must contain a lowercase exact hostname")
        target = self.targets.get(host)
        if target is None:
            raise ScopeGuardError("URL host is not on the exact researcher-owned allowlist")
        if target.approved_exact_urls and value not in target.approved_exact_urls:
            raise ScopeGuardError("URL is not on the target's exact request allowlist")
        path = parsed.path or "/"
        lowered_path = path.lower()
        if ("%2f" in lowered_path or "%5c" in lowered_path) and value not in target.approved_exact_urls:
            raise ScopeGuardError("encoded path separators are not allowed by the guard")
        decoded_path = urllib.parse.unquote(path)
        if "\\" in decoded_path or any(
            segment in {".", ".."} for segment in decoded_path.split("/")
        ):
            raise ScopeGuardError("ambiguous or traversing URL paths are not allowed")
        if not any(_path_matches(decoded_path, prefix) for prefix in target.path_prefixes):
            raise ScopeGuardError("URL path is outside the approved path prefixes")
        return target


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return path.startswith("/")
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")

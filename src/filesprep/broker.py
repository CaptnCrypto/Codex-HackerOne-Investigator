from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import tempfile
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from .rate_limit import SharedRateLimiter
from .scope_guard import ScopeGuard, ScopeGuardError


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
APPROVED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
FORBIDDEN_HEADERS = frozenset(
    {
        "connection", "forwarded", "host", "proxy-authorization", "proxy-connection",
        "te", "trailer", "transfer-encoding", "upgrade", "x-forwarded-for",
        "x-forwarded-host", "x-forwarded-proto",
    }
)
SENSITIVE_HEADERS = frozenset(
    {
        "authorization", "cookie", "proxy-authorization", "set-cookie",
        "x-api-key", "x-filesapi-key",
    }
)


class BrokerError(RuntimeError):
    pass


class Transport(Protocol):
    def send(self, request: "PreparedRequest", ip: str) -> "TransportResponse": ...


@dataclass(frozen=True)
class PreparedRequest:
    request_id: str
    target_id: str
    hypothesis_id: str
    approval_reference: str
    method: str
    host: str
    path_query: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: dict[str, str]
    body: bytes


def _public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BrokerError("approved address is not an IP literal") from exc
    if not address.is_global:
        raise BrokerError("approved address must be globally routable")
    return address.compressed


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise BrokerError("private directory must be user-owned mode 0700")


def _atomic_private_write(path: Path, data: bytes) -> None:
    _private_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_private_secret(path_value: Any) -> str:
    if not isinstance(path_value, str):
        raise BrokerError("credential secret file path is missing")
    path = Path(path_value)
    if not path.is_absolute():
        raise BrokerError("credential secret file path must be absolute")
    parent = path.parent
    try:
        parent_info = parent.stat()
    except OSError as exc:
        raise BrokerError("credential secret directory is not accessible") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise BrokerError("credential secret directory must be user-owned mode 0700")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BrokerError("credential secret must be a readable non-symlink file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BrokerError("credential secret must be a regular file")
        if info.st_uid != os.getuid():
            raise BrokerError("credential secret must be owned by the broker user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise BrokerError("credential secret permissions must be 0600 or stricter")
        raw = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    if len(raw) > 8192:
        raise BrokerError("credential secret exceeds the 8 KiB safety limit")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\r" in raw or b"\n" in raw or any(value < 0x20 or value == 0x7F for value in raw):
        raise BrokerError("credential secret must be one non-empty printable line")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BrokerError("credential secret must contain ASCII characters only") from exc


class BrokerPolicy:
    def __init__(self, config: dict[str, Any], *, now: Callable[[], datetime]) -> None:
        self.scope = ScopeGuard(config, now=now)
        self._approval_reference = config["researcher_approval"]["approval_reference"].strip()
        broker = config.get("broker")
        if not isinstance(broker, dict) or broker.get("execution_enabled") is not True:
            raise BrokerError("broker execution is disabled pending activation approval")
        self.targets: dict[str, dict[str, Any]] = {}
        for entry in config["targets"]:
            host = entry["host"]
            target_id = entry.get("target_id")
            methods = entry.get("approved_methods")
            addresses = entry.get("approved_ip_addresses")
            hypotheses = entry.get("approved_hypothesis_ids")
            credential = entry.get("credential")
            exact_urls = entry.get("approved_exact_urls")
            if not isinstance(target_id, str) or not SAFE_ID.fullmatch(target_id):
                raise BrokerError("each target requires a safe target_id")
            if not isinstance(methods, list) or not methods:
                raise BrokerError("each target requires explicitly approved methods")
            method_set = frozenset(methods)
            if any(not isinstance(m, str) or m != m.upper() for m in methods):
                raise BrokerError("approved methods must be uppercase strings")
            if not method_set <= APPROVED_METHODS:
                raise BrokerError("target contains a prohibited HTTP method")
            if not isinstance(addresses, list) or not addresses:
                raise BrokerError("each target requires manually approved pinned IP addresses")
            approved_ips = frozenset(_public_ip(v) for v in addresses if isinstance(v, str))
            if len(approved_ips) != len(addresses):
                raise BrokerError("approved IP addresses must be unique strings")
            if not isinstance(hypotheses, list) or not hypotheses or any(
                not isinstance(v, str) or not SAFE_ID.fullmatch(v) for v in hypotheses
            ):
                raise BrokerError("each target requires approved hypothesis identifiers")
            if not isinstance(exact_urls, list) or not exact_urls:
                raise BrokerError("active broker targets require at least one exact approved URL")
            if (
                not isinstance(credential, dict)
                or set(credential) != {"header_name", "secret_file"}
                or credential.get("header_name") != "X-FilesAPI-Key"
                or not isinstance(credential.get("secret_file"), str)
                or not Path(credential["secret_file"]).is_absolute()
            ):
                raise BrokerError("each target requires one host-side Files.com credential")
            self.targets[host] = {
                "target_id": target_id,
                "methods": method_set,
                "ips": approved_ips,
                "hypotheses": frozenset(hypotheses),
                "credential": credential,
            }
        self.max_request_bytes = int(broker.get("max_request_bytes", 1048576))
        self.max_response_bytes = int(broker.get("max_response_bytes", 4194304))
        if not 0 <= self.max_request_bytes <= 1048576 or not 1 <= self.max_response_bytes <= 4194304:
            raise BrokerError("broker byte limits exceed safety caps")

    def prepare(self, envelope: Any) -> PreparedRequest:
        if not isinstance(envelope, dict):
            raise BrokerError("request envelope must be an object")
        allowed = {"request_id", "method", "url", "headers", "body_base64", "hypothesis_id", "approval_reference"}
        if set(envelope) - allowed:
            raise BrokerError("request envelope contains unsupported fields")
        request_id = envelope.get("request_id")
        hypothesis = envelope.get("hypothesis_id")
        approval = envelope.get("approval_reference")
        if any(not isinstance(v, str) or not SAFE_ID.fullmatch(v) for v in (request_id, hypothesis, approval)):
            raise BrokerError("request, hypothesis, and approval identifiers are required")
        method = envelope.get("method")
        if not isinstance(method, str) or method != method.upper() or method not in APPROVED_METHODS:
            raise BrokerError("HTTP method is not broker-approved")
        url = envelope.get("url")
        try:
            target = self.scope.authorize_url(url)
            parsed = urllib.parse.urlsplit(url)
        except (ScopeGuardError, TypeError) as exc:
            raise BrokerError(str(exc)) from exc
        details = self.targets[target.host]
        if method not in details["methods"]:
            raise BrokerError("HTTP method is not approved for this target")
        if hypothesis not in details["hypotheses"]:
            raise BrokerError("hypothesis is not approved for this target")
        if approval != self.scope_config_approval:
            raise BrokerError("request approval reference does not match current approval")
        headers = self._headers(envelope.get("headers", {}))
        credential = details["credential"]
        headers[credential["header_name"]] = _read_private_secret(credential["secret_file"])
        raw_body = envelope.get("body_base64")
        if raw_body is None:
            body = b""
        elif isinstance(raw_body, str):
            try:
                body = base64.b64decode(raw_body, validate=True)
            except ValueError as exc:
                raise BrokerError("body_base64 is invalid") from exc
        else:
            raise BrokerError("body_base64 must be a string or null")
        if len(body) > self.max_request_bytes:
            raise BrokerError("request body exceeds configured limit")
        path_query = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        return PreparedRequest(request_id, details["target_id"], hypothesis, approval, method, target.host, path_query, headers, body)

    @property
    def scope_config_approval(self) -> str:
        # ScopeGuard already validated this value; keep only a non-secret approval identifier.
        return self._approval_reference

    @staticmethod
    def _headers(raw: Any) -> dict[str, str]:
        if not isinstance(raw, dict) or len(raw) > 64:
            raise BrokerError("headers must be an object with at most 64 entries")
        clean: dict[str, str] = {}
        for name, value in raw.items():
            if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
                raise BrokerError("invalid HTTP header name")
            if name.lower() in FORBIDDEN_HEADERS:
                raise BrokerError("hop-by-hop or routing headers are forbidden")
            if name.lower() in SENSITIVE_HEADERS:
                raise BrokerError("client-supplied credential headers are forbidden")
            if not isinstance(value, str) or "\r" in value or "\n" in value or len(value) > 8192:
                raise BrokerError("invalid HTTP header value")
            clean[name] = value
        return clean


class DirectTLSTransport:
    """HTTPS transport pinned to a preapproved IP; never uses proxy settings."""

    def __init__(self, *, timeout: float = 15.0, max_response_bytes: int = 4194304) -> None:
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.context = ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt")
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def send(self, request: PreparedRequest, ip: str) -> TransportResponse:
        connection = _PinnedHTTPSConnection(request.host, ip, self.context, self.timeout)
        try:
            connection.request(request.method, request.path_query, body=request.body, headers=request.headers)
            response = connection.getresponse()
            body = response.read(self.max_response_bytes + 1)
            if len(body) > self.max_response_bytes:
                raise BrokerError("response exceeds configured byte limit")
            headers = {k: v for k, v in response.getheaders() if k.lower() not in SENSITIVE_HEADERS}
            return TransportResponse(response.status, headers, body)
        finally:
            connection.close()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(host, port=443, timeout=timeout, context=context)
        self._approved_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._approved_ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class RequestBroker:
    def __init__(
        self, config: dict[str, Any], *, runtime_dir: Path, evidence_dir: Path,
        resolver: Callable[[str], set[str]], transport: Transport,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        limiter: SharedRateLimiter | None = None,
    ) -> None:
        self.policy = BrokerPolicy(config, now=now)
        self.runtime_dir, self.evidence_dir = runtime_dir, evidence_dir
        _private_directory(runtime_dir)
        _private_directory(evidence_dir)
        self.stop_path = runtime_dir / "STOP"
        self.resolver, self.transport, self.now = resolver, transport, now
        self.limiter = limiter or SharedRateLimiter(runtime_dir / "rate-state.json", requests_per_second=self.policy.scope.requests_per_second)

    def emergency_stop(self, reason: str = "manual") -> None:
        safe_reason = reason if SAFE_ID.fullmatch(reason) else "manual"
        _atomic_private_write(self.stop_path, (safe_reason + "\n").encode("ascii"))

    def execute(self, envelope: Any) -> dict[str, Any]:
        self._check_running()
        prepared = self.policy.prepare(envelope)
        self.limiter.acquire()
        self._check_running()
        try:
            resolved = {_public_ip(value) for value in self.resolver(prepared.host)}
        except Exception as exc:
            self.emergency_stop("dns-resolution-failure")
            raise BrokerError("DNS resolution failed closed; emergency stop engaged") from exc
        approved = self.policy.targets[prepared.host]["ips"]
        if not resolved or not resolved <= approved:
            self.emergency_stop("dns-pin-violation")
            raise BrokerError("DNS result differs from approved IP pins; emergency stop engaged")
        self._check_running()
        try:
            response = self.transport.send(prepared, sorted(resolved)[0])
        except Exception as exc:
            self.emergency_stop("transport-failure")
            raise BrokerError("transport failed closed; emergency stop engaged") from exc
        self._check_running()
        if 300 <= response.status <= 399:
            self._audit(prepared, response.status, len(response.body), "redirect-blocked")
            raise BrokerError("redirect response blocked; broker never follows redirects")
        if response.status == 429 or response.status >= 500:
            self._audit(prepared, response.status, len(response.body), "availability-stop")
            self.emergency_stop("availability-signal")
            raise BrokerError("availability signal received; emergency stop engaged")
        self._audit(prepared, response.status, len(response.body), "complete")
        return {"request_id": prepared.request_id, "status": response.status, "headers": response.headers, "body_base64": base64.b64encode(response.body).decode("ascii")}

    def _check_running(self) -> None:
        if self.stop_path.exists():
            raise BrokerError("emergency stop is active")

    def _audit(self, request: PreparedRequest, status: int, size: int, outcome: str) -> None:
        record = {
            "timestamp": self.now().astimezone(timezone.utc).isoformat(),
            "request_id": request.request_id, "target_id": request.target_id,
            "hypothesis_id": request.hypothesis_id, "method": request.method,
            "path_sha256": hashlib.sha256(request.path_query.split("?", 1)[0].encode()).hexdigest(),
            "query_present": "?" in request.path_query,
            "http_status": status, "response_bytes": size, "outcome": outcome,
        }
        path = self.evidence_dir / f"{request.request_id}.json"
        _atomic_private_write(path, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())


def system_resolver(host: str) -> set[str]:
    return {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}

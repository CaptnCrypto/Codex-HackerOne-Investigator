from __future__ import annotations

import json
import os
import socketserver
import stat
from pathlib import Path
from typing import Any

from .broker import BrokerError, DirectTLSTransport, RequestBroker, system_resolver
from .scope_guard import load_config


MAX_ENVELOPE = 2 * 1024 * 1024


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_ENVELOPE + 1)
        if len(raw) > MAX_ENVELOPE or not raw.endswith(b"\n"):
            self._reply({"ok": False, "error": "request envelope exceeds limit or is incomplete"})
            return
        try:
            envelope = json.loads(raw)
            if envelope == {"operation": "emergency-stop"}:
                self.server.broker.emergency_stop()  # type: ignore[attr-defined]
                result: dict[str, Any] = {"ok": True, "stopped": True}
            else:
                result = {"ok": True, "response": self.server.broker.execute(envelope)}  # type: ignore[attr-defined]
        except (BrokerError, ValueError, TypeError):
            # Deliberately generic at the IPC boundary: detailed bodies, URLs, and secrets are never echoed.
            result = {"ok": False, "error": "request denied by broker policy"}
        self._reply(result)

    def _reply(self, value: dict[str, Any]) -> None:
        self.wfile.write((json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8"))


class PrivateUnixServer(socketserver.UnixStreamServer):
    allow_reuse_address = False

    def __init__(self, socket_path: Path, broker: RequestBroker) -> None:
        if socket_path.exists():
            raise BrokerError("broker socket path already exists")
        super().__init__(str(socket_path), _Handler)
        os.chmod(socket_path, 0o600)
        self.broker = broker


def serve(config_path: Path, runtime_dir: Path, evidence_dir: Path) -> None:
    config = load_config(config_path)
    transport = DirectTLSTransport(max_response_bytes=int(config.get("broker", {}).get("max_response_bytes", 4194304)))
    broker = RequestBroker(config, runtime_dir=runtime_dir, evidence_dir=evidence_dir, resolver=system_resolver, transport=transport)
    socket_path = runtime_dir / "broker.sock"
    with PrivateUnixServer(socket_path, broker) as server:
        info = socket_path.stat()
        if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise BrokerError("broker socket permissions are unsafe")
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            socket_path.unlink(missing_ok=True)

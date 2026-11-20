from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from filesprep.broker import BrokerError, BrokerPolicy, RequestBroker, TransportResponse
from filesprep.rate_limit import SharedRateLimiter


ORIGINAL_CONNECT = socket.socket.connect
NOW = datetime(2026, 10, 18, 2, 0, 0, tzinfo=timezone.utc)
PUBLIC_IP = "93.184.216.34"
SECRET_DIRECTORY = None
SECRET_FILE = None


def setUpModule():
    global SECRET_DIRECTORY, SECRET_FILE
    def deny_network(*args, **kwargs):
        raise AssertionError("socket connections are forbidden in offline tests")
    socket.socket.connect = deny_network
    SECRET_DIRECTORY = tempfile.TemporaryDirectory()
    secret_root = Path(SECRET_DIRECTORY.name)
    secret_root.chmod(0o700)
    SECRET_FILE = secret_root / "files-api-key"
    SECRET_FILE.write_text("HOSTSIDESECRET\n")
    SECRET_FILE.chmod(0o600)


def tearDownModule():
    socket.socket.connect = ORIGINAL_CONNECT
    SECRET_DIRECTORY.cleanup()


def config() -> dict:
    return {
        "version": 1, "enabled": True,
        "policy_verification": {"verified_at": "2026-10-18T01:00:00Z", "expires_at": "2026-10-19T01:00:00Z", "policy_sha256": "a" * 64},
        "researcher_approval": {"approved": True, "approved_at": "2026-10-18T01:01:00Z", "approval_reference": "approval-1"},
        "rate_limit": {"requests_per_second": 1.5},
        "broker": {"execution_enabled": True, "max_request_bytes": 1024, "max_response_bytes": 4096},
        "targets": [{
            "host": "research-lab-17.files.com", "ownership": "researcher-owned-files-trial",
            "trial_reference": "trial-a", "verified_at": "2026-10-18T01:02:00Z", "approved": True,
            "path_prefixes": ["/"], "target_id": "trial-primary", "approved_methods": ["GET", "POST"],
            "approved_exact_urls": ["https://research-lab-17.files.com/api/rest/v1/users?redacted=1"],
            "approved_ip_addresses": [PUBLIC_IP], "approved_hypothesis_ids": ["hyp-1"],
            "credential": {"header_name": "X-FilesAPI-Key", "secret_file": str(SECRET_FILE)},
        }],
    }


def envelope(**changes) -> dict:
    value = {"request_id": "request-1", "method": "GET", "url": "https://research-lab-17.files.com/api/rest/v1/users?redacted=1", "headers": {}, "body_base64": None, "hypothesis_id": "hyp-1", "approval_reference": "approval-1"}
    value.update(changes)
    return value


class FakeLimiter:
    def __init__(self): self.calls = 0
    def acquire(self): self.calls += 1


class FakeTransport:
    def __init__(self, response=None): self.calls = []; self.response = response or TransportResponse(200, {"Content-Type": "text/plain"}, b"ok")
    def send(self, request, ip): self.calls.append((request, ip)); return self.response


class BrokerTests(unittest.TestCase):
    def policy(self, value=None):
        data = value or config(); return BrokerPolicy(data, now=lambda: NOW)

    def broker(self, temporary, *, resolver=lambda host: {PUBLIC_IP}, transport=None, value=None):
        root = Path(temporary); runtime = root / "runtime"; evidence = root / "evidence"
        runtime.mkdir(mode=0o700); evidence.mkdir(mode=0o700)
        return RequestBroker(value or config(), runtime_dir=runtime, evidence_dir=evidence, resolver=resolver, transport=transport or FakeTransport(), now=lambda: NOW, limiter=FakeLimiter())

    def test_disabled_and_empty_configuration_fails_closed(self):
        value = config(); value["broker"]["execution_enabled"] = False
        with self.assertRaises(BrokerError): self.policy(value)

    def test_active_broker_requires_exact_approved_urls(self):
        value = config(); value["targets"][0].pop("approved_exact_urls")
        with self.assertRaisesRegex(BrokerError, "exact approved URL"):
            self.policy(value)

    def test_scope_bypass_and_invalid_targets_are_denied(self):
        policy = self.policy()
        for url in ("https://evil.example/", "https://research-lab-17.files.com.evil.example/", "https://research-lab-17.files.com@evil.example/", "http://research-lab-17.files.com/", "https://research-lab-17.files.com:444/"):
            with self.subTest(url=url), self.assertRaises(BrokerError): policy.prepare(envelope(url=url))

    def test_method_hypothesis_and_approval_are_explicit(self):
        policy = self.policy()
        for change in ({"method": "TRACE"}, {"method": "DELETE"}, {"hypothesis_id": "hyp-2"}, {"approval_reference": "old"}):
            with self.subTest(change=change), self.assertRaises(BrokerError): policy.prepare(envelope(**change))

    def test_routing_and_header_injection_are_denied(self):
        policy = self.policy()
        for headers in (
            {"Host": "evil.example"},
            {"Connection": "keep-alive"},
            {"X-Test": "ok\r\nHost: evil"},
            {"X-FilesAPI-Key": "client-secret"},
            {"Authorization": "Bearer client-secret"},
            {"Cookie": "sid=client-secret"},
        ):
            with self.subTest(headers=headers), self.assertRaises(BrokerError): policy.prepare(envelope(headers=headers))

    def test_host_side_files_key_is_injected_after_client_header_validation(self):
        prepared = self.policy().prepare(envelope(headers={"Accept": "application/json"}))
        self.assertEqual(prepared.headers["X-FilesAPI-Key"], "HOSTSIDESECRET")
        self.assertEqual(prepared.headers["Accept"], "application/json")

    def test_unsafe_secret_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            secret = root / "key"
            secret.write_text("SECRET\n")
            value = config()
            value["targets"][0]["credential"]["secret_file"] = str(secret)
            secret.chmod(0o644)
            with self.assertRaisesRegex(BrokerError, "0600"):
                self.policy(value).prepare(envelope())
            secret.chmod(0o600)
            link = root / "linked-key"
            link.symlink_to(secret)
            value["targets"][0]["credential"]["secret_file"] = str(link)
            with self.assertRaisesRegex(BrokerError, "non-symlink"):
                self.policy(value).prepare(envelope())

    def test_unapproved_or_private_dns_change_engages_stop(self):
        for address in ("93.184.216.35", "127.0.0.1", "10.0.0.5"):
            with self.subTest(address=address), tempfile.TemporaryDirectory() as temporary:
                broker = self.broker(temporary, resolver=lambda host, a=address: {a})
                with self.assertRaises(BrokerError): broker.execute(envelope())
                self.assertTrue(broker.stop_path.exists())
                self.assertEqual(stat.S_IMODE(broker.stop_path.stat().st_mode), 0o600)

    def test_empty_and_mixed_dns_results_fail_closed(self):
        for result in (set(), {PUBLIC_IP, "93.184.216.35"}):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as temporary:
                transport = FakeTransport(); broker = self.broker(temporary, resolver=lambda host, r=result: r, transport=transport)
                with self.assertRaises(BrokerError): broker.execute(envelope())
                self.assertEqual(transport.calls, [])

    def test_approved_ip_is_used_for_connection_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport(); broker = self.broker(temporary, transport=transport)
            result = broker.execute(envelope())
            self.assertEqual(result["status"], 200); self.assertEqual(transport.calls[0][1], PUBLIC_IP)

    def test_redirect_is_never_followed_or_returned_as_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport(TransportResponse(302, {"Location": "https://evil.example/"}, b"")); broker = self.broker(temporary, transport=transport)
            with self.assertRaisesRegex(BrokerError, "never follows"): broker.execute(envelope())
            self.assertEqual(len(transport.calls), 1)

    def test_availability_response_engages_stop(self):
        for status in (429, 500, 503):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                broker = self.broker(temporary, transport=FakeTransport(TransportResponse(status, {}, b"")))
                with self.assertRaisesRegex(BrokerError, "availability"): broker.execute(envelope())
                self.assertTrue(broker.stop_path.exists())

    def test_manual_and_midflight_emergency_stop_prevent_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport(); broker = self.broker(temporary, transport=transport); broker.emergency_stop("manual")
            with self.assertRaises(BrokerError): broker.execute(envelope())
            self.assertEqual(transport.calls, [])
        with tempfile.TemporaryDirectory() as temporary:
            transport = FakeTransport(); holder = {}
            def resolver(host): holder["broker"].emergency_stop("customer-data"); return {PUBLIC_IP}
            broker = self.broker(temporary, resolver=resolver, transport=transport); holder["broker"] = broker
            with self.assertRaises(BrokerError): broker.execute(envelope())
            self.assertEqual(transport.calls, [])

    def test_audit_redacts_credentials_url_query_and_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            redaction_url = "https://research-lab-17.files.com/?token=QUERYSECRET"
            policy = config(); policy["targets"][0]["approved_exact_urls"].append(redaction_url)
            broker = self.broker(temporary, value=policy)
            value = envelope(url=redaction_url, body_base64="Qk9EWVNFQ1JFVA==")
            broker.execute(value)
            raw = next((Path(temporary) / "evidence").iterdir()).read_text()
            for secret in ("HOSTSIDESECRET", "QUERYSECRET", "BODYSECRET", "X-FilesAPI-Key", "token="):
                self.assertNotIn(secret, raw)
            self.assertEqual(stat.S_IMODE(next((Path(temporary) / "evidence").iterdir()).stat().st_mode), 0o600)

    def test_proxy_environment_has_no_effect_on_broker_routing(self):
        old = os.environ.get("HTTPS_PROXY"); os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"
        try:
            with tempfile.TemporaryDirectory() as temporary:
                transport = FakeTransport(); broker = self.broker(temporary, transport=transport); broker.execute(envelope())
                self.assertEqual(transport.calls[0][1], PUBLIC_IP)
        finally:
            if old is None: os.environ.pop("HTTPS_PROXY", None)
            else: os.environ["HTTPS_PROXY"] = old

    def test_shared_rate_limit_serializes_concurrent_clients(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); directory.chmod(0o700); state = directory / "rate.json"
            grants = []
            def worker():
                limiter = SharedRateLimiter(state, requests_per_second=1.5, boot_id="offline-test")
                limiter.acquire(); grants.append(time.monotonic())
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            grants.sort(); self.assertGreaterEqual(grants[1] - grants[0], 0.64)


if __name__ == "__main__": unittest.main(verbosity=2)

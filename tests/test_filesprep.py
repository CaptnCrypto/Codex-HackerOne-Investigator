from __future__ import annotations

import json
import socket
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from filesprep.rate_limit import RateLimitError, SharedRateLimiter
from filesprep.scope_guard import ScopeGuard, ScopeGuardError, load_config


_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
NOW = datetime(2026, 10, 18, 2, 0, 0, tzinfo=timezone.utc)


def setUpModule():
    def deny_network(*args, **kwargs):
        raise AssertionError("network access is forbidden during Stage 3 offline tests")

    socket.socket.connect = deny_network


def tearDownModule():
    socket.socket.connect = _ORIGINAL_SOCKET_CONNECT


def valid_config() -> dict:
    return {
        "version": 1,
        "enabled": True,
        "source_snapshot_id": "synthetic-snapshot-001",
        "policy_verification": {
            "verified_at": "2026-10-18T01:45:00+00:00",
            "expires_at": "2026-10-19T01:45:00+00:00",
            "policy_sha256": "a" * 64,
            "verified_by": "researcher",
        },
        "researcher_approval": {
            "approved": True,
            "approved_at": "2026-10-18T01:50:00+00:00",
            "approval_reference": "local-approval-001",
        },
        "rate_limit": {
            "program_maximum_requests_per_second": 2.0,
            "requests_per_second": 1.5,
            "scope": "global",
        },
        "targets": [
            {
                "host": "research-lab-17.files.com",
                "ownership": "researcher-owned-files-trial",
                "trial_reference": "trial-a",
                "verified_at": "2026-10-18T01:55:00+00:00",
                "approved": True,
                "path_prefixes": ["/"],
            },
            {
                "host": "research-lab-17.hosted-by-files.com",
                "ownership": "researcher-owned-public-hosting",
                "trial_reference": "trial-a",
                "verified_at": "2026-10-18T01:55:00+00:00",
                "approved": True,
                "path_prefixes": ["/public"],
            },
        ],
    }


def guard(config: dict | None = None) -> ScopeGuard:
    return ScopeGuard(config or valid_config(), now=lambda: NOW)


class ScopeGuardTests(unittest.TestCase):
    def test_exact_trial_host_is_authorized(self):
        target = guard().authorize_url("https://research-lab-17.files.com/api/rest/v1/users")
        self.assertEqual(target.trial_reference, "trial-a")

    def test_exact_public_hosting_path_is_authorized(self):
        target = guard().authorize_url(
            "https://research-lab-17.hosted-by-files.com/public/sample.txt"
        )
        self.assertEqual(target.ownership, "researcher-owned-public-hosting")

    def test_missing_next_path_boundary_is_denied(self):
        with self.assertRaises(ScopeGuardError):
            guard().authorize_url("https://research-lab-17.hosted-by-files.com/publicity")

    def test_encoded_separator_and_traversal_paths_are_denied(self):
        values = (
            "https://research-lab-17.hosted-by-files.com/public%2fprivate",
            "https://research-lab-17.hosted-by-files.com/public/../private",
            "https://research-lab-17.hosted-by-files.com/public/%2e%2e/private",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ScopeGuardError):
                guard().authorize_url(value)

    def test_encoded_separator_is_allowed_only_for_a_complete_exact_url(self):
        approved = (
            "https://research-lab-17.files.com/api/rest/v1/files/"
            "lab-control-shared%2Fcontrol-readable.txt"
            "?action=stat&path=lab-control-shared%2Fcontrol-readable.txt"
        )
        config = valid_config()
        config["targets"][0]["path_prefixes"] = [
            "/api/rest/v1/files/lab-control-shared/control-readable.txt"
        ]
        config["targets"][0]["approved_exact_urls"] = [approved]
        target = guard(config).authorize_url(approved)
        self.assertEqual(target.host, "research-lab-17.files.com")

        denied = (
            approved.replace("action=stat&", ""),
            approved + "&extra=1",
            approved.replace("%2F", "%2f"),
            approved.replace("control-readable.txt", "other.txt"),
            approved.replace("action=stat&path", "path=lab-control-shared%2Fcontrol-readable.txt&action"),
            "https://research-lab-17.files.com/api/rest/v1/files/lab-control-shared/control-readable.txt?action=stat&path=lab-control-shared/control-readable.txt",
        )
        for value in denied:
            with self.subTest(value=value), self.assertRaises(ScopeGuardError):
                guard(config).authorize_url(value)

    def test_invalid_exact_url_configuration_is_denied(self):
        values = (
            "http://research-lab-17.files.com/file%2Fname?action=stat",
            "https://evil.example/file%2Fname?action=stat",
            "https://research-lab-17.files.com/file%2Fname#fragment",
            "https://research-lab-17.files.com/file%2Fname",
            "https://research-lab-17.files.com/other%2Fname?action=stat",
        )
        for value in values:
            config = valid_config()
            config["targets"][0]["path_prefixes"] = ["/file/name"]
            config["targets"][0]["approved_exact_urls"] = [value]
            with self.subTest(value=value), self.assertRaises(ScopeGuardError):
                guard(config)

    def test_customer_and_suffix_trick_hosts_are_denied(self):
        values = (
            "https://some-customer.files.com/",
            "https://research-lab-17.files.com.example.test/",
            "https://research-lab-17.files.com@evil.example/",
            "https://evil.example/?next=https://research-lab-17.files.com/",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ScopeGuardError):
                guard().authorize_url(value)

    def test_shared_and_explicitly_excluded_hosts_cannot_be_targets(self):
        for host in ("app.files.com", "www.files.com", "developers.files.com", "status.files.com", "mail.files.com"):
            config = valid_config()
            config["targets"][0]["host"] = host
            with self.subTest(host=host), self.assertRaises(ScopeGuardError):
                guard(config)

    def test_wildcard_target_is_denied(self):
        config = valid_config()
        config["targets"][0]["host"] = "*.files.com"
        with self.assertRaises(ScopeGuardError):
            guard(config)

    def test_unsafe_url_authority_is_denied(self):
        values = (
            "http://research-lab-17.files.com/",
            "https://user:pass@research-lab-17.files.com/",
            "https://research-lab-17.files.com:444/",
            "https://research-lab-17.files.com/#fragment",
            "https://research-lab-17.files.com./",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ScopeGuardError):
                guard().authorize_url(value)

    def test_disabled_or_unapproved_configuration_is_denied(self):
        config = valid_config()
        config["enabled"] = False
        with self.assertRaises(ScopeGuardError):
            guard(config)
        config = valid_config()
        config["researcher_approval"]["approved"] = False
        with self.assertRaises(ScopeGuardError):
            guard(config)

    def test_expired_policy_verification_is_denied(self):
        config = valid_config()
        config["policy_verification"]["expires_at"] = "2026-10-18T01:59:59+00:00"
        with self.assertRaises(ScopeGuardError):
            guard(config)

    def test_future_target_verification_is_denied(self):
        config = valid_config()
        config["targets"][0]["verified_at"] = "2026-10-18T02:00:01+00:00"
        with self.assertRaises(ScopeGuardError):
            guard(config)

    def test_rate_above_safety_cap_is_denied_by_scope_config(self):
        config = valid_config()
        config["rate_limit"]["requests_per_second"] = 1.51
        with self.assertRaises(ScopeGuardError):
            guard(config)

    def test_config_file_permissions_and_symlinks_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "allowlist.json"
            path.write_text(json.dumps(valid_config()), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(load_config(path)["version"], 1)
            path.chmod(0o644)
            with self.assertRaises(ScopeGuardError):
                load_config(path)
            path.chmod(0o600)
            link = directory / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ScopeGuardError):
                load_config(link)

    def test_loose_config_directory_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "allowlist.json"
            path.write_text(json.dumps(valid_config()), encoding="utf-8")
            path.chmod(0o600)
            directory.chmod(0o755)
            with self.assertRaises(ScopeGuardError):
                load_config(path)

    def test_missing_config_fails_closed_without_raw_os_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ScopeGuardError):
                load_config(Path(temporary) / "missing" / "allowlist.json")


class RateLimiterTests(unittest.TestCase):
    def test_shared_limiter_enforces_conservative_interval(self):
        now = [100.0]
        sleeps = []

        def sleep(delay):
            sleeps.append(delay)
            now[0] += delay

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            state = directory / "rate-state.json"
            limiter = SharedRateLimiter(
                state,
                requests_per_second=1.5,
                clock=lambda: now[0],
                sleeper=sleep,
                boot_id="test-boot",
            )
            limiter.acquire()
            limiter.acquire()
            self.assertAlmostEqual(sleeps[0], 2.0 / 3.0)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)

    def test_rate_above_safety_cap_is_rejected(self):
        with self.assertRaises(RateLimitError):
            SharedRateLimiter(Path("unused"), requests_per_second=2.0, boot_id="test")
        with self.assertRaises(RateLimitError):
            SharedRateLimiter(Path("unused"), requests_per_second=True, boot_id="test")

    def test_malformed_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            state = directory / "rate-state.json"
            state.write_text("not-json", encoding="ascii")
            state.chmod(0o600)
            limiter = SharedRateLimiter(state, clock=lambda: 100.0, boot_id="test")
            with self.assertRaises(RateLimitError):
                limiter.acquire()

    def test_loose_state_directory_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            limiter = SharedRateLimiter(
                directory / "rate-state.json", clock=lambda: 100.0, boot_id="test"
            )
            with self.assertRaises(RateLimitError):
                limiter.acquire()

    def test_missing_state_directory_fails_closed_without_raw_os_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            limiter = SharedRateLimiter(
                Path(temporary) / "missing" / "rate-state.json",
                clock=lambda: 100.0,
                boot_id="test",
            )
            with self.assertRaises(RateLimitError):
                limiter.acquire()

    def test_new_boot_identifier_resets_stale_monotonic_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            state = directory / "rate-state.json"
            state.write_text(
                json.dumps({"boot_id": "old-boot", "last_grant_monotonic": 999999.0}),
                encoding="ascii",
            )
            state.chmod(0o600)
            limiter = SharedRateLimiter(state, clock=lambda: 5.0, boot_id="new-boot")
            self.assertEqual(limiter.acquire(), 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

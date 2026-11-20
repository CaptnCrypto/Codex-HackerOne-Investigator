from __future__ import annotations

import json
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from h1ro.client import (
    APIError,
    HTTPSJSONTransport,
    HackerOneClient,
    PaginationError,
    RateLimiter,
    Response,
)
from h1ro.normalize import normalize_program
from h1ro.ranking import rank_programs, score_program
from h1ro.security import CredentialSecurityError, read_credentials
from h1ro.workflow import synchronize


FAKE_USERNAME = "fake-user-identifier"
FAKE_TOKEN = "fake-token-value-never-send"
_ORIGINAL_SOCKET_CONNECT = socket.socket.connect


def setUpModule():
    def deny_network(*args, **kwargs):
        raise AssertionError("network access is forbidden during mocked tests")

    socket.socket.connect = deny_network


def tearDownModule():
    socket.socket.connect = _ORIGINAL_SOCKET_CONNECT


def program(handle: str, *, amount: int = 5000, open_state: bool = True) -> dict:
    return {
        "id": handle,
        "type": "program",
        "attributes": {
            "handle": handle,
            "name": handle.title(),
            "currency": "usd",
            "policy": f"Testing policy with safe instructions. Critical awards up to ${amount}.",
            "submission_state": "open" if open_state else "paused",
            "state": "public_mode",
            "triage_active": True,
            "offers_bounties": True,
            "open_scope": False,
            "fast_payments": True,
            "gold_standard_safe_harbor": True,
        },
    }


def scope(identifier: str = "1") -> dict:
    asset_identifier = (
        identifier if identifier.startswith("https://") else "https://api.example.test"
    )
    return {
        "id": identifier,
        "type": "structured-scope",
        "attributes": {
            "asset_type": "URL",
            "asset_identifier": asset_identifier,
            "eligible_for_submission": True,
            "eligible_for_bounty": True,
            "max_severity": "critical",
            "instruction": "Use only the test tenant.",
            "updated_at": "2026-10-01T00:00:00Z",
        },
    }


class FakeTransport:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, path, query):
        self.calls.append((path, dict(query)))
        return self.handler(path, query, len(self.calls))


class NoWaitLimiter:
    def wait(self, bucket):
        return None


class SecurityTests(unittest.TestCase):
    def test_secure_credentials_are_read_without_modification(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "hackerone"
            directory.mkdir(mode=0o700)
            for name, value in (("username", FAKE_USERNAME), ("token", FAKE_TOKEN)):
                path = directory / name
                path.write_text(value + "\n", encoding="utf-8")
                path.chmod(0o600)
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            self.assertEqual(read_credentials(directory), (FAKE_USERNAME, FAKE_TOKEN))
            after = {p.name: p.read_bytes() for p in directory.iterdir()}
            self.assertEqual(before, after)

    def test_loose_permissions_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "hackerone"
            directory.mkdir(mode=0o700)
            username = directory / "username"
            token_real = directory / "token-real"
            username.write_text(FAKE_USERNAME, encoding="utf-8")
            token_real.write_text(FAKE_TOKEN, encoding="utf-8")
            username.chmod(0o644)
            token_real.chmod(0o600)
            (directory / "token").symlink_to(token_real)
            with self.assertRaises(CredentialSecurityError):
                read_credentials(directory)
            username.chmod(0o600)
            with self.assertRaises(CredentialSecurityError):
                read_credentials(directory)

    def test_symlinked_credential_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary) / "real"
            link = Path(temporary) / "link"
            real.mkdir(mode=0o700)
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(CredentialSecurityError):
                read_credentials(link)


class ClientTests(unittest.TestCase):
    @staticmethod
    def next_link(path: str, page: int) -> str:
        return (
            f"https://api.hackerone.com{path}?"
            f"page%5Bnumber%5D={page}&page%5Bsize%5D=100"
        )

    def test_documented_endpoint_and_pagination(self):
        def handler(path, query, call):
            self.assertEqual(path, "/v1/hackers/programs")
            page = int(query["page[number]"])
            data = [program(f"p{number}") for number in range(100)] if page == 1 else [program("last")]
            links = {"next": self.next_link(path, 2)} if page == 1 else {}
            return Response(200, {}, json.dumps({"data": data, "links": links}).encode())

        transport = FakeTransport(handler)
        client = HackerOneClient(transport, limiter=NoWaitLimiter())
        self.assertEqual(len(client.programs()), 101)
        self.assertEqual(len(transport.calls), 2)

    def test_pagination_follows_next_even_when_page_is_short(self):
        def handler(path, query, call):
            page = int(query["page[number]"])
            payload = {
                "data": [program(f"page-{page}")],
                "links": {"next": self.next_link(path, 2)} if page == 1 else {},
            }
            return Response(200, {}, json.dumps(payload).encode())

        transport = FakeTransport(handler)
        client = HackerOneClient(transport, limiter=NoWaitLimiter())
        self.assertEqual(len(client.programs()), 2)
        self.assertEqual(len(transport.calls), 2)

    def test_invalid_handle_is_rejected_before_transport(self):
        transport = FakeTransport(lambda *_: self.fail("transport must not run"))
        client = HackerOneClient(transport, limiter=NoWaitLimiter())
        with self.assertRaises(APIError):
            client.program("../../reports")

    def test_all_documented_endpoint_response_shapes(self):
        payload_program = program("alpha")
        payload_scope = scope()

        def handler(path, query, call):
            if path == "/v1/hackers/programs/alpha":
                payload = {"data": payload_program}
            elif path.endswith("/structured_scopes"):
                payload = {"data": [payload_scope], "links": {}}
            elif path.endswith("/scope_exclusions"):
                payload = {"data": [], "links": {}}
            else:
                self.fail(f"unexpected endpoint type in mocked test: {path}")
            return Response(200, {}, json.dumps(payload).encode())

        client = HackerOneClient(FakeTransport(handler), limiter=NoWaitLimiter())
        self.assertEqual(client.program("alpha"), payload_program)
        self.assertEqual(client.structured_scopes("alpha"), [payload_scope])
        self.assertEqual(client.scope_exclusions("alpha"), [])

    def test_shape_diagnostics_do_not_echo_response_body(self):
        private_marker = "PRIVATE-RESPONSE-CONTENT-MUST-NOT-APPEAR"
        cases = (
            (b"[]", "top-level type is array; expected object"),
            (
                json.dumps({"errors": [{"detail": private_marker}]}).encode(),
                "required data member is missing; errors_member=present",
            ),
            (b'{"data": {}}', "data type is object; expected array"),
            (
                json.dumps({"data": [private_marker], "links": {}}).encode(),
                "data item 0 type is string; expected object",
            ),
            (b'{"data": [], "links": []}', "links type is array; expected object"),
            (b'{"data": []}', "links type is null; expected object"),
            (b'{"data": [', "invalid JSON; response_bytes=10"),
        )
        for body, reason in cases:
            with self.subTest(reason=reason):
                response = Response(200, {}, body)
                client = HackerOneClient(
                    FakeTransport(lambda *_: response), limiter=NoWaitLimiter()
                )
                with self.assertRaises(APIError) as raised:
                    client.programs()
                message = str(raised.exception)
                self.assertIn("operation=paginate", message)
                self.assertIn("endpoint_type=program-list", message)
                self.assertIn("page=1", message)
                self.assertIn("http_status=200", message)
                self.assertIn(f"validation={reason}", message)
                self.assertNotIn(private_marker, message)

    def test_endpoint_specific_shape_diagnostics(self):
        cases = (
            (
                lambda client: client.program("alpha"),
                "program-detail",
                b'{"errors": []}',
                "fetch-one",
            ),
            (
                lambda client: client.structured_scopes("alpha"),
                "structured-scopes",
                b'{"data": {}}',
                "paginate",
            ),
            (
                lambda client: client.scope_exclusions("alpha"),
                "scope-exclusions",
                b'{"data": {}}',
                "fetch-list",
            ),
        )
        for invoke, endpoint_type, body, operation in cases:
            with self.subTest(endpoint_type=endpoint_type):
                client = HackerOneClient(
                    FakeTransport(lambda *_: Response(200, {}, body)),
                    limiter=NoWaitLimiter(),
                )
                with self.assertRaises(APIError) as raised:
                    invoke(client)
                message = str(raised.exception)
                self.assertIn(f"operation={operation}", message)
                self.assertIn(f"endpoint_type={endpoint_type}", message)
                self.assertIn("http_status=200", message)

    def test_api_error_diagnostics_include_status_but_not_body(self):
        private_marker = "PRIVATE-ERROR-BODY-MUST-NOT-APPEAR"
        for status, reason in (
            (401, "authentication or authorization rejected"),
            (403, "authentication or authorization rejected"),
            (404, "resource not found"),
            (503, "HackerOne service error"),
        ):
            with self.subTest(status=status):
                response = Response(
                    status,
                    {},
                    json.dumps({"errors": [{"detail": private_marker}]}).encode(),
                )
                client = HackerOneClient(
                    FakeTransport(lambda *_: response), limiter=NoWaitLimiter()
                )
                with self.assertRaises(APIError) as raised:
                    client.programs()
                message = str(raised.exception)
                self.assertIn("operation=paginate", message)
                self.assertIn("endpoint_type=program-list", message)
                self.assertIn(f"http_status={status}", message)
                self.assertIn(f"validation={reason}", message)
                self.assertNotIn(private_marker, message)

    def test_structured_scope_400_is_not_treated_as_completion(self):
        private_marker = "PRIVATE-SCOPE-ERROR-MUST-NOT-APPEAR"
        response = Response(
            400,
            {},
            json.dumps({"errors": [{"detail": private_marker}]}).encode(),
        )
        client = HackerOneClient(
            FakeTransport(lambda *_: response), limiter=NoWaitLimiter()
        )
        with self.assertRaises(APIError) as raised:
            client.structured_scopes("alpha")
        message = str(raised.exception)
        self.assertIn("operation=paginate", message)
        self.assertIn("endpoint_type=structured-scopes", message)
        self.assertIn("page=1", message)
        self.assertIn("http_status=400", message)
        self.assertIn("validation=unexpected API response", message)
        self.assertNotIn(private_marker, message)

    def test_structured_scope_cursor_pagination_and_termination(self):
        path = "/v1/hackers/programs/alpha/structured_scopes"

        def handler(actual_path, query, call):
            self.assertEqual(actual_path, path)
            if call == 1:
                self.assertEqual(query, {"page[size]": "100"})
                payload = {
                    "data": [scope("100"), scope("101")],
                    "links": {"next": self.next_link(path, 2)},
                }
            else:
                self.assertEqual(
                    query,
                    {"page[size]": "100", "filter[id__gt]": "101"},
                )
                payload = {"data": [scope("205")], "links": {}}
            return Response(200, {}, json.dumps(payload).encode())

        transport = FakeTransport(handler)
        client = HackerOneClient(transport, limiter=NoWaitLimiter())
        self.assertEqual(
            [item["id"] for item in client.structured_scopes("alpha")],
            ["100", "101", "205"],
        )
        self.assertEqual(len(transport.calls), 2)

    def test_structured_scope_no_next_terminates_after_one_batch(self):
        response = Response(
            200,
            {},
            json.dumps({"data": [scope("7")], "links": {}}).encode(),
        )
        transport = FakeTransport(lambda *_: response)
        client = HackerOneClient(transport, limiter=NoWaitLimiter())
        self.assertEqual(client.structured_scopes("alpha"), [scope("7")])
        self.assertEqual(len(transport.calls), 1)

    def test_invalid_next_links_are_rejected_without_following(self):
        path = "/v1/hackers/programs"
        invalid_links = (
            "https://example.test/v1/hackers/programs?page%5Bnumber%5D=2&page%5Bsize%5D=100",
            "https://api.hackerone.com/v1/hackers/reports?page%5Bnumber%5D=2&page%5Bsize%5D=100",
            self.next_link(path, 1),
        )
        for next_link in invalid_links:
            with self.subTest(next_link=next_link):
                response = Response(
                    200,
                    {},
                    json.dumps({"data": [program("alpha")], "links": {"next": next_link}}).encode(),
                )
                transport = FakeTransport(lambda *_: response)
                client = HackerOneClient(transport, limiter=NoWaitLimiter())
                with self.assertRaises(PaginationError) as raised:
                    client.programs()
                self.assertIn("next link is invalid", str(raised.exception))
                self.assertEqual(len(transport.calls), 1)

    def test_structured_scope_invalid_next_link_is_rejected(self):
        response = Response(
            200,
            {},
            json.dumps(
                {
                    "data": [scope("1")],
                    "links": {
                        "next": (
                            "https://example.test/v1/hackers/programs/alpha/"
                            "structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=100"
                        )
                    },
                }
            ).encode(),
        )
        transport = FakeTransport(lambda *_: response)
        client = HackerOneClient(transport, limiter=NoWaitLimiter())
        with self.assertRaises(PaginationError):
            client.structured_scopes("alpha")
        self.assertEqual(len(transport.calls), 1)

    def test_production_transport_rejects_non_allowlisted_paths_and_queries(self):
        transport = HTTPSJSONTransport(FAKE_USERNAME, FAKE_TOKEN)
        with self.assertRaises(APIError):
            transport.get("/v1/hackers/reports", {})
        with self.assertRaises(APIError):
            transport.get("/v1/hackers/programs", {"filter[secret]": "x"})
        with self.assertRaises(APIError):
            transport.get(
                "/v1/hackers/programs",
                {"page[number]": "101", "page[size]": "100"},
            )
        with self.assertRaises(APIError):
            transport.get(
                "/v1/hackers/programs/alpha/structured_scopes",
                {
                    "page[number]": "2",
                    "page[size]": "100",
                    "filter[id__gt]": "99",
                },
            )
        with self.assertRaises(APIError):
            transport.get(
                "/v1/hackers/programs/alpha/structured_scopes",
                {"page[size]": "100", "filter[id__gt]": "-1"},
            )

    def test_production_transport_accepts_documented_scope_cursor(self):
        captured = []

        class FakeHTTPResponse:
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self, _limit):
                return b'{"data":[],"links":{}}'

        class FakeOpener:
            def open(self, request, timeout):
                captured.append((request.full_url, timeout))
                return FakeHTTPResponse()

        transport = HTTPSJSONTransport(FAKE_USERNAME, FAKE_TOKEN)
        transport._opener = FakeOpener()
        response = transport.get(
            "/v1/hackers/programs/alpha/structured_scopes",
            {"page[size]": "100", "filter[id__gt]": "9900"},
        )
        self.assertEqual(response.status, 200)
        self.assertIn("page%5Bsize%5D=100", captured[0][0])
        self.assertIn("filter%5Bid__gt%5D=9900", captured[0][0])

    def test_429_retry_after_then_success(self):
        sleeps = []

        def handler(path, query, call):
            if call == 1:
                return Response(429, {"Retry-After": "2"}, b'{"errors":[]}')
            return Response(200, {}, b'{"data": [], "links": {}}')

        client = HackerOneClient(
            FakeTransport(handler), limiter=NoWaitLimiter(), sleeper=sleeps.append
        )
        self.assertEqual(client.programs(), [])
        self.assertEqual(sleeps, [2.0])

    def test_pagination_safety_limit(self):
        def handler(path, query, call):
            page = int(query["page[number]"])
            response = {
                "data": [program(f"p{page}-{x}") for x in range(100)],
                "links": {"next": self.next_link(path, page + 1)},
            }
            return Response(200, {}, json.dumps(response).encode())

        client = HackerOneClient(FakeTransport(handler), limiter=NoWaitLimiter())
        with self.assertRaises(PaginationError):
            client.programs()

    def test_structured_scope_cursor_batch_limit_is_fail_closed(self):
        path = "/v1/hackers/programs/alpha/structured_scopes"

        def handler(actual_path, query, call):
            payload = {
                "data": [scope(str(call))],
                "links": {"next": self.next_link(path, 2)},
            }
            return Response(200, {}, json.dumps(payload).encode())

        client = HackerOneClient(FakeTransport(handler), limiter=NoWaitLimiter())
        with mock.patch("h1ro.client.MAX_CURSOR_BATCHES", 2):
            with self.assertRaises(PaginationError) as raised:
                client.structured_scopes("alpha")
        self.assertIn("2-batch safety limit", str(raised.exception))

    def test_rate_limiter_uses_stricter_scope_interval(self):
        times = iter([0.0, 0.5, 1.25])
        sleeps = []
        limiter = RateLimiter(clock=lambda: next(times), sleeper=sleeps.append)
        limiter.wait("structured_scopes")
        limiter.wait("structured_scopes")
        self.assertEqual(sleeps, [0.75])


class WorkflowTests(unittest.TestCase):
    def test_normalization_ranking_raw_preservation_and_permissions(self):
        payload_program = program("alpha", amount=12000)
        payload_scope = scope()

        def handler(path, query, call):
            if path == "/v1/hackers/programs":
                payload = {"data": [payload_program], "links": {}}
            elif path == "/v1/hackers/programs/alpha":
                self.fail("workflow must not make the redundant program-detail request")
            elif path.endswith("/structured_scopes"):
                payload = {"data": [payload_scope], "links": {}}
            elif path.endswith("/scope_exclusions"):
                payload = {"data": [], "links": {}}
            else:
                self.fail(f"unexpected path: {path}")
            return Response(200, {}, json.dumps(payload, separators=(",", ":")).encode())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "CASE-INFO.txt").write_text("CASE_ID=DEMO-CASE\n", encoding="utf-8")
            client = HackerOneClient(FakeTransport(handler), limiter=NoWaitLimiter())
            outputs = synchronize(client, root)
            report = outputs["report"].read_text(encoding="utf-8")
            self.assertIn("Alpha", report)
            self.assertIn("/100", report)
            for path in root.rglob("*"):
                mode = stat.S_IMODE(path.stat().st_mode)
                if path.is_dir() and path.name != Path(temporary).name:
                    self.assertEqual(mode, 0o700, path)
                elif path.is_file() and path.name != "CASE-INFO.txt":
                    self.assertEqual(mode, 0o600, path)
                    data = path.read_bytes()
                    self.assertNotIn(FAKE_USERNAME.encode(), data)
                    self.assertNotIn(FAKE_TOKEN.encode(), data)
            raw = next((outputs["raw"] / "programs").glob("page-*.json"))
            self.assertEqual(
                json.loads(raw.read_text(encoding="utf-8")),
                {"data": [payload_program], "links": {}},
            )
            scope_raw = next(
                (outputs["raw"] / "alpha" / "structured-scopes").glob("batch-*.json")
            )
            self.assertEqual(
                json.loads(scope_raw.read_text(encoding="utf-8")),
                {"data": [payload_scope], "links": {}},
            )
            requested_paths = [path for path, _query in client.transport.calls]
            self.assertNotIn("/v1/hackers/programs/alpha", requested_paths)

    def test_ranking_returns_only_top_ten_eligible(self):
        normalized = []
        for number in range(12):
            normalized.append(
                normalize_program(
                    program(f"program-{number}", amount=1000 + number * 1000),
                    [scope(f"https://p{number}.example.test")],
                    [],
                    retrieved_at="2026-10-17T00:00:00+00:00",
                )
            )
        normalized.append(
            normalize_program(
                program("closed", open_state=False),
                [scope()],
                [],
                retrieved_at="2026-10-17T00:00:00+00:00",
            )
        )
        ranking = rank_programs(normalized)
        self.assertEqual(len(ranking), 10)
        self.assertTrue(all(item["eligible"] for item in ranking))
        self.assertFalse(score_program(normalized[-1])["eligible"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


API_ORIGIN = "https://api.hackerone.com"
API_PREFIX = "/v1/hackers"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
ALLOWED_PATH_RE = re.compile(
    r"^/v1/hackers/programs(?:/[A-Za-z0-9_-]{1,128}"
    r"(?:/(?:structured_scopes|scope_exclusions))?)?$"
)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 100
MAX_CURSOR_BATCHES = 1000
MAX_RETRIES = 4


class APIError(RuntimeError):
    pass


class PaginationError(APIError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise APIError(f"unexpected HTTP redirect ({code}); request stopped")


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class RateLimiter:
    """Sequential fixed-interval limiter with independent endpoint buckets."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.clock = clock
        self.sleeper = sleeper
        self.last_request: dict[str, float] = {}

    def wait(self, bucket: str) -> None:
        # Stay below documented limits: general reads 600/min; scopes 50/min.
        interval = 1.25 if bucket == "structured_scopes" else 0.11
        now = self.clock()
        previous = self.last_request.get(bucket)
        if previous is not None:
            remaining = interval - (now - previous)
            if remaining > 0:
                self.sleeper(remaining)
                now = self.clock()
        self.last_request[bucket] = now


class HTTPSJSONTransport:
    """Production transport fixed to HackerOne HTTPS with TLS verification."""

    def __init__(self, username: str, token: str, *, timeout: float = 20.0) -> None:
        if not (5.0 <= timeout <= 60.0):
            raise ValueError("timeout must be between 5 and 60 seconds")
        auth = base64.b64encode(f"{username}:{token}".encode("utf-8")).decode("ascii")
        self._authorization = f"Basic {auth}"
        self.timeout = timeout
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def get(self, path: str, query: dict[str, str]) -> Response:
        if not ALLOWED_PATH_RE.fullmatch(path):
            raise APIError("request path is outside the Hacker API allowlist")
        program_list = path == f"{API_PREFIX}/programs"
        structured_scopes = path.endswith("/structured_scopes")
        if program_list:
            allowed_query = {"page[number]", "page[size]"}
        elif structured_scopes:
            allowed_query = {"page[number]", "page[size]", "filter[id__gt]"}
        else:
            allowed_query = set()
        if set(query) - allowed_query:
            raise APIError("request query contains a parameter outside the allowlist")
        if program_list:
            try:
                page = int(query["page[number]"])
                size = int(query["page[size]"])
            except (KeyError, TypeError, ValueError) as exc:
                raise APIError("pagination parameters are invalid") from exc
            if not (1 <= page <= MAX_PAGES and 1 <= size <= PAGE_SIZE):
                raise APIError("pagination parameters exceed safety limits")
        elif structured_scopes:
            try:
                size = int(query["page[size]"])
            except (KeyError, TypeError, ValueError) as exc:
                raise APIError("pagination parameters are invalid") from exc
            has_page = "page[number]" in query
            has_cursor = "filter[id__gt]" in query
            if has_page and has_cursor:
                raise APIError("page number and ID cursor cannot be combined")
            try:
                page = int(query["page[number]"]) if has_page else None
                cursor = int(query["filter[id__gt]"]) if has_cursor else None
            except (TypeError, ValueError) as exc:
                raise APIError("pagination parameters are invalid") from exc
            if not (1 <= size <= PAGE_SIZE):
                raise APIError("pagination parameters exceed safety limits")
            if page is not None and not (1 <= page <= MAX_PAGES):
                raise APIError("pagination parameters exceed safety limits")
            if cursor is not None and cursor < 0:
                raise APIError("pagination parameters exceed safety limits")
        url = API_ORIGIN + path + "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Authorization": self._authorization,
                "User-Agent": "codex-investigator-h1-ro/1.0.2",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise APIError("API response exceeds the 16 MiB safety limit")
                return Response(response.status, dict(response.headers.items()), body)
        except urllib.error.HTTPError as exc:
            body = exc.read(64 * 1024)
            return Response(exc.code, dict(exc.headers.items()), body)
        except APIError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise APIError(f"network request failed: {type(exc).__name__}") from exc


class HackerOneClient:
    def __init__(
        self,
        transport: Any,
        *,
        limiter: RateLimiter | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        recorder: Callable[[str, dict[str, str], bytes], None] | None = None,
    ) -> None:
        self.transport = transport
        self.limiter = limiter or RateLimiter(sleeper=sleeper)
        self.sleeper = sleeper
        self.recorder = recorder

    @staticmethod
    def _validate_handle(handle: str) -> None:
        if not HANDLE_RE.fullmatch(handle):
            raise APIError(
                "operation=validate endpoint_type=program-handle "
                "http_status=not-applicable validation=invalid handle syntax"
            )

    @staticmethod
    def _diagnostic(
        *,
        operation: str,
        endpoint_type: str,
        status: int | str,
        reason: str,
        page: int | None = None,
    ) -> str:
        page_text = f" page={page}" if page is not None else ""
        return (
            f"operation={operation} endpoint_type={endpoint_type}{page_text} "
            f"http_status={status} validation={reason}"
        )

    @staticmethod
    def _json_type(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        if isinstance(value, str):
            return "string"
        if isinstance(value, (int, float)):
            return "number"
        return type(value).__name__

    def _request(
        self,
        path: str,
        query: dict[str, str],
        *,
        operation: str,
        endpoint_type: str,
        expected_data_type: type,
        bucket: str = "general",
        page: int | None = None,
    ) -> dict[str, Any]:
        last_status = 0
        for attempt in range(MAX_RETRIES + 1):
            self.limiter.wait(bucket)
            try:
                response = self.transport.get(path, query)
            except APIError as exc:
                raise APIError(
                    self._diagnostic(
                        operation=operation,
                        endpoint_type=endpoint_type,
                        page=page,
                        status="unavailable",
                        reason=str(exc),
                    )
                ) from exc
            last_status = response.status
            if response.status == 429 and attempt < MAX_RETRIES:
                raw_wait = response.headers.get("Retry-After", "")
                try:
                    wait = min(60.0, max(1.0, float(raw_wait)))
                except ValueError:
                    wait = min(60.0, 2.0**attempt)
                self.sleeper(wait)
                continue
            if response.status != 200:
                if response.status in {401, 403}:
                    detail = "authentication or authorization rejected"
                elif response.status == 404:
                    detail = "resource not found"
                elif response.status == 429:
                    detail = "rate limit remained active after retries"
                elif 500 <= response.status <= 599:
                    detail = "HackerOne service error"
                else:
                    detail = "unexpected API response"
                raise APIError(
                    self._diagnostic(
                        operation=operation,
                        endpoint_type=endpoint_type,
                        page=page,
                        status=response.status,
                        reason=detail,
                    )
                )
            try:
                parsed = json.loads(response.body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise APIError(
                    self._diagnostic(
                        operation=operation,
                        endpoint_type=endpoint_type,
                        page=page,
                        status=response.status,
                        reason=f"invalid JSON; response_bytes={len(response.body)}",
                    )
                ) from exc
            if not isinstance(parsed, dict):
                raise APIError(
                    self._diagnostic(
                        operation=operation,
                        endpoint_type=endpoint_type,
                        page=page,
                        status=response.status,
                        reason=f"top-level type is {self._json_type(parsed)}; expected object",
                    )
                )
            if "data" not in parsed:
                errors_state = "present" if "errors" in parsed else "absent"
                raise APIError(
                    self._diagnostic(
                        operation=operation,
                        endpoint_type=endpoint_type,
                        page=page,
                        status=response.status,
                        reason=f"required data member is missing; errors_member={errors_state}",
                    )
                )
            data = parsed["data"]
            if not isinstance(data, expected_data_type):
                raise APIError(
                    self._diagnostic(
                        operation=operation,
                        endpoint_type=endpoint_type,
                        page=page,
                        status=response.status,
                        reason=(
                            f"data type is {self._json_type(data)}; expected "
                            f"{'object' if expected_data_type is dict else 'array'}"
                        ),
                    )
                )
            if self.recorder is not None:
                self.recorder(path, query, response.body)
            return parsed
        raise APIError(
            self._diagnostic(
                operation=operation,
                endpoint_type=endpoint_type,
                page=page,
                status=last_status,
                reason="request failed after bounded retries",
            )
        )

    def _paginated(
        self,
        path: str,
        *,
        endpoint_type: str,
        bucket: str = "general",
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            payload = self._request(
                path,
                {"page[number]": str(page), "page[size]": str(PAGE_SIZE)},
                operation="paginate",
                endpoint_type=endpoint_type,
                expected_data_type=list,
                bucket=bucket,
                page=page,
            )
            data = payload["data"]
            for index, item in enumerate(data):
                if not isinstance(item, dict):
                    raise APIError(
                        self._diagnostic(
                            operation="paginate",
                            endpoint_type=endpoint_type,
                            page=page,
                            status=200,
                            reason=(
                                f"data item {index} type is {self._json_type(item)}; "
                                "expected object"
                            ),
                        )
                    )
            results.extend(data)
            links_value = payload.get("links")
            if not isinstance(links_value, dict):
                raise APIError(
                    self._diagnostic(
                        operation="paginate",
                        endpoint_type=endpoint_type,
                        page=page,
                        status=200,
                        reason=(
                            f"links type is {self._json_type(links_value)}; "
                            "expected object"
                        ),
                    )
                )
            next_link = links_value.get("next")
            if not next_link:
                return results
            self._validate_next_link(
                next_link,
                path=path,
                endpoint_type=endpoint_type,
                page=page,
                cursor_mode=False,
            )
        raise PaginationError(
            self._diagnostic(
                operation="paginate",
                endpoint_type=endpoint_type,
                page=MAX_PAGES,
                status=200,
                reason=f"pagination exceeded the {MAX_PAGES}-page safety limit",
            )
        )

    def _validate_next_link(
        self,
        value: Any,
        *,
        path: str,
        endpoint_type: str,
        page: int,
        cursor_mode: bool,
    ) -> None:
        reason = "next link is invalid or outside the endpoint allowlist"
        try:
            if not isinstance(value, str) or not value:
                raise ValueError
            parsed = urllib.parse.urlsplit(value)
            if (
                parsed.scheme != "https"
                or parsed.hostname != "api.hackerone.com"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
                or parsed.path != path
                or parsed.fragment
            ):
                raise ValueError
            query = urllib.parse.parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
            if any(len(values) != 1 for values in query.values()):
                raise ValueError
            allowed = {"page[number]", "page[size]"}
            if cursor_mode:
                allowed.add("filter[id__gt]")
            if not query or set(query) - allowed:
                raise ValueError
            size = int(query["page[size]"][0])
            if not 1 <= size <= PAGE_SIZE:
                raise ValueError
            if cursor_mode:
                if "page[number]" in query and int(query["page[number]"][0]) < 1:
                    raise ValueError
                if "filter[id__gt]" in query and int(query["filter[id__gt]"][0]) < 0:
                    raise ValueError
            elif int(query["page[number]"][0]) != page + 1:
                raise ValueError
        except (KeyError, TypeError, ValueError, urllib.error.URLError) as exc:
            raise PaginationError(
                self._diagnostic(
                    operation="paginate",
                    endpoint_type=endpoint_type,
                    page=page,
                    status=200,
                    reason=reason,
                )
            ) from exc

    def programs(self) -> list[dict[str, Any]]:
        return self._paginated(
            f"{API_PREFIX}/programs",
            endpoint_type="program-list",
        )

    def program(self, handle: str) -> dict[str, Any]:
        self._validate_handle(handle)
        payload = self._request(
            f"{API_PREFIX}/programs/{handle}",
            {},
            operation="fetch-one",
            endpoint_type="program-detail",
            expected_data_type=dict,
        )
        return payload["data"]

    def structured_scopes(self, handle: str) -> list[dict[str, Any]]:
        self._validate_handle(handle)
        path = f"{API_PREFIX}/programs/{handle}/structured_scopes"
        results: list[dict[str, Any]] = []
        cursor: int | None = None
        for batch in range(1, MAX_CURSOR_BATCHES + 1):
            query = {"page[size]": str(PAGE_SIZE)}
            if cursor is not None:
                query["filter[id__gt]"] = str(cursor)
            payload = self._request(
                path,
                query,
                operation="paginate",
                endpoint_type="structured-scopes",
                expected_data_type=list,
                bucket="structured_scopes",
                page=batch,
            )
            data = payload["data"]
            batch_ids: list[int] = []
            for index, item in enumerate(data):
                if not isinstance(item, dict):
                    reason = (
                        f"data item {index} type is {self._json_type(item)}; expected object"
                    )
                else:
                    try:
                        identifier = int(item["id"])
                    except (KeyError, TypeError, ValueError):
                        reason = f"data item {index} has no numeric ID for cursor pagination"
                    else:
                        reason = ""
                        if identifier < 0 or (batch_ids and identifier <= batch_ids[-1]):
                            reason = f"data item {index} ID is not strictly increasing"
                        elif cursor is not None and identifier <= cursor:
                            reason = f"data item {index} ID does not advance the cursor"
                if reason:
                    raise PaginationError(
                        self._diagnostic(
                            operation="paginate",
                            endpoint_type="structured-scopes",
                            page=batch,
                            status=200,
                            reason=reason,
                        )
                    )
                batch_ids.append(identifier)

            links_value = payload.get("links")
            if not isinstance(links_value, dict):
                raise APIError(
                    self._diagnostic(
                        operation="paginate",
                        endpoint_type="structured-scopes",
                        page=batch,
                        status=200,
                        reason=(
                            f"links type is {self._json_type(links_value)}; expected object"
                        ),
                    )
                )
            results.extend(data)
            next_link = links_value.get("next")
            if not next_link:
                return results
            self._validate_next_link(
                next_link,
                path=path,
                endpoint_type="structured-scopes",
                page=batch,
                cursor_mode=True,
            )
            if not batch_ids:
                raise PaginationError(
                    self._diagnostic(
                        operation="paginate",
                        endpoint_type="structured-scopes",
                        page=batch,
                        status=200,
                        reason="next link is present but the data array is empty",
                    )
                )
            cursor = batch_ids[-1]
        raise PaginationError(
            self._diagnostic(
                operation="paginate",
                endpoint_type="structured-scopes",
                page=MAX_CURSOR_BATCHES,
                status=200,
                reason=(
                    "cursor pagination exceeded the "
                    f"{MAX_CURSOR_BATCHES}-batch safety limit"
                ),
            )
        )

    def scope_exclusions(self, handle: str) -> list[dict[str, Any]]:
        self._validate_handle(handle)
        payload = self._request(
            f"{API_PREFIX}/programs/{handle}/scope_exclusions",
            {},
            operation="fetch-list",
            endpoint_type="scope-exclusions",
            expected_data_type=list,
        )
        for index, item in enumerate(payload["data"]):
            if not isinstance(item, dict):
                raise APIError(
                    self._diagnostic(
                        operation="fetch-list",
                        endpoint_type="scope-exclusions",
                        status=200,
                        reason=(
                            f"data item {index} type is {self._json_type(item)}; "
                            "expected object"
                        ),
                    )
                )
        return payload["data"]

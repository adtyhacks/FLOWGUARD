"""Unit tests for the foundational FLOWGUARD client and evidence components."""

from __future__ import annotations

from dataclasses import asdict
import threading
import time
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.evidence import capture_evidence, redact_headers, sanitize_payload


class FakeResponse:
    """Minimal response stub used to simulate HTTP responses in tests."""

    def __init__(self, status_code: int, payload: object, headers: dict[str, str] | None = None, reason: str = "OK") -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {"Content-Type": "application/json"}
        self.reason = reason
        self.text = str(payload)

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("Not JSON")
        return self._payload


def test_flowguard_config_validates_local_target() -> None:
    """FlowGuardConfig accepts localhost by default and rejects non-local targets."""
    cfg = FlowGuardConfig(base_url="http://127.0.0.1:5000", target_mode="vulnerable")
    assert cfg.base_url == "http://127.0.0.1:5000"
    assert cfg.target_mode == "vulnerable"

    with pytest.raises(ValueError):
        FlowGuardConfig(base_url="https://example.com")


def test_flowguard_config_rejects_embedded_url_credentials() -> None:
    with pytest.raises(ValueError, match="embedded credentials"):
        FlowGuardConfig(base_url="http://user:password@localhost:5000")

    with pytest.raises(ValueError):
        FlowGuardConfig(target_mode="invalid")


def test_flowguard_config_rejects_query_credentials_and_unapproved_allowlist() -> None:
    with pytest.raises(ValueError):
        FlowGuardConfig(base_url="http://localhost:5000/?api_key=secret")
    with pytest.raises(ValueError):
        FlowGuardConfig(allowed_local_hosts=("localhost", "example.com"))


def test_flowguard_config_serialization_never_exposes_secrets() -> None:
    config = FlowGuardConfig(
        admin_key="admin-test-secret",
        extra_headers={"Cookie": "cookie-test-secret", "X-Api-Key": "api-test-secret"},
    )
    rendered = repr(config)
    exported = str(config.to_dict())
    generic_export = str(asdict(config))
    for secret in ("admin-test-secret", "cookie-test-secret", "api-test-secret"):
        assert secret not in rendered
        assert secret not in exported
        assert secret not in generic_export


def test_flowguard_config_from_env_uses_expected_values() -> None:
    """Config values can be loaded from environment variables."""
    cfg = FlowGuardConfig.from_env(
        {
            "FLOWGUARD_BASE_URL": "http://localhost:5001",
            "FLOWGUARD_TARGET_MODE": "secure",
            "FLOWGUARD_TIMEOUT": "3.25",
            "ADMIN_KEY": "test-admin-key",
        }
    )

    assert cfg.base_url == "http://localhost:5001"
    assert cfg.target_mode == "secure"
    assert cfg.timeout == 3.25
    assert cfg.admin_key == "test-admin-key"


def test_client_handles_http_success_response() -> None:
    """A successful response is parsed and marked as OK."""
    client = FlowGuardClient()
    fake_response = FakeResponse(200, {"status": "ok", "count": 2})

    with patch("requests.Session.request", return_value=fake_response):
        result = client.get("/products")

    assert result.status_code == 200
    assert result.ok is True
    assert result.payload == {"status": "ok", "count": 2}
    assert result.error is None


def test_client_handles_http_error_response() -> None:
    """HTTP error payloads are marked not OK and surfaced in the result."""
    client = FlowGuardClient()
    fake_response = FakeResponse(401, {"error": "Unauthorized", "message": "invalid bearer token"})

    with patch("requests.Session.request", return_value=fake_response):
        result = client.get("/products")

    assert result.status_code == 401
    assert result.ok is False
    assert result.error == "invalid bearer token"


def test_client_handles_http_timeout() -> None:
    """Timeouts are caught and converted into a structured failure result."""
    client = FlowGuardClient()

    with patch("requests.Session.request", side_effect=requests.Timeout("request halted")):
        result = client.get("/products")

    assert result.status_code == 0
    assert result.ok is False
    assert result.error == "Request timed out."
    assert result.payload == {"error": "Request timed out."}


@pytest.mark.parametrize("path", [
    "https://example.com/steal",
    "http://user:password@localhost:5000/steal",
    "//example.com/steal",
    "\\\\example.com\\steal",
    "/../admin/steal",
    "/%2e%2e/admin/steal",
    "/%2f%2fevil.test/steal",
    "/%252e%252e/admin",
    "/%252f%252fevil",
    "/%255c%255cevil",
    "/%252e%252e%252fadmin",
    "/%2525252e%2525252e/admin",
    "/path?token=secret",
    "/bad%2",
])
def test_client_rejects_unapproved_or_malformed_paths_before_sending_headers(path: str) -> None:
    client = FlowGuardClient(FlowGuardConfig(admin_key="admin-test-secret"))
    with patch("requests.Session.request") as request:
        with pytest.raises(ValueError):
            client.get(path, headers={"Authorization": "Bearer bearer-test-secret"})
    request.assert_not_called()


def test_client_does_not_follow_redirects_or_report_them_as_success() -> None:
    client = FlowGuardClient()
    fake_response = FakeResponse(302, {"message": "Redirect"}, headers={"Content-Type": "application/json", "Location": "https://example.com/steal"})
    with patch("requests.Session.request", return_value=fake_response) as request:
        result = client.get("/products", headers={"Authorization": "Bearer local-token"})

    assert result.status_code == 302
    assert result.ok is False
    assert request.call_args.kwargs["allow_redirects"] is False


def test_client_disables_hostile_environment_proxies_for_local_credentials() -> None:
    client = FlowGuardClient(FlowGuardConfig(
        admin_key="admin-test-secret",
        extra_headers={"X-Admin-Key": "admin-test-secret"},
    ))
    fake_response = FakeResponse(200, {"status": "ok"})

    with patch.dict("os.environ", {
        "HTTP_PROXY": "http://hostile-proxy.example:8080",
        "HTTPS_PROXY": "http://hostile-proxy.example:8080",
        "ALL_PROXY": "http://hostile-proxy.example:8080",
        "NO_PROXY": "",
        "no_proxy": "",
    }, clear=False):
        with patch("requests.Session") as session_factory:
            session = session_factory.return_value.__enter__.return_value
            session.request.return_value = fake_response
            result = client.get(
                "/products",
                headers={"Authorization": "Bearer local-test-token"},
            )

    assert result.ok is True
    assert session.trust_env is False
    assert session.request.call_args.kwargs["url"].startswith("http://127.0.0.1:")
    assert session.request.call_args.kwargs["headers"]["Authorization"] == "Bearer local-test-token"
    assert not any(name.lower() == "x-admin-key" for name in session.request.call_args.kwargs["headers"])


def test_admin_key_only_reaches_dedicated_verification_requests() -> None:
    client = FlowGuardClient(FlowGuardConfig(
        admin_key="configured-admin-secret",
        extra_headers={"x-admin-key": "extra-admin-secret"},
    ))
    fake_response = FakeResponse(200, {"found": True, "order": {"id": 7, "status": "PENDING_PAYMENT"}})

    with patch("requests.Session.request", return_value=fake_response) as request:
        client.get(
            "/orders",
            headers={"X-AdMiN-KeY": "caller-admin-secret", "Authorization": "Bearer user-token"},
        )
        ordinary_headers = request.call_args.kwargs["headers"]
        assert not any(name.lower() == "x-admin-key" for name in ordinary_headers)
        assert ordinary_headers["Authorization"] == "Bearer user-token"

        for path in (
            "/api/admin/verify/order/secure/7/extra",
            "/api/admin/verify/order/secure/7/",
            "/api/admin/verify/other/secure/7",
        ):
            client.get(path, headers={"X-aDmIn-KeY": "caller-admin-secret"})
            invalid_verification_headers = request.call_args.kwargs["headers"]
            assert not any(name.lower() == "x-admin-key" for name in invalid_verification_headers)

        client.post(
            "/api/admin/verify/order/secure/7",
            headers={"X-ADMIN-KEY": "caller-admin-secret"},
        )
        non_read_only_headers = request.call_args.kwargs["headers"]
        assert not any(name.lower() == "x-admin-key" for name in non_read_only_headers)

        client.admin_verify_order("secure", 7)
        order_headers = request.call_args.kwargs["headers"]
        assert order_headers["X-Admin-Key"] == "configured-admin-secret"
        client.admin_verify_payment("secure", 7)
        payment_headers = request.call_args.kwargs["headers"]
        assert payment_headers["X-Admin-Key"] == "configured-admin-secret"
        client.admin_verify_coupon("secure", "WELCOME10")
        coupon_headers = request.call_args.kwargs["headers"]
        assert coupon_headers["X-Admin-Key"] == "configured-admin-secret"
        for verification_headers in (order_headers, payment_headers, coupon_headers):
            assert len([name for name in verification_headers if name.lower() == "x-admin-key"]) == 1


def test_client_handles_invalid_json_response() -> None:
    """Invalid JSON content is returned as raw text rather than crashing."""
    client = FlowGuardClient()
    fake_response = FakeResponse(200, "not-json", headers={"Content-Type": "application/json"})

    with patch("requests.Session.request", return_value=fake_response):
        result = client.get("/products")

    assert result.ok is True
    assert result.payload == "not-json"


def test_client_tracks_request_timing() -> None:
    """Request timing is captured in milliseconds."""
    client = FlowGuardClient(FlowGuardConfig(timeout=1.0))

    def fake_request(*args, **kwargs):
        time.sleep(0.02)
        return FakeResponse(200, {"status": "ok"})

    with patch("requests.Session.request", side_effect=fake_request):
        result = client.get("/products")

    assert result.elapsed_ms >= 10
    assert result.elapsed_ms < 5000


def test_redact_headers_removes_sensitive_metadata() -> None:
    """Authorization and admin headers are redacted for safe evidence output."""
    headers = {
        "Authorization": "Bearer secret-token",
        "X-Admin-Key": "admin-secret",
        "Accept": "application/json",
    }

    sanitized = redact_headers(headers)
    assert sanitized["Authorization"] == "***REDACTED***"
    assert sanitized["X-Admin-Key"] == "***REDACTED***"
    assert sanitized["Accept"] == "application/json"


def test_sanitize_payload_redacts_nested_password_and_tokens() -> None:
    """Nested credentials and tokens are redacted without destroying useful structure."""
    payload = {
        "username": "alice",
        "password": "secret-password",
        "nested": {
            "token": "abc123",
            "user": {"password": "another-secret"},
        },
        "api_key": "key-456",
    }

    sanitized = sanitize_payload(payload)
    assert sanitized["password"] == "***REDACTED***"
    assert sanitized["nested"]["token"] == "***REDACTED***"
    assert sanitized["nested"]["user"]["password"] == "***REDACTED***"
    assert sanitized["api_key"] == "***REDACTED***"
    assert sanitized["username"] == "alice"


def test_evidence_capture_serializes_safely() -> None:
    """Evidence records contain sanitized request and response content."""
    record = capture_evidence(
        scenario_id="TC-99",
        endpoint="/vuln/api/orders/checkout",
        request_method="POST",
        request_payload={"password": "pass123", "coupon_code": "CYBERSEC20"},
        request_headers={"Authorization": "Bearer demo-token"},
        response_payload={"token": "sensitive-token", "status": "ok"},
        response_status_code=200,
        observed_state={"order_status": "PENDING_PAYMENT"},
    )

    observed = record.to_dict()
    assert observed["scenario_id"] == "TC-99"
    assert observed["request_summary"]["headers"]["Authorization"] == "***REDACTED***"
    assert observed["request_summary"]["payload"]["password"] == "***REDACTED***"
    assert observed["response_summary"]["payload"]["token"] == "***REDACTED***"
    assert observed["observed_state"]["order_status"] == "PENDING_PAYMENT"


def test_concurrent_client_requests_do_not_share_session_state() -> None:
    """Concurrent calls use per-request session handling without leaking shared state."""
    client = FlowGuardClient()
    count = 8
    results: list[dict[str, object]] = []
    barrier = threading.Barrier(count)
    request_index = {"value": 0}
    lock = threading.Lock()

    def fake_request(*args, **kwargs):
        barrier.wait(timeout=2)
        with lock:
            index = request_index["value"]
            request_index["value"] += 1
        time.sleep(0.01)
        return FakeResponse(200, {"status": "ok", "index": index})

    with patch("requests.Session.request", side_effect=fake_request):
        threads = []
        for _ in range(count):
            thread = threading.Thread(target=lambda: results.append(client.get("/products").payload))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    assert len(results) == count
    assert {item["index"] for item in results} == set(range(count))
    assert not hasattr(client, "session")

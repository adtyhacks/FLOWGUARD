"""Behavioral and failure-path tests for the TC-01 payment bypass scenario."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.scenarios.tc01_payment_bypass import TC01PaymentBypassScenario
from shopzone.config import TestingConfig


class TransportResponse:
    def __init__(self, status_code: int, payload: object, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {"Content-Type": "application/json"}
        self.reason = "OK" if status_code < 400 else "Error"
        self.text = json.dumps(payload) if not isinstance(payload, str) else payload

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("Invalid JSON")
        return self._payload


class FlaskRequestsSession:
    """Route Requests-shaped calls through ShopZone's real Flask test client."""

    def __init__(
        self,
        flask_client,
        calls: list[dict[str, object]],
        overrides=None,
        post_route_overrides=None,
    ) -> None:
        self.flask_client = flask_client
        self.calls = calls
        self.overrides = overrides or {}
        self.post_route_overrides = post_route_overrides or {}
        self.trust_env = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
        parsed = urlsplit(url)
        path = parsed.path
        call = {
            "method": method,
            "path": path,
            "json": json,
            "headers": dict(headers or {}),
            "timeout": timeout,
            "allow_redirects": allow_redirects,
            "trust_env": self.trust_env,
        }
        self.calls.append(call)
        override = self.overrides.get((method, path))
        if override is None:
            override = next(
                (
                    value
                    for (override_method, pattern), value in self.overrides.items()
                    if override_method == method and pattern.endswith("*") and path.startswith(pattern[:-1])
                ),
                None,
            )
        if override is not None:
            if isinstance(override, BaseException):
                raise override
            return override
        response = self.flask_client.open(path, method=method, json=json, headers=headers)
        post_route_override = self.post_route_overrides.get((method, path))
        if post_route_override is not None:
            return post_route_override
        return TransportResponse(
            response.status_code,
            response.get_json(silent=True) if response.is_json else response.get_data(as_text=True),
            {"Content-Type": response.content_type},
        )


def _scenario_for(app_client, *, mode: str = "secure", overrides=None, post_route_overrides=None, extra_headers=None):
    calls: list[dict[str, object]] = []
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode=mode,
        admin_key=TestingConfig.ADMIN_KEY,
        extra_headers=extra_headers,
    )
    client = FlowGuardClient(config)

    def session_factory():
        return FlaskRequestsSession(app_client, calls, overrides, post_route_overrides)

    return TC01PaymentBypassScenario(client, timeout=1.75), calls, session_factory


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_order_status"),
    [
        ("vulnerable", "FAIL", "CONFIRMED"),
        ("secure", "PASS", "PENDING_PAYMENT"),
    ],
)
def test_tc01_detects_unpaid_confirmation_against_real_shopzone_routes(
    client, mode: str, expected_status: str, expected_order_status: str
) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode=mode)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(mode)

    assert result.status == expected_status
    if mode == "secure":
        confirm_evidence = next(item for item in result.evidence if item.observed_state["step"] == "attempt_confirmation_without_payment")
        assert confirm_evidence.response_summary["status_code"] == 400
        assert confirm_evidence.response_summary["payload"]["error"] == "Bad Request"
        assert confirm_evidence.response_summary["payload"]["message"] == (
            "Cannot confirm order in state 'PENDING_PAYMENT'. Order must be in PAID state."
        )
    order_evidence = next(item for item in result.evidence if item.request_summary["method"] == "GET" and "/verify/order/" in item.endpoint)
    payment_evidence = next(item for item in result.evidence if item.request_summary["method"] == "GET" and "/verify/payment/" in item.endpoint)
    assert order_evidence.response_summary["payload"]["order"]["status"] == expected_order_status
    assert payment_evidence.response_summary["payload"] == {"found": False, "payment": None}

    call_paths = [call["path"] for call in calls]
    assert any(path.endswith("/orders/checkout") for path in call_paths)
    assert any(path.endswith("/confirm") for path in call_paths)
    assert not any(path.endswith("/payment/process") for path in call_paths)
    assert any(path.endswith("/auth/logout") for path in call_paths)
    assert all(call["trust_env"] is False for call in calls)
    assert all(call["allow_redirects"] is False for call in calls)
    assert all(call["timeout"] == 1.75 for call in calls)
    admin_calls = [call for call in calls if "/api/admin/verify/" in call["path"]]
    assert admin_calls
    assert all(call["headers"].get("X-Admin-Key") == TestingConfig.ADMIN_KEY for call in admin_calls)


@pytest.mark.parametrize(
    ("response", "expected_status"),
    [
        (TransportResponse(500, {"message": "server error"}), "ERROR"),
        (requests.Timeout("request timed out"), "ERROR"),
        (TransportResponse(409, {"error": "Conflict", "message": "unexpected rejection"}), "ERROR"),
        (TransportResponse(200, {"message": "Order confirmed"}), "ERROR"),
    ],
)
def test_tc01_unexpected_secure_confirmation_response_never_passes(client, response, expected_status) -> None:
    scenario, _, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/orders/1/confirm"): response},
    )
    # Order IDs are reset for each app fixture and this test creates the first order.
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")
    assert result.status == expected_status
    assert result.status != "PASS"


def test_tc01_global_admin_header_is_only_sent_to_verification_endpoints(client) -> None:
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        extra_headers={"x-admin-key": TestingConfig.ADMIN_KEY},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "PASS"
    for call in calls:
        admin_verification = "/api/admin/verify/" in call["path"]
        admin_headers = [name for name in call["headers"] if name.lower() == "x-admin-key"]
        assert bool(admin_headers) is admin_verification


def test_tc01_admin_verification_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/*"): TransportResponse(503, {"message": "verification unavailable"}),
        ("GET", "/api/admin/verify/payment/*"): TransportResponse(503, {"message": "verification unavailable"}),
    }
    scenario, _, session_factory = _scenario_for(client, mode="vulnerable", overrides=overrides)
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    assert result.status == "INCONCLUSIVE"
    assert "ground-truth" in (result.error or "").lower()


def test_tc01_authentication_failure_is_execution_error(client) -> None:
    override = TransportResponse(401, {"error": "Unauthorized", "message": "Invalid username or password."})
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/auth/login"): override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert not any(call["path"].endswith("/orders/checkout") for call in calls)
    assert not any(call["path"].endswith("/auth/logout") for call in calls)


def test_tc01_checkout_failure_cleans_cart_and_logs_out(client) -> None:
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/orders/checkout"): TransportResponse(500, {"message": "checkout failed"})},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert any(call["method"] == "DELETE" and call["path"] == "/secure/api/cart" for call in calls)
    assert any(call["method"] == "POST" and call["path"] == "/secure/api/auth/logout" for call in calls)
    steps = [record.observed_state["step"] for record in result.evidence]
    assert "cleanup_residual_cart" in steps
    assert "cleanup_logout" in steps


def test_tc01_malformed_catalog_and_checkout_responses_are_errors(client) -> None:
    malformed_catalog = TransportResponse(200, {"items": []})
    scenario, _, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("GET", "/secure/api/products"): malformed_catalog},
    )
    with patch("requests.Session", side_effect=session_factory):
        catalog_result = scenario.run("secure")
    assert catalog_result.status == "ERROR"

    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/orders/checkout"): TransportResponse(201, {"message": "created"})},
    )
    with patch("requests.Session", side_effect=session_factory):
        checkout_result = scenario.run("secure")
    assert checkout_result.status == "ERROR"
    assert not any(call["path"].endswith("/confirm") for call in calls)
    assert any(call["method"] == "DELETE" and call["path"] == "/secure/api/cart" for call in calls)


def test_tc01_malformed_success_after_cart_commit_triggers_user_scoped_cleanup(client) -> None:
    client.post("/sec/api/auth/register", json={
        "username": "unrelated_cart_owner",
        "email": "unrelated_cart_owner@flowguard.local",
        "password": "UnrelatedPass!123",
    })
    unrelated_login = client.post("/sec/api/auth/login", json={
        "username": "unrelated_cart_owner",
        "password": "UnrelatedPass!123",
    }).get_json()
    unrelated_headers = {"Authorization": f"Bearer {unrelated_login['token']}"}
    client.post("/sec/api/cart/items", headers=unrelated_headers, json={"product_id": 1, "quantity": 1})

    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        post_route_overrides={
            ("POST", "/secure/api/cart/items"): TransportResponse(201, {"unexpected": "malformed success"}),
        },
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert any(call["method"] == "DELETE" and call["path"] == "/secure/api/cart" for call in calls)
    unrelated_cart = client.get("/sec/api/cart", headers=unrelated_headers).get_json()
    assert unrelated_cart["item_count"] == 1
    steps = [record.observed_state["step"] for record in result.evidence]
    assert "cleanup_residual_cart" in steps


def test_tc01_cart_cleanup_exception_does_not_prevent_logout(client) -> None:
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/orders/checkout"): TransportResponse(500, {"message": "checkout failed"}),
            ("DELETE", "/secure/api/cart"): RuntimeError("simulated cleanup failure"),
        },
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert any(call["method"] == "DELETE" and call["path"] == "/secure/api/cart" for call in calls)
    assert any(call["method"] == "POST" and call["path"] == "/secure/api/auth/logout" for call in calls)
    assert "cleanup_cart_error" in [record.observed_state["step"] for record in result.evidence]


@pytest.mark.parametrize("order_payload", [
    {"found": True, "order": {"id": 1}},
    {"found": True, "order": {"id": True, "status": "PENDING_PAYMENT"}},
    {"found": True, "order": {"id": "1", "status": "PENDING_PAYMENT"}},
])
def test_tc01_admin_verification_malformed_state_is_inconclusive(client, order_payload) -> None:
    overrides = {("GET", "/api/admin/verify/order/*"): TransportResponse(200, order_payload)}
    scenario, _, session_factory = _scenario_for(client, mode="secure", overrides=overrides)
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")
    assert result.status == "INCONCLUSIVE"


def test_tc01_evidence_redacts_credentials_and_tokens(client) -> None:
    scenario, _, session_factory = _scenario_for(client, mode="vulnerable")
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    serialized = json.dumps(result.to_dict())
    assert "***REDACTED***" in serialized
    assert "Bearer " not in serialized
    assert "password" in serialized
    assert "tc01_" in serialized
    assert "ADMIN_KEY" not in serialized


def test_tc01_missing_admin_key_is_inconclusive_without_requests() -> None:
    client = FlowGuardClient(FlowGuardConfig(base_url="http://127.0.0.1:5000", admin_key=None))
    scenario = TC01PaymentBypassScenario(client)
    with patch("requests.Session.request") as request:
        result = scenario.run("secure")
    assert result.status == "INCONCLUSIVE"
    request.assert_not_called()


def test_tc01_rejects_invalid_mode_without_requests() -> None:
    scenario = TC01PaymentBypassScenario(
        FlowGuardClient(FlowGuardConfig(admin_key=TestingConfig.ADMIN_KEY)),
    )
    with patch("requests.Session.request") as request:
        result = scenario.run("production")
    assert result.status == "ERROR"
    request.assert_not_called()


# =========================================================================
# TC-01 Ownership Validation Tests (Findings Remediation)
# =========================================================================

def test_tc01_correct_checkout_ownership_proceeds_to_confirmation(client) -> None:
    """1. Correct checkout ownership allows confirmation to proceed."""
    scenario, calls, session_factory = _scenario_for(client, mode="secure")
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "PASS"
    confirm_calls = [call for call in calls if call["path"].endswith("/confirm")]
    assert len(confirm_calls) == 1


def test_tc01_checkout_different_user_id_is_inconclusive_without_confirmation(client) -> None:
    """2. Different checkout user_id returns INCONCLUSIVE without sending confirmation."""
    override = TransportResponse(
        201,
        {"order": {"id": 1, "status": "PENDING_PAYMENT", "user_id": 9999}},
    )
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/orders/checkout"): override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ownership" in (result.error or "").lower()
    confirm_calls = [call for call in calls if call["path"].endswith("/confirm")]
    assert len(confirm_calls) == 0, f"Expected 0 confirmation calls, got {len(confirm_calls)}"


def test_tc01_checkout_missing_user_id_is_inconclusive_without_confirmation(client) -> None:
    """3. Missing checkout user_id returns INCONCLUSIVE without sending confirmation."""
    override = TransportResponse(
        201,
        {"order": {"id": 1, "status": "PENDING_PAYMENT"}},
    )
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/orders/checkout"): override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ownership" in (result.error or "").lower()
    confirm_calls = [call for call in calls if call["path"].endswith("/confirm")]
    assert len(confirm_calls) == 0, f"Expected 0 confirmation calls, got {len(confirm_calls)}"


@pytest.mark.parametrize("bad_user_id", [True, False, "1", None, 1.5, [1], {"id": 1}])
def test_tc01_checkout_malformed_user_id_is_inconclusive_without_confirmation(client, bad_user_id) -> None:
    """4. Malformed checkout user_id (bool, string, float, null) returns INCONCLUSIVE without confirmation."""
    override = TransportResponse(
        201,
        {"order": {"id": 1, "status": "PENDING_PAYMENT", "user_id": bad_user_id}},
    )
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("POST", "/secure/api/orders/checkout"): override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ownership" in (result.error or "").lower()
    confirm_calls = [call for call in calls if call["path"].endswith("/confirm")]
    assert len(confirm_calls) == 0, f"Expected 0 confirmation calls, got {len(confirm_calls)}"


def test_tc01_admin_different_user_id_is_inconclusive(client) -> None:
    """5. Different admin user_id returns INCONCLUSIVE."""
    admin_override = TransportResponse(
        200,
        {"found": True, "order": {"id": 1, "status": "PENDING_PAYMENT", "user_id": 9999}},
    )
    scenario, _, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("GET", "/api/admin/verify/order/*"): admin_override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ground-truth" in (result.error or "").lower()


def test_tc01_admin_missing_user_id_is_inconclusive(client) -> None:
    """6. Missing admin user_id returns INCONCLUSIVE."""
    admin_override = TransportResponse(
        200,
        {"found": True, "order": {"id": 1, "status": "PENDING_PAYMENT"}},
    )
    scenario, _, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("GET", "/api/admin/verify/order/*"): admin_override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ground-truth" in (result.error or "").lower()


@pytest.mark.parametrize("bad_admin_user_id", [True, False, "1", None, 1.5])
def test_tc01_admin_boolean_or_string_user_id_is_inconclusive(client, bad_admin_user_id) -> None:
    """7. Boolean or string admin user_id returns INCONCLUSIVE."""
    admin_override = TransportResponse(
        200,
        {"found": True, "order": {"id": 1, "status": "PENDING_PAYMENT", "user_id": bad_admin_user_id}},
    )
    scenario, _, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={("GET", "/api/admin/verify/order/*"): admin_override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ground-truth" in (result.error or "").lower()


def test_tc01_checkout_admin_ownership_disagreement_is_inconclusive(client) -> None:
    """8. Disagreement between checkout user_id and admin user_id returns INCONCLUSIVE."""
    admin_override = TransportResponse(
        200,
        {"found": True, "order": {"id": 1, "status": "CONFIRMED", "user_id": 9999}},
    )
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="vulnerable",
        overrides={("GET", "/api/admin/verify/order/*"): admin_override},
    )
    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    # Confirmation was sent because checkout ownership succeeded
    confirm_calls = [call for call in calls if call["path"].endswith("/confirm")]
    assert len(confirm_calls) == 1
    # But admin ownership disagreed, so it must NOT classify as FAIL
    assert result.status == "INCONCLUSIVE"
    assert "ground-truth" in (result.error or "").lower()

"""Behavioral, invariant, and failure-path tests for the TC-04 Order IDOR scenario."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.scenarios.tc04_order_idor import TC04OrderIDORScenario
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

    return TC04OrderIDORScenario(client, timeout=2.0), calls, session_factory


@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [
        ("vulnerable", "FAIL"),
        ("secure", "PASS"),
    ],
)
def test_tc04_order_idor_against_real_shopzone_routes(
    client, mode: str, expected_status: str
) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode=mode)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(mode)

    assert result.status == expected_status

    if mode == "vulnerable":
        assert "Vulnerable mode permitted unauthorized user B to access victim user A's order" in result.actual_behavior
        # User B successfully accessed User A's order
        idor_ev = next(
            item for item in result.evidence if item.observed_state["step"] == "user_b_access_user_a_order"
        )
        assert idor_ev.response_summary["status_code"] == 200
        assert "order" in idor_ev.response_summary["payload"]
        assert idor_ev.response_summary["payload"]["order"]["id"] > 0
    else:
        assert "Secure mode enforced object-level authorization" in result.actual_behavior
        # User B was denied
        idor_ev = next(
            item for item in result.evidence if item.observed_state["step"] == "user_b_access_user_a_order"
        )
        assert idor_ev.response_summary["status_code"] == 404
        assert "order" not in (idor_ev.response_summary["payload"] or {})

        # User A successfully retrieved their own order
        owner_ev = next(
            item for item in result.evidence if item.observed_state["step"] == "user_a_verify_own_order_access"
        )
        assert owner_ev.response_summary["status_code"] == 200
        assert "order" in owner_ev.response_summary["payload"]

    call_paths = [call["path"] for call in calls]
    # Checkouts occurred
    assert any(path.endswith("/orders/checkout") for path in call_paths)
    # Logouts occurred for both synthetic users
    logout_count = sum(1 for path in call_paths if path.endswith("/auth/logout"))
    assert logout_count >= 2


def test_tc04_missing_admin_key_is_inconclusive_without_requests(client) -> None:
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=None,
    )
    flowguard_client = FlowGuardClient(config)
    scenario = TC04OrderIDORScenario(flowguard_client, timeout=1.0)
    calls: list[dict[str, object]] = []

    def session_factory():
        return FlaskRequestsSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "ADMIN_KEY" in (result.error or "")
    assert "not configured" in result.actual_behavior
    assert len(calls) == 0


@pytest.mark.parametrize("invalid_mode", ["invalid", "production", ""])
def test_tc04_rejects_invalid_mode_without_requests(client, invalid_mode: str) -> None:
    scenario, calls, session_factory = _scenario_for(client)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(invalid_mode)

    assert result.status == "ERROR"
    assert "mode must be vulnerable or secure" in (result.error or "")
    assert len(calls) == 0


def test_tc04_user_a_registration_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/auth/register"): TransportResponse(500, {"error": "DB Error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Registration failed for user A" in result.actual_behavior


def test_tc04_user_a_login_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/auth/login"): TransportResponse(401, {"error": "Invalid credentials"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Authentication failed for user A" in result.actual_behavior


def test_tc04_product_catalog_failure_is_error(client) -> None:
    overrides = {
        ("GET", "/secure/api/products"): TransportResponse(500, {"error": "Server error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Product catalog could not be retrieved" in result.actual_behavior


def test_tc04_cart_addition_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/cart/items"): TransportResponse(400, {"error": "Bad Request"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Cart creation failed for user A" in result.actual_behavior


def test_tc04_checkout_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/orders/checkout"): TransportResponse(400, {"error": "Empty cart"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Checkout failed for user A" in result.actual_behavior


def test_tc04_initial_order_ground_truth_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(404, {"found": False, "order": None}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "not found in admin ground truth" in result.actual_behavior


def test_tc04_initial_order_ground_truth_auth_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(401, {"error": "Unauthorized"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Admin verification rejected credentials" in result.actual_behavior


def test_tc04_user_b_registration_failure_is_error(client) -> None:
    calls: list[dict[str, object]] = []
    reg_calls = [0]

    def custom_session_factory():
        class CustomSession(FlaskRequestsSession):
            def request(self, *args, **kwargs):
                parsed = urlsplit(kwargs.get("url"))
                if kwargs.get("method") == "POST" and parsed.path == "/secure/api/auth/register":
                    reg_calls[0] += 1
                    if reg_calls[0] == 2:
                        self.calls.append({"method": "POST", "path": parsed.path})
                        return TransportResponse(500, {"error": "Registration failed for user B"})
                return super().request(*args, **kwargs)

        return CustomSession(client, calls)

    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    flowguard_client = FlowGuardClient(config)
    scenario_inst = TC04OrderIDORScenario(flowguard_client, timeout=2.0)

    with patch("requests.Session", side_effect=custom_session_factory):
        result = scenario_inst.run("secure")

    assert result.status == "ERROR"
    assert "Registration failed for user B" in result.actual_behavior


def test_tc04_user_b_transport_failure_is_error(client) -> None:
    overrides = {
        ("GET", "/secure/api/orders/*"): requests.Timeout("Connection timed out"),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Cross-user order request failed at transport layer" in result.actual_behavior


def test_tc04_vulnerable_denial_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/vulnerable/api/orders/*"): TransportResponse(404, {"error": "Not Found"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="vulnerable", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    assert result.status == "INCONCLUSIVE"
    assert "Vulnerable mode denied access to user A's order" in result.actual_behavior


def test_tc04_vulnerable_malformed_order_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/vulnerable/api/orders/*"): TransportResponse(200, {"order": "not-a-dict"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="vulnerable", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    assert result.status == "INCONCLUSIVE"
    assert "order payload was malformed or ownership was mismatched" in result.actual_behavior


def test_tc04_secure_mode_unauthorized_disclosure_fails(client) -> None:
    overrides = {
        ("GET", "/secure/api/orders/*"): TransportResponse(200, {"order": {"id": 1, "user_id": 1}}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "FAIL"
    assert "Secure mode permitted unauthorized user B to access" in result.actual_behavior or "returned HTTP 200" in result.actual_behavior


def test_tc04_secure_mode_denial_leaking_order_body_fails(client) -> None:
    overrides = {
        ("GET", "/secure/api/orders/*"): TransportResponse(404, {"error": "Not Found", "order": {"id": 1, "user_id": 1}}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "FAIL"
    assert "leaked order dictionary in response body" in result.actual_behavior


def test_tc04_secure_mode_owner_access_failure_is_error(client) -> None:
    calls: list[dict[str, object]] = []
    order_gets = [0]

    def custom_session_factory():
        class CustomSession(FlaskRequestsSession):
            def request(self, *args, **kwargs):
                parsed = urlsplit(kwargs.get("url"))
                if kwargs.get("method") == "GET" and parsed.path.startswith("/secure/api/orders/"):
                    order_gets[0] += 1
                    if order_gets[0] == 1:
                        # User B's unauthorized access -> returns 404 (expected secure denial)
                        return TransportResponse(404, {"error": "Not Found", "message": "Order not found."})
                    elif order_gets[0] == 2:
                        # User A's legitimate access -> fails with 500
                        return TransportResponse(500, {"error": "Internal Server Error"})
                return super().request(*args, **kwargs)

        return CustomSession(client, calls)

    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    flowguard_client = FlowGuardClient(config)
    scenario_inst = TC04OrderIDORScenario(flowguard_client, timeout=2.0)

    with patch("requests.Session", side_effect=custom_session_factory):
        result = scenario_inst.run("secure")

    assert result.status == "ERROR"
    assert "Legitimate order owner could not access their own order" in result.actual_behavior


def test_tc04_evidence_redacts_credentials_and_tokens(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    # Inspect all evidence items for credential leakage
    for item in result.evidence:
        serialized = json.dumps(item.to_dict())
        assert TestingConfig.ADMIN_KEY not in serialized
        assert "password" not in serialized or '"password": "[REDACTED]"' in serialized or '"password": "[SECRET"' in serialized


def test_tc04_global_admin_header_is_only_sent_to_verification_endpoints(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        scenario.run("secure")

    for call in calls:
        headers = call["headers"]
        path = str(call["path"])
        if "/api/admin/verify" in path:
            assert headers.get("X-Admin-Key") == TestingConfig.ADMIN_KEY
        else:
            assert "X-Admin-Key" not in headers


@pytest.mark.parametrize(
    "malformed_payload",
    [
        {"found": True, "order": {"id": True, "user_id": 1}},  # bool id
        {"found": True, "order": {"id": 1, "user_id": False}},  # bool user_id
        {"found": True, "order": {"id": "1", "user_id": 1}},  # string id
        {"found": True, "order": {"id": -1, "user_id": 1}},  # negative id
        {"found": False, "order": None},  # found False
        {"found": True, "order": None},  # missing order dict
    ],
)
def test_tc04_admin_order_malformed_state_is_inconclusive(client, malformed_payload: dict) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(200, malformed_payload),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"

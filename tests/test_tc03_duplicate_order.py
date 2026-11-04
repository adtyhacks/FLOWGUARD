"""Behavioral, invariant, and failure-path tests for the TC-03 duplicate checkout scenario."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.scenarios.tc03_duplicate_order import TC03DuplicateOrderScenario
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

    return TC03DuplicateOrderScenario(client, timeout=2.0), calls, session_factory


@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [
        ("vulnerable", "FAIL"),
        ("secure", "PASS"),
    ],
)
def test_tc03_checkout_idempotency_against_real_shopzone_routes(
    client, mode: str, expected_status: str
) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode=mode)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(mode)

    assert result.status == expected_status

    if mode == "vulnerable":
        assert "Duplicate order creation confirmed" in result.actual_behavior
        # Both orders exist in ground truth
        verify_duplicate_ev = next(
            item for item in result.evidence if item.observed_state["step"] == "verify_duplicate_order_ground_truth"
        )
        assert verify_duplicate_ev.response_summary["status_code"] == 200
        assert verify_duplicate_ev.response_summary["payload"]["found"] is True
    else:
        assert "Idempotent checkout verified" in result.actual_behavior
        # Identical replay returned 200 OK
        replay_ev = next(
            item for item in result.evidence if item.observed_state["step"] == "attempt_identical_checkout_replay"
        )
        assert replay_ev.response_summary["status_code"] == 200
        assert replay_ev.response_summary["payload"]["idempotent_replay"] is True

        # Conflicting payload returned 409 Conflict
        conflict_ev = next(
            item for item in result.evidence if item.observed_state["step"] == "attempt_conflicting_payload_replay"
        )
        assert conflict_ev.response_summary["status_code"] == 409
        assert conflict_ev.response_summary["payload"]["error"] == "Conflict"

    call_paths = [call["path"] for call in calls]
    # Checkouts occurred
    assert any(path.endswith("/orders/checkout") for path in call_paths)
    # Logouts occurred
    assert any(path.endswith("/auth/logout") for path in call_paths)


def test_tc03_missing_admin_key_is_inconclusive_without_requests(client) -> None:
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=None,
    )
    flowguard_client = FlowGuardClient(config)
    scenario = TC03DuplicateOrderScenario(flowguard_client, timeout=1.0)
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
def test_tc03_rejects_invalid_mode_without_requests(client, invalid_mode: str) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(invalid_mode)

    assert result.status == "ERROR"
    assert "mode must be vulnerable or secure" in (result.error or "")
    assert len(calls) == 0


def test_tc03_user_auth_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/auth/register"): TransportResponse(500, {"error": "DB error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Registration failed" in result.actual_behavior


def test_tc03_product_catalog_failure_is_error(client) -> None:
    overrides = {
        ("GET", "/secure/api/products"): TransportResponse(200, {"products": []}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Product catalog was empty or invalid" in result.actual_behavior


def test_tc03_initial_cart_or_checkout_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/orders/checkout"): TransportResponse(500, {"error": "Server error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Initial checkout failed" in result.actual_behavior


def test_tc03_initial_order_ground_truth_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(500, {"error": "Admin crash"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Initial order ground truth could not be validated" in result.actual_behavior


def test_tc03_repopulating_cart_failure_is_error(client) -> None:
    cart_calls = 0

    def cart_override():
        nonlocal cart_calls
        cart_calls += 1
        if cart_calls == 1:
            return None  # First cart creation succeeds
        return TransportResponse(500, {"error": "Cart failure"})

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "POST" and path.endswith("/cart/items"):
                override = cart_override()
                if override is not None:
                    self.calls.append({"method": method, "path": path, "headers": dict(headers or {})})
                    return override
            return super().request(
                method=method, url=url, json=json, params=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects
            )

    calls: list[dict[str, object]] = []
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    client_obj = FlowGuardClient(config)
    scenario = TC03DuplicateOrderScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Re-populating cart failed" in result.actual_behavior


def test_tc03_secure_unexpected_duplicate_order_on_replay_fails(client) -> None:
    # Simulating secure mode failing to be idempotent and returning a new order on replay
    checkout_calls = 0

    def checkout_override():
        nonlocal checkout_calls
        checkout_calls += 1
        if checkout_calls == 1:
            return None  # First checkout succeeds normally
        if checkout_calls == 2:
            # Second checkout returns a duplicate order
            return TransportResponse(
                201,
                {
                    "message": "Order created",
                    "order": {"id": 999, "user_id": 1, "status": "PENDING_PAYMENT", "idempotency_key": "some-key"},
                },
            )
        return None

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "POST" and path.endswith("/orders/checkout"):
                override = checkout_override()
                if override is not None:
                    self.calls.append({"method": method, "path": path, "headers": dict(headers or {})})
                    return override
            return super().request(
                method=method, url=url, json=json, params=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects
            )

    calls: list[dict[str, object]] = []
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    client_obj = FlowGuardClient(config)
    scenario = TC03DuplicateOrderScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "FAIL"
    assert "Secure mode permitted duplicate order creation" in result.actual_behavior


def test_tc03_secure_conflicting_payload_not_rejected_is_error(client) -> None:
    # Simulating secure mode returning 200 instead of 409 for conflicting payload
    checkout_calls = 0

    def checkout_override():
        nonlocal checkout_calls
        checkout_calls += 1
        if checkout_calls in (1, 2):
            return None  # First and second checkouts run normally
        # Third checkout (conflicting payload) erroneously returns 200
        return TransportResponse(200, {"message": "Success", "order": {"id": 1}})

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "POST" and path.endswith("/orders/checkout"):
                override = checkout_override()
                if override is not None:
                    self.calls.append({"method": method, "path": path, "headers": dict(headers or {})})
                    return override
            return super().request(
                method=method, url=url, json=json, params=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects
            )

    calls: list[dict[str, object]] = []
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    client_obj = FlowGuardClient(config)
    scenario = TC03DuplicateOrderScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Secure mode failed to reject conflicting payload" in result.actual_behavior


def test_tc03_vulnerable_contradictory_ground_truth_is_inconclusive(client) -> None:
    # In vulnerable mode, replay returns 201, but user orders list claims count=1
    orders_calls = 0

    def orders_override():
        return TransportResponse(200, {"orders": [{"id": 1, "idempotency_key": "some-key", "user_id": 1}], "count": 1})

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "GET" and path.endswith("/orders"):
                self.calls.append({"method": method, "path": path, "headers": dict(headers or {})})
                return orders_override()
            return super().request(
                method=method, url=url, json=json, params=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects
            )

    calls: list[dict[str, object]] = []
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="vulnerable",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    client_obj = FlowGuardClient(config)
    scenario = TC03DuplicateOrderScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    assert result.status == "INCONCLUSIVE"
    assert "Contradicted duplicate order creation" in result.actual_behavior.lower() or "contradicted" in (result.actual_behavior or "").lower()


def test_tc03_user_orders_endpoint_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/secure/api/orders"): TransportResponse(500, {"error": "Server error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Could not retrieve user orders list" in result.actual_behavior


def test_tc03_evidence_redacts_credentials_and_tokens(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    serialized = json.dumps([item.to_dict() for item in result.evidence])
    assert TestingConfig.ADMIN_KEY not in serialized
    assert "Bearer " not in serialized
    for item in result.evidence:
        payload = item.request_summary.get("payload")
        if isinstance(payload, dict) and "password" in payload:
            assert payload["password"] == "***REDACTED***"


def test_tc03_global_admin_header_is_only_sent_to_verification_endpoints(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "PASS"

    for call in calls:
        headers = call.get("headers", {})
        if "/api/admin/verify/" in str(call.get("path")):
            assert headers.get("X-Admin-Key") == TestingConfig.ADMIN_KEY
        else:
            assert "X-Admin-Key" not in headers


def test_tc03_residual_cart_cleanup_and_logout(client) -> None:
    # In secure mode, cart is re-populated before replay, so the cart has 1 residual item
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "PASS"

    # Cleanup must delete the residual cart
    delete_cart_calls = [call for call in calls if call["method"] == "DELETE" and call["path"].endswith("/cart")]
    assert len(delete_cart_calls) == 1

    # User logout must be invoked
    logout_calls = [call for call in calls if call["method"] == "POST" and call["path"].endswith("/auth/logout")]
    assert len(logout_calls) == 1


@pytest.mark.parametrize(
    "malformed_order_truth",
    [
        {"found": False},
        {"found": True, "order": None},
        {"found": True, "order": {"id": True, "user_id": 1}},  # bool id
        {"found": True, "order": {"id": 1, "user_id": True}},  # bool user_id
        {"found": True, "order": {"id": 1, "user_id": "bad_user"}},  # string user_id
        {"found": True, "order": {"id": 1, "user_id": 999}},  # mismatched user_id
    ],
)
def test_tc03_admin_order_malformed_state_is_inconclusive(client, malformed_order_truth: dict) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(200, malformed_order_truth),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Initial order ground truth could not be validated" in result.actual_behavior

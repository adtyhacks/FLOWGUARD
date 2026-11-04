"""Behavioral, invariant, and failure-path tests for the TC-07 Price Tampering scenario."""

from __future__ import annotations

import fnmatch
import json
import threading
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.scenarios.tc07_price_tampering import TC07PriceTamperingScenario
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
    """Route Requests-shaped calls through ShopZone's real Flask test client in a thread-safe manner."""

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
        self._lock = threading.Lock()

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
        with self._lock:
            self.calls.append(call)

        override = self.overrides.get((method, path))
        if override is None:
            override = next(
                (
                    value
                    for (override_method, pattern), value in self.overrides.items()
                    if override_method == method and (fnmatch.fnmatch(path, pattern) or (pattern.endswith("*") and path.startswith(pattern[:-1])))
                ),
                None,
            )
        if override is not None:
            if callable(override):
                override_val = override(self.flask_client, call)
                if override_val is not None:
                    return override_val
            elif isinstance(override, BaseException):
                raise override
            else:
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
    scenario = TC07PriceTamperingScenario(client=client)

    def session_factory():
        return FlaskRequestsSession(
            app_client,
            calls,
            overrides=overrides,
            post_route_overrides=post_route_overrides,
        )

    return scenario, calls, session_factory


# =========================================================================
# TC-07 Core Invariant Tests (Live Flask Client)
# =========================================================================

def test_tc07_vulnerable_price_tampering_detected(app, client):
    """Vulnerable mode: accepts client-submitted total_amount; scenario reports FAIL."""
    scenario, calls, session_factory = _scenario_for(client, mode="vulnerable")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable", tampered_amount=100)

    assert result.status == "FAIL"
    assert result.scenario_id == "TC-07"
    assert "price tampering" in result.actual_behavior.lower()
    assert "100" in result.actual_behavior

    # Admin key strictly restricted to verification routes
    for call in calls:
        if "X-Admin-Key" in call["headers"]:
            assert call["path"].startswith("/api/admin/verify/")

    # Evidence verification
    steps = [entry.observed_state.get("step") for entry in result.evidence if entry.observed_state]
    assert "fetch_product_catalog" in steps
    assert "populate_cart" in steps
    assert "submit_tampered_checkout" in steps
    assert "admin_verify_tampered_order" in steps
    assert "cleanup_residual_cart" in steps
    assert "logout_synthetic_user" in steps


def test_tc07_secure_price_tampering_prevented(app, client):
    """Secure mode: ignores client-submitted total_amount; scenario reports PASS."""
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", tampered_amount=100)

    assert result.status == "PASS"
    assert result.scenario_id == "TC-07"
    assert "server-authoritative" in result.actual_behavior.lower() or "canonical" in result.actual_behavior.lower()

    # Admin key strictly restricted to verification routes
    for call in calls:
        if "X-Admin-Key" in call["headers"]:
            assert call["path"].startswith("/api/admin/verify/")

    steps = [entry.observed_state.get("step") for entry in result.evidence if entry.observed_state]
    assert "fetch_product_catalog" in steps
    assert "populate_cart" in steps
    assert "submit_tampered_checkout" in steps
    assert "admin_verify_tampered_order" in steps
    assert "cleanup_residual_cart" in steps
    assert "logout_synthetic_user" in steps


def test_tc07_secure_mode_tampering_permitted_fails_closed(app, client):
    """Secure mode: if ground truth unexpectedly reflects tampered price, scenario reports FAIL."""
    def ground_truth_tampered_override(flask_client, call):
        # Allow open to get the real order, but modify total_minor_units to 100
        resp = flask_client.open(call["path"], method="GET", headers=call["headers"])
        if resp.is_json:
            data = resp.get_json()
            if isinstance(data, dict) and data.get("found") is True and isinstance(data.get("order"), dict):
                data["order"]["total_minor_units"] = 100
                return TransportResponse(200, data)
        return None

    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/api/admin/verify/order/secure/*"): ground_truth_tampered_override,
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", tampered_amount=100)

    assert result.status == "FAIL"
    assert "tampered price" in result.actual_behavior.lower()


# =========================================================================
# Guardrails, Edge Cases, and Error Handling Tests
# =========================================================================

def test_tc07_missing_admin_key_is_inconclusive():
    """Scenario fails closed with INCONCLUSIVE if admin key is missing."""
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=None,
    )
    scenario = TC07PriceTamperingScenario(client=FlowGuardClient(config))
    result = scenario.run("secure")
    assert result.status == "INCONCLUSIVE"
    assert "Admin verification is not configured" in result.actual_behavior


def test_tc07_invalid_mode_error():
    """Scenario rejects invalid target mode with ERROR."""
    config = FlowGuardConfig(base_url="http://127.0.0.1:5000", target_mode="secure", admin_key="test-key")
    scenario = TC07PriceTamperingScenario(client=FlowGuardClient(config))

    result = scenario.run("invalid_mode")
    assert result.status == "ERROR"
    assert "Invalid ShopZone mode" in result.actual_behavior


def test_tc07_invalid_tampered_amount_error():
    """Scenario rejects negative amounts or invalid types with ERROR."""
    config = FlowGuardConfig(base_url="http://127.0.0.1:5000", target_mode="secure", admin_key="test-key")
    scenario = TC07PriceTamperingScenario(client=FlowGuardClient(config))

    for invalid_amt in (-1, -500, "100", True, False, None, [100]):
        result = scenario.run("secure", tampered_amount=invalid_amt)
        assert result.status == "ERROR"
        assert "Invalid tampered amount" in result.actual_behavior


def test_tc07_product_catalog_failure_is_error(app, client):
    """Scenario returns ERROR if catalog endpoint fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/secure/api/products"): TransportResponse(500, {"error": "DB error"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "catalog" in result.actual_behavior.lower()


def test_tc07_empty_product_catalog_is_error(app, client):
    """Scenario returns ERROR if catalog is empty."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/secure/api/products"): TransportResponse(200, {"products": []}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "empty or invalid" in result.actual_behavior.lower()


def test_tc07_user_registration_failure_is_error(app, client):
    """Scenario returns ERROR if synthetic user registration fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/auth/register"): TransportResponse(500, {"error": "Registration DB error"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Registration failed" in result.actual_behavior


def test_tc07_user_login_failure_is_error(app, client):
    """Scenario returns ERROR if synthetic user login fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/auth/login"): TransportResponse(401, {"error": "Unauthorized"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Authentication failed" in result.actual_behavior


def test_tc07_cart_addition_failure_is_error(app, client):
    """Scenario returns ERROR if adding product to cart fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/cart/items"): TransportResponse(500, {"error": "Cart failure"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Cart creation failed" in result.actual_behavior


def test_tc07_checkout_failure_is_error(app, client):
    """Scenario returns ERROR if checkout fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/orders/checkout"): TransportResponse(500, {"error": "Checkout crash"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Checkout request did not complete" in result.actual_behavior


def test_tc07_admin_ground_truth_failure_is_inconclusive(app, client):
    """Scenario returns INCONCLUSIVE if admin order verification returns 404 or found=False."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(200, {"found": False}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Admin ground-truth verification" in result.actual_behavior


def test_tc07_admin_ground_truth_ownership_mismatch_is_inconclusive(app, client):
    """Scenario returns INCONCLUSIVE if admin verification indicates order belongs to another user."""
    def ownership_mismatch_override(flask_client, call):
        resp = flask_client.open(call["path"], method="GET", headers=call["headers"])
        if resp.is_json:
            data = resp.get_json()
            if isinstance(data, dict) and data.get("found") is True and isinstance(data.get("order"), dict):
                data["order"]["user_id"] = 999999
                return TransportResponse(200, data)
        return None

    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/api/admin/verify/order/secure/*"): ownership_mismatch_override,
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Admin ground-truth verification" in result.actual_behavior


def test_tc07_admin_ground_truth_malformed_total_is_inconclusive(app, client):
    """Scenario returns INCONCLUSIVE if ground truth order total is malformed or invalid."""
    def malformed_total_override(flask_client, call):
        resp = flask_client.open(call["path"], method="GET", headers=call["headers"])
        if resp.is_json:
            data = resp.get_json()
            if isinstance(data, dict) and data.get("found") is True and isinstance(data.get("order"), dict):
                data["order"]["total_minor_units"] = "one-hundred"
                return TransportResponse(200, data)
        return None

    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/api/admin/verify/order/secure/*"): malformed_total_override,
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Stored order total in ground truth is not a valid integer" in result.actual_behavior


def test_tc07_evidence_credential_redaction(app, client):
    """Scenario evidence must not expose plain-text passwords or secret credentials."""
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", tampered_amount=100)

    for entry in result.evidence:
        payload = entry.request_summary.get("payload") if entry.request_summary else None
        headers = entry.request_summary.get("headers") if entry.request_summary else None
        if payload:
            payload_str = json.dumps(payload)
            assert "password" not in payload_str or "tc07_tamperer" not in payload_str
        if headers:
            if "X-Admin-Key" in headers:
                assert "/api/admin/verify/" in entry.endpoint

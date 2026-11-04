"""Behavioral, invariant, and failure-path tests for the TC-06 Concurrent Checkout scenario."""

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
from flowguard.scenarios.tc06_concurrent_checkout import TC06ConcurrentCheckoutScenario
from shopzone.blueprints.secure.sec_orders import set_checkout_race_hook as set_sec_checkout_race_hook
from shopzone.blueprints.vulnerable.vuln_orders import set_checkout_race_hook as set_vuln_checkout_race_hook
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
    scenario = TC06ConcurrentCheckoutScenario(client=client)

    def session_factory():
        return FlaskRequestsSession(
            app_client,
            calls,
            overrides=overrides,
            post_route_overrides=post_route_overrides,
        )

    return scenario, calls, session_factory


class ControlledPhaseAHook:
    """Synchronize only the first N concurrent checkout workers (Phase A) at a barrier."""

    def __init__(self, num_parties: int, timeout: float = 3.0) -> None:
        self.barrier = threading.Barrier(num_parties)
        self.num_parties = num_parties
        self.timeout = timeout
        self.counter = 0
        self.lock = threading.Lock()

    def __call__(self) -> None:
        with self.lock:
            self.counter += 1
            should_wait = (self.counter <= self.num_parties)

        if should_wait:
            try:
                self.barrier.wait(timeout=self.timeout)
            except Exception:
                pass


# =========================================================================
# TC-06 Core Invariant Tests (Live Flask Client)
# =========================================================================

def test_tc06_vulnerable_concurrent_checkout_detected(app, client):
    """Vulnerable mode: concurrent same-key checkouts create duplicate orders; scenario reports FAIL."""
    num_workers = 4
    hook = ControlledPhaseAHook(num_workers)
    set_vuln_checkout_race_hook(hook)

    scenario, calls, session_factory = _scenario_for(client, mode="vulnerable")
    try:
        with patch("requests.Session", side_effect=session_factory):
            result = scenario.run("vulnerable", num_workers=num_workers)

        assert result.status == "FAIL"
        assert result.scenario_id == "TC-06"
        assert "duplicate order" in result.actual_behavior.lower()
        assert "vulnerable" in result.actual_behavior.lower()

        # Admin key was strictly restricted to verification endpoints
        for call in calls:
            if "X-Admin-Key" in call["headers"]:
                assert call["path"].startswith("/api/admin/verify/")

        # Evidence records individual worker checkout requests and cleanup
        steps = [entry.observed_state.get("step") for entry in result.evidence if entry.observed_state]
        assert "fetch_product_catalog" in steps
        assert "populate_cart_phase_a" in steps
        assert any(s and s.startswith("concurrent_same_key_worker_") for s in steps)
        assert "fetch_user_orders_phase_a" in steps
        assert "cleanup_residual_cart" in steps
        assert "logout_synthetic_user" in steps
    finally:
        set_vuln_checkout_race_hook(None)


def test_tc06_vulnerable_without_race_manifestation_is_inconclusive(app, client):
    """Vulnerable mode: without race hook, if no race manifests, scenario fails closed with INCONCLUSIVE."""
    set_vuln_checkout_race_hook(None)

    # When ground truth does not corroborate duplicate orders committed, fail closed
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="vulnerable",
        overrides={
            ("GET", "/vulnerable/api/orders"): TransportResponse(
                200,
                {"orders": [{"id": 9999, "idempotency_key": "unrelated-key", "user_id": 9999}]},
            )
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable", num_workers=3)

    assert result.status == "INCONCLUSIVE"
    assert "not manifest" in result.actual_behavior.lower() or "not observed" in str(result.error).lower()


def test_tc06_secure_concurrent_checkout_enforced(app, client):
    """Secure mode: concurrent same-key checkouts are deduplicated to exactly 1 order; scenario reports PASS."""
    num_workers = 4
    hook = ControlledPhaseAHook(num_workers)
    set_sec_checkout_race_hook(hook)

    scenario, calls, session_factory = _scenario_for(client, mode="secure")
    try:
        with patch("requests.Session", side_effect=session_factory):
            result = scenario.run("secure", num_workers=num_workers)

        assert result.status == "PASS"
        assert result.scenario_id == "TC-06"
        assert "deduplicated" in result.actual_behavior.lower() or "enforced" in result.actual_behavior.lower()

        # Admin key was strictly restricted to verification endpoints
        for call in calls:
            if "X-Admin-Key" in call["headers"]:
                assert call["path"].startswith("/api/admin/verify/")

        # Verify steps in evidence
        steps = [entry.observed_state.get("step") for entry in result.evidence if entry.observed_state]
        assert "fetch_product_catalog" in steps
        assert "populate_cart_phase_a" in steps
        assert any(s and s.startswith("concurrent_same_key_worker_") for s in steps)
        assert "fetch_user_orders_phase_a" in steps
        assert "populate_cart_phase_b" in steps
        assert any(s and s.startswith("concurrent_diff_key_worker_") for s in steps)
        assert "cleanup_residual_cart" in steps
        assert "logout_synthetic_user" in steps
    finally:
        set_sec_checkout_race_hook(None)


def test_tc06_secure_duplicate_orders_fails_closed(app, client):
    """Secure mode: if ground truth unexpectedly reveals duplicate orders, scenario reports FAIL."""
    num_workers = 3

    def dynamic_orders_override(flask_client, call):
        # Find the shared idempotency key used in checkout calls so far
        shared_key = None
        for c in calls:
            if c.get("path") == "/secure/api/orders/checkout" and isinstance(c.get("json"), dict):
                k = c["json"].get("idempotency_key")
                if k and k.startswith("tc06-shared-"):
                    shared_key = k
                    break
        if shared_key:
            return TransportResponse(
                200,
                {
                    "orders": [
                        {"id": 101, "idempotency_key": shared_key, "user_id": 1},
                        {"id": 102, "idempotency_key": shared_key, "user_id": 1},
                    ]
                },
            )
        return None

    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/secure/api/orders"): dynamic_orders_override,
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=num_workers)

    assert result.status == "FAIL"
    assert "duplicate" in result.actual_behavior.lower()


# =========================================================================
# Configuration, Authentication, and Guardrail Tests
# =========================================================================

def test_tc06_missing_admin_key_inconclusive(app, client):
    """Scenario fails closed with INCONCLUSIVE if admin key is not configured."""
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=None,
    )
    fg_client = FlowGuardClient(config)
    scenario = TC06ConcurrentCheckoutScenario(client=fg_client)

    result = scenario.run("secure")
    assert result.status == "INCONCLUSIVE"
    assert "Admin verification is not configured" in result.actual_behavior


def test_tc06_invalid_mode_error():
    """Scenario rejects invalid target mode with ERROR."""
    config = FlowGuardConfig(base_url="http://127.0.0.1:5000", target_mode="secure", admin_key="test-key")
    scenario = TC06ConcurrentCheckoutScenario(client=FlowGuardClient(config))

    result = scenario.run("invalid_mode")
    assert result.status == "ERROR"
    assert "Invalid ShopZone mode" in result.actual_behavior


def test_tc06_invalid_num_workers_error():
    """Scenario rejects worker counts outside [2, 10] or invalid types with ERROR."""
    config = FlowGuardConfig(base_url="http://127.0.0.1:5000", target_mode="secure", admin_key="test-key")
    scenario = TC06ConcurrentCheckoutScenario(client=FlowGuardClient(config))

    for invalid_workers in (1, 11, "4", True, None, 0, -2):
        result = scenario.run("secure", num_workers=invalid_workers)
        assert result.status == "ERROR"
        assert "Invalid worker count" in result.actual_behavior


def test_tc06_product_catalog_failure_error(app, client):
    """Scenario returns ERROR if product catalog retrieval fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/secure/api/products"): TransportResponse(500, {"error": "Catalog DB error"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "ERROR"
    assert "catalog" in result.actual_behavior.lower()


def test_tc06_empty_product_catalog_error(app, client):
    """Scenario returns ERROR if product catalog returns empty product list."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/secure/api/products"): TransportResponse(200, {"products": []}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "ERROR"
    assert "empty or invalid" in result.actual_behavior.lower()


def test_tc06_user_registration_failure_error(app, client):
    """Scenario returns ERROR if synthetic user registration fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/auth/register"): TransportResponse(500, {"error": "Registration failed"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "ERROR"
    assert "Registration failed" in result.actual_behavior


def test_tc06_user_authentication_failure_error(app, client):
    """Scenario returns ERROR if synthetic user login fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/auth/login"): TransportResponse(401, {"error": "Unauthorized"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "ERROR"
    assert "Authentication failed" in result.actual_behavior


def test_tc06_cart_population_failure_error(app, client):
    """Scenario returns ERROR if cart addition fails."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/cart/items"): TransportResponse(500, {"error": "Cart DB error"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "ERROR"
    assert "Cart creation failed" in result.actual_behavior


def test_tc06_admin_orders_list_malformed_inconclusive(app, client):
    """Scenario returns INCONCLUSIVE if user orders listing ground truth is malformed."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/secure/api/orders"): TransportResponse(200, {"orders": "not-a-list"}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "INCONCLUSIVE"
    assert "Malformed orders list" in result.actual_behavior


def test_tc06_admin_verify_order_failure_inconclusive(app, client):
    """Scenario returns INCONCLUSIVE if admin order verification returns 404 or found=False."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(200, {"found": False}),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    assert result.status == "INCONCLUSIVE"
    assert "Admin verification" in result.actual_behavior


def test_tc06_evidence_credential_redaction(app, client):
    """Scenario evidence must not expose plain-text passwords or secret credentials."""
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=2)

    for entry in result.evidence:
        payload = entry.request_summary.get("payload") if entry.request_summary else None
        headers = entry.request_summary.get("headers") if entry.request_summary else None
        if payload:
            payload_str = json.dumps(payload)
            assert "password" not in payload_str or "tc06_racer" not in payload_str
        if headers:
            # X-Admin-Key should only be present in admin verification steps
            if "X-Admin-Key" in headers:
                assert entry.endpoint.startswith("/api/admin/verify/")


def test_tc06_worker_transport_failure_handled(app, client):
    """Worker thread encountering a transport exception is cleanly handled without crashing."""
    scenario, calls, session_factory = _scenario_for(
        client,
        mode="secure",
        overrides={
            ("POST", "/secure/api/orders/checkout"): requests.ConnectionError("Connection aborted"),
        },
    )

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", num_workers=3)

    # Handled cleanly; fails closed on orders verification or invariant check
    assert result.status in ("FAIL", "INCONCLUSIVE", "ERROR")
    assert not result.error or "unexpected" not in str(result.error).lower()

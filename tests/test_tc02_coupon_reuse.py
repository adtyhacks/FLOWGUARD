"""Behavioral, invariant, and failure-path tests for the TC-02 coupon reuse scenario."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.scenarios.tc02_coupon_reuse import TC02CouponReuseScenario
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

    return TC02CouponReuseScenario(client, timeout=2.0), calls, session_factory


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_redemptions_count"),
    [
        ("vulnerable", "FAIL", 2),
        ("secure", "PASS", 1),
    ],
)
def test_tc02_detects_coupon_reuse_against_real_shopzone_routes(
    client, mode: str, expected_status: str, expected_redemptions_count: int
) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode=mode)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(mode, coupon_code="CYBERSEC20")

    assert result.status == expected_status

    if mode == "vulnerable":
        assert "globally single-use coupon was redeemed by multiple users" in result.actual_behavior
    else:
        assert "only the first user redeemed the globally single-use coupon" in result.actual_behavior
        reuse_evidence = next(
            item for item in result.evidence if item.observed_state["step"] == "attempt_coupon_reuse_user_b"
        )
        assert reuse_evidence.response_summary["status_code"] == 409
        assert reuse_evidence.response_summary["payload"]["error"] == "Conflict"

    final_admin_ev = next(
        item for item in result.evidence if item.observed_state["step"] == "verify_final_coupon_state"
    )
    assert final_admin_ev.response_summary["status_code"] == 200
    assert final_admin_ev.response_summary["payload"]["redemption_count"] >= expected_redemptions_count

    call_paths = [call["path"] for call in calls]
    # Checkouts occurred
    assert any(path.endswith("/orders/checkout") for path in call_paths)
    # Logouts occurred for synthetic users
    assert any(path.endswith("/auth/logout") for path in call_paths)


def test_tc02_missing_admin_key_is_inconclusive_without_requests(client) -> None:
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=None,
    )
    flowguard_client = FlowGuardClient(config)
    scenario = TC02CouponReuseScenario(flowguard_client, timeout=1.0)
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
def test_tc02_rejects_invalid_mode_without_requests(client, invalid_mode: str) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(invalid_mode)

    assert result.status == "ERROR"
    assert "mode must be vulnerable or secure" in (result.error or "")
    assert len(calls) == 0


@pytest.mark.parametrize("invalid_code", ["", "   ", None])
def test_tc02_rejects_invalid_coupon_code_without_requests(client, invalid_code: str | None) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", coupon_code=invalid_code)  # type: ignore

    assert result.status == "ERROR"
    assert "coupon_code must be a non-empty string" in (result.error or "")
    assert len(calls) == 0


def test_tc02_admin_initial_verification_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/coupon/secure/CYBERSEC20"): TransportResponse(500, {"error": "Server error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Initial ground-truth verification was malformed" in (result.error or "")


def test_tc02_coupon_not_found_is_inconclusive(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", coupon_code="NONEXISTENT99")

    assert result.status == "INCONCLUSIVE"
    assert "Target coupon not found" in (result.error or "")


def test_tc02_coupon_not_single_use_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/coupon/secure/MULTIUSE"): TransportResponse(
            200,
            {
                "found": True,
                "coupon": {"id": 10, "code": "MULTIUSE", "max_uses": 5, "times_used": 0, "is_active": True},
                "redemptions": [],
                "redemption_count": 0,
            },
        ),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure", coupon_code="MULTIUSE")

    assert result.status == "INCONCLUSIVE"
    assert "max_uses=5" in result.actual_behavior
    assert "requires max_uses=1" in (result.actual_behavior or "")


def test_tc02_coupon_already_used_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/coupon/secure/CYBERSEC20"): TransportResponse(
            200,
            {
                "found": True,
                "coupon": {"id": 1, "code": "CYBERSEC20", "max_uses": 1, "times_used": 1, "is_active": False},
                "redemptions": [{"id": 1, "coupon_id": 1, "user_id": 99, "order_id": 5}],
                "redemption_count": 1,
            },
        ),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "already exhausted, inactive, or previously redeemed" in result.actual_behavior


def test_tc02_user_a_auth_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/auth/register"): TransportResponse(500, {"error": "DB error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Registration failed for user A" in result.actual_behavior


def test_tc02_user_a_checkout_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/orders/checkout"): TransportResponse(500, {"error": "Checkout crash"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Initial checkout with coupon failed for user A" in result.actual_behavior


def test_tc02_malformed_catalog_response_is_error(client) -> None:
    overrides = {
        ("GET", "/secure/api/products"): TransportResponse(200, {"products": []}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Product catalog was empty or invalid" in result.actual_behavior


def test_tc02_admin_final_verification_failure_is_inconclusive(client) -> None:
    # Initial admin check succeeds, but final admin check fails
    admin_calls = 0

    def admin_override(method, path):
        nonlocal admin_calls
        admin_calls += 1
        if admin_calls == 1:
            # Let the real route handle initial inspection
            return None
        return TransportResponse(500, {"error": "Admin crash"})

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "GET" and "/verify/coupon/" in path:
                override = admin_override(method, path)
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
    scenario = TC02CouponReuseScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Final ground-truth verification was missing or malformed" in (result.error or "")


@pytest.mark.parametrize(
    "malformed_payload",
    [
        {"found": False},
        {"found": True, "coupon": None},
        {"found": True, "coupon": {"code": "CYBERSEC20", "max_uses": True}},  # bool max_uses
        {"found": True, "coupon": {"code": "CYBERSEC20", "max_uses": 1}, "redemptions": "not_a_list"},
        {
            "found": True,
            "coupon": {"code": "CYBERSEC20", "max_uses": 1},
            "redemptions": [{"user_id": True}],  # bool user_id
            "redemption_count": 1,
        },
        {
            "found": True,
            "coupon": {"code": "CYBERSEC20", "max_uses": 1},
            "redemptions": [{"user_id": "string_id"}],  # string user_id
            "redemption_count": 1,
        },
        {
            "found": True,
            "coupon": {"code": "CYBERSEC20", "max_uses": 1},
            "redemptions": [{"user_id": 1}],
            "redemption_count": True,  # bool redemption_count
        },
    ],
)
def test_tc02_admin_final_verification_malformed_state_is_inconclusive(client, malformed_payload: dict) -> None:
    admin_calls = 0

    def admin_override(method, path):
        nonlocal admin_calls
        admin_calls += 1
        if admin_calls == 1:
            return None
        return TransportResponse(200, malformed_payload)

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "GET" and "/verify/coupon/" in path:
                override = admin_override(method, path)
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
    scenario = TC02CouponReuseScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Final ground-truth verification was missing or malformed" in (result.error or "")


def test_tc02_contradictory_evidence_in_vulnerable_mode_is_inconclusive(client) -> None:
    # User B checkout returns 201, but admin verification claims redemption_count=1 (User B not present)
    admin_calls = 0

    def admin_override(method, path):
        nonlocal admin_calls
        admin_calls += 1
        if admin_calls == 1:
            return None
        # Return only user 1 redemption
        return TransportResponse(
            200,
            {
                "found": True,
                "coupon": {"id": 1, "code": "CYBERSEC20", "max_uses": 1, "times_used": 1, "is_active": True},
                "redemptions": [{"id": 1, "coupon_id": 1, "user_id": 1, "order_id": 1}],
                "redemption_count": 1,
            },
        )

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "GET" and "/verify/coupon/" in path:
                override = admin_override(method, path)
                if override is not None:
                    self.calls.append({"method": method, "path": path, "headers": dict(headers or {})})
                    return override
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
    scenario = TC02CouponReuseScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    assert result.status == "INCONCLUSIVE"
    assert "Contradictory evidence" in result.actual_behavior


def test_tc02_unexpected_secure_reuse_response_never_passes(client) -> None:
    # In secure mode, if User B checkout unexpectedly returns 201 and admin verifies 2 redemptions -> FAIL
    admin_calls = 0

    def admin_override(method, path):
        nonlocal admin_calls
        admin_calls += 1
        if admin_calls == 1:
            return None
        return TransportResponse(
            200,
            {
                "found": True,
                "coupon": {"id": 1, "code": "CYBERSEC20", "max_uses": 1, "times_used": 2, "is_active": False},
                "redemptions": [
                    {"id": 1, "coupon_id": 1, "user_id": 1, "order_id": 1},
                    {"id": 2, "coupon_id": 1, "user_id": 2, "order_id": 2},
                ],
                "redemption_count": 2,
            },
        )

    checkout_calls = 0

    def checkout_override():
        nonlocal checkout_calls
        checkout_calls += 1
        if checkout_calls == 1:
            return None
        # User B checkout unexpectedly returns 201
        return TransportResponse(
            201,
            {
                "message": "Order created",
                "order": {"id": 2, "user_id": 2, "status": "PENDING_PAYMENT", "coupon_id": 1},
            },
        )

    class CustomSession(FlaskRequestsSession):
        def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
            parsed = urlsplit(url)
            path = parsed.path
            if method == "GET" and "/verify/coupon/" in path:
                override = admin_override(method, path)
                if override is not None:
                    self.calls.append({"method": method, "path": path, "headers": dict(headers or {})})
                    return override
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
    scenario = TC02CouponReuseScenario(client_obj, timeout=2.0)

    def session_factory():
        return CustomSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "FAIL"
    assert "Secure mode permitted multiple redemptions" in result.actual_behavior


def test_tc02_evidence_redacts_credentials_and_tokens(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    serialized = json.dumps([item.to_dict() for item in result.evidence])
    assert TestingConfig.ADMIN_KEY not in serialized
    assert "Bearer " not in serialized
    # Check that passwords don't leak
    for item in result.evidence:
        payload = item.request_summary.get("payload")
        if isinstance(payload, dict) and "password" in payload:
            assert payload["password"] == "***REDACTED***"


def test_tc02_global_admin_header_is_only_sent_to_verification_endpoints(client) -> None:
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


def test_tc02_cleanup_removes_user_b_cart_and_logs_out_both_users(client) -> None:
    # In secure mode, User B's checkout fails with 409, so User B has an uncompleted cart
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "PASS"

    # User B's uncompleted cart cleanup must have been executed
    delete_cart_calls = [call for call in calls if call["method"] == "DELETE" and call["path"].endswith("/cart")]
    assert len(delete_cart_calls) == 1

    # Both User A and User B must be logged out
    logout_calls = [call for call in calls if call["method"] == "POST" and call["path"].endswith("/auth/logout")]
    assert len(logout_calls) == 2



def test_tc02_runner_repeated_execution_provisions_fresh_synthetic_coupon_and_succeeds(client) -> None:
    from flowguard.runner import AssessmentRunner
    calls: list[dict[str, object]] = []
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="vulnerable",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    runner = AssessmentRunner(config, timeout=2.0)

    def session_factory():
        return FlaskRequestsSession(client, calls)

    with patch("requests.Session", side_effect=session_factory):
        # Run 1 against vulnerable mode: provisions unique synthetic coupon and confirms flaw (FAIL)
        res1 = runner.run_scenario("TC-02", "vulnerable")
        assert res1.status == "FAIL"

        # Run 2 against vulnerable mode without database reset: provisions fresh synthetic coupon and confirms flaw (FAIL)
        res2 = runner.run_scenario("TC-02", "vulnerable")
        assert res2.status == "FAIL"

        # Run 3 against secure mode without database reset: provisions fresh synthetic coupon and verifies defense (PASS)
        res3 = runner.run_scenario("TC-02", "secure")
        assert res3.status == "PASS"

    # Verify admin coupon provisioning calls occurred
    admin_coupon_calls = [c for c in calls if "/api/admin/coupon/" in str(c.get("path"))]
    assert len(admin_coupon_calls) >= 3


def test_tc02_exhausted_coupon_precondition_handling_without_provisioning(client) -> None:
    # First exhaust the coupon via direct scenario execution
    scenario, calls, session_factory = _scenario_for(client, mode="vulnerable")
    with patch("requests.Session", side_effect=session_factory):
        res1 = scenario.run("vulnerable", coupon_code="CYBERSEC20")
        assert res1.status == "FAIL"

        # Subsequent direct scenario run with the now-exhausted coupon returns INCONCLUSIVE
        res2 = scenario.run("vulnerable", coupon_code="CYBERSEC20")
        assert res2.status == "INCONCLUSIVE"
        assert "already exhausted, inactive, or previously redeemed" in res2.actual_behavior
        assert "Target coupon must be unused" in (res2.error or "")

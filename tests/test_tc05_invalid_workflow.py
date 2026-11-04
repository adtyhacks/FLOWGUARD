"""Behavioral, invariant, and failure-path tests for the TC-05 Invalid Workflow scenario."""

from __future__ import annotations

import fnmatch
import json
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest
import requests

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.scenarios.tc05_invalid_workflow import TC05InvalidWorkflowScenario
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
                    if override_method == method and (fnmatch.fnmatch(path, pattern) or (pattern.endswith("*") and path.startswith(pattern[:-1])))
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

    return TC05InvalidWorkflowScenario(client, timeout=2.0), calls, session_factory


@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [
        ("vulnerable", "FAIL"),
        ("secure", "PASS"),
    ],
)
def test_tc05_invalid_workflow_against_real_shopzone_routes(
    client, mode: str, expected_status: str
) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode=mode)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(mode)

    assert result.status == expected_status

    if mode == "vulnerable":
        assert "Vulnerable mode permitted multiple invalid workflow transitions" in result.actual_behavior
        unpaid_ev = next(item for item in result.evidence if item.observed_state["step"] == "attempt_unpaid_confirmation")
        assert unpaid_ev.response_summary["status_code"] == 200

        resurrect_ev = next(item for item in result.evidence if item.observed_state["step"] == "attempt_cancelled_order_confirmation")
        assert resurrect_ev.response_summary["status_code"] == 200
    else:
        assert "Secure mode strictly enforced finite state machine invariants" in result.actual_behavior
        unpaid_ev = next(item for item in result.evidence if item.observed_state["step"] == "attempt_unpaid_confirmation")
        assert unpaid_ev.response_summary["status_code"] == 400

        repeat_cancel_ev = next(item for item in result.evidence if item.observed_state["step"] == "attempt_repeated_cancellation")
        assert repeat_cancel_ev.response_summary["status_code"] == 400

        resurrect_ev = next(item for item in result.evidence if item.observed_state["step"] == "attempt_cancelled_order_confirmation")
        assert resurrect_ev.response_summary["status_code"] == 400

        # Legitimate cancellation succeeded
        valid_cancel_ev = next(item for item in result.evidence if item.observed_state["step"] == "legitimate_order_cancellation")
        assert valid_cancel_ev.response_summary["status_code"] == 200

    call_paths = [call["path"] for call in calls]
    assert any(path.endswith("/orders/checkout") for path in call_paths)
    assert any(path.endswith("/auth/logout") for path in call_paths)


def test_tc05_missing_admin_key_is_inconclusive_without_requests(client) -> None:
    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=None,
    )
    flowguard_client = FlowGuardClient(config)
    scenario = TC05InvalidWorkflowScenario(flowguard_client, timeout=1.0)
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
def test_tc05_rejects_invalid_mode_without_requests(client, invalid_mode: str) -> None:
    scenario, calls, session_factory = _scenario_for(client)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run(invalid_mode)

    assert result.status == "ERROR"
    assert "mode must be vulnerable or secure" in (result.error or "")
    assert len(calls) == 0


def test_tc05_user_registration_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/auth/register"): TransportResponse(500, {"error": "DB Error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Registration failed for synthetic user" in result.actual_behavior


def test_tc05_user_login_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/auth/login"): TransportResponse(401, {"error": "Invalid credentials"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Authentication failed for synthetic user" in result.actual_behavior


def test_tc05_product_catalog_failure_is_error(client) -> None:
    overrides = {
        ("GET", "/secure/api/products"): TransportResponse(500, {"error": "Server error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Product catalog could not be retrieved" in result.actual_behavior


def test_tc05_cart_creation_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/cart/items"): TransportResponse(400, {"error": "Bad Request"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Cart creation failed for Order 1" in result.actual_behavior


def test_tc05_checkout_order1_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/orders/checkout"): TransportResponse(500, {"error": "Checkout crash"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Checkout failed for Order 1" in result.actual_behavior


def test_tc05_order1_initial_ground_truth_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(404, {"found": False, "order": None}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Order 1 initial state is invalid in ground truth" in result.actual_behavior


def test_tc05_order1_initial_ground_truth_auth_failure_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(401, {"error": "Unauthorized"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Admin verification rejected credentials" in result.actual_behavior


def test_tc05_order1_unexpected_payment_record_is_inconclusive(client) -> None:
    overrides = {
        ("GET", "/api/admin/verify/payment/secure/*"): TransportResponse(200, {"found": True, "payment": {"id": 1}}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"
    assert "Unexpected payment record found for Order 1" in result.actual_behavior


def test_tc05_unpaid_confirmation_transport_failure_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/orders/*/confirm"): requests.Timeout("Network timeout"),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Unpaid confirmation request failed at transport layer" in result.actual_behavior


def test_tc05_legitimate_cancellation_failure_is_error(client) -> None:
    cancel_calls = [0]
    calls: list[dict[str, object]] = []

    def custom_session_factory():
        class CustomSession(FlaskRequestsSession):
            def request(self, *args, **kwargs):
                parsed = urlsplit(kwargs.get("url"))
                if kwargs.get("method") == "POST" and parsed.path.endswith("/cancel"):
                    cancel_calls[0] += 1
                    if cancel_calls[0] == 1:
                        # Fail the legitimate cancellation
                        self.calls.append({"method": "POST", "path": parsed.path})
                        return TransportResponse(500, {"error": "Server error during cancellation"})
                return super().request(*args, **kwargs)

        return CustomSession(client, calls)

    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    flowguard_client = FlowGuardClient(config)
    scenario_inst = TC05InvalidWorkflowScenario(flowguard_client, timeout=2.0)

    with patch("requests.Session", side_effect=custom_session_factory):
        result = scenario_inst.run("secure")

    assert result.status == "ERROR"
    assert "Legitimate cancellation of pending Order 2 failed" in result.actual_behavior


def test_tc05_repeated_cancellation_transport_failure_is_error(client) -> None:
    cancel_calls = [0]
    calls: list[dict[str, object]] = []

    def custom_session_factory():
        class CustomSession(FlaskRequestsSession):
            def request(self, *args, **kwargs):
                parsed = urlsplit(kwargs.get("url"))
                if kwargs.get("method") == "POST" and parsed.path.endswith("/cancel"):
                    cancel_calls[0] += 1
                    if cancel_calls[0] == 2:
                        # Fail the repeated cancellation with transport exception
                        self.calls.append({"method": "POST", "path": parsed.path})
                        raise requests.Timeout("Timeout on repeat cancel")
                return super().request(*args, **kwargs)

        return CustomSession(client, calls)

    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    flowguard_client = FlowGuardClient(config)
    scenario_inst = TC05InvalidWorkflowScenario(flowguard_client, timeout=2.0)

    with patch("requests.Session", side_effect=custom_session_factory):
        result = scenario_inst.run("secure")

    assert result.status == "ERROR"
    assert "Repeated cancellation request failed at transport layer" in result.actual_behavior


def test_tc05_resurrection_confirmation_transport_failure_is_error(client) -> None:
    confirm_calls = [0]
    calls: list[dict[str, object]] = []

    def custom_session_factory():
        class CustomSession(FlaskRequestsSession):
            def request(self, *args, **kwargs):
                parsed = urlsplit(kwargs.get("url"))
                if kwargs.get("method") == "POST" and parsed.path.endswith("/confirm"):
                    confirm_calls[0] += 1
                    if confirm_calls[0] == 3:  # 1st: ord1, 2nd: ord1 repeat, 3rd: ord2 resurrect
                        self.calls.append({"method": "POST", "path": parsed.path})
                        raise requests.Timeout("Timeout on resurrection confirm")
                return super().request(*args, **kwargs)

        return CustomSession(client, calls)

    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    flowguard_client = FlowGuardClient(config)
    scenario_inst = TC05InvalidWorkflowScenario(flowguard_client, timeout=2.0)

    with patch("requests.Session", side_effect=custom_session_factory):
        result = scenario_inst.run("secure")

    assert result.status == "ERROR"
    assert "Resurrection confirmation request failed at transport layer" in result.actual_behavior


def test_tc05_vulnerable_mode_unexpected_rejection_is_inconclusive(client) -> None:
    overrides = {
        ("POST", "/vulnerable/api/orders/*/confirm"): TransportResponse(400, {"error": "Bad Request", "message": "Cannot confirm"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="vulnerable", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("vulnerable")

    assert result.status == "INCONCLUSIVE"
    assert "Vulnerable mode did not exhibit the expected state machine bypasses" in result.actual_behavior


def test_tc05_secure_mode_unpaid_confirm_not_rejected_fails(client) -> None:
    confirm_calls = [0]
    calls: list[dict[str, object]] = []

    def custom_session_factory():
        class CustomSession(FlaskRequestsSession):
            def request(self, *args, **kwargs):
                parsed = urlsplit(kwargs.get("url"))
                if kwargs.get("method") == "POST" and parsed.path.endswith("/confirm"):
                    confirm_calls[0] += 1
                    if confirm_calls[0] == 1:
                        # Allow unpaid confirmation through with 200
                        self.calls.append({"method": "POST", "path": parsed.path})
                        return TransportResponse(200, {"message": "Order confirmed", "order": {"id": 1, "status": "CONFIRMED"}})
                return super().request(*args, **kwargs)

        return CustomSession(client, calls)

    config = FlowGuardConfig(
        base_url="http://127.0.0.1:5000",
        target_mode="secure",
        admin_key=TestingConfig.ADMIN_KEY,
    )
    flowguard_client = FlowGuardClient(config)
    scenario_inst = TC05InvalidWorkflowScenario(flowguard_client, timeout=2.0)

    with patch("requests.Session", side_effect=custom_session_factory):
        result = scenario_inst.run("secure")

    assert result.status == "FAIL"
    assert "Secure mode permitted an illegal workflow transition" in result.actual_behavior


def test_tc05_secure_mode_unexpected_error_status_is_error(client) -> None:
    overrides = {
        ("POST", "/secure/api/orders/*/confirm"): TransportResponse(500, {"error": "Server error"}),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "ERROR"
    assert "Secure mode returned unexpected responses during invalid transition attempts" in result.actual_behavior


def test_tc05_evidence_redacts_credentials_and_tokens(client) -> None:
    scenario, calls, session_factory = _scenario_for(client, mode="secure")

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    for item in result.evidence:
        serialized = json.dumps(item.to_dict())
        assert TestingConfig.ADMIN_KEY not in serialized
        assert "password" not in serialized or '"password": "[REDACTED]"' in serialized or '"password": "[SECRET"' in serialized


def test_tc05_global_admin_header_is_only_sent_to_verification_endpoints(client) -> None:
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
        {"found": True, "order": {"id": True, "user_id": 1, "status": "PENDING_PAYMENT"}},  # bool id
        {"found": True, "order": {"id": 1, "user_id": False, "status": "PENDING_PAYMENT"}},  # bool user_id
        {"found": True, "order": {"id": "1", "user_id": 1, "status": "PENDING_PAYMENT"}},  # string id
        {"found": True, "order": {"id": -1, "user_id": 1, "status": "PENDING_PAYMENT"}},  # negative id
        {"found": False, "order": None},  # found False
        {"found": True, "order": None},  # missing order dict
        {"found": True, "order": {"id": 1, "user_id": 1, "status": ""}},  # empty status
    ],
)
def test_tc05_admin_order_malformed_state_is_inconclusive(client, malformed_payload: dict) -> None:
    overrides = {
        ("GET", "/api/admin/verify/order/secure/*"): TransportResponse(200, malformed_payload),
    }
    scenario, calls, session_factory = _scenario_for(client, mode="secure", overrides=overrides)

    with patch("requests.Session", side_effect=session_factory):
        result = scenario.run("secure")

    assert result.status == "INCONCLUSIVE"

"""Unit tests for the FLOWGUARD synthetic user management and auth module."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch

import pytest

from flowguard.auth import AuthSession, SyntheticUserManager
from flowguard.client import FlowGuardClient
from flowguard.evidence import capture_evidence
from flowguard.schemas import ApiResult


class FakeResponse:
    """Minimal fake response for mocked HTTP calls."""

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


def test_synthetic_username_generation() -> None:
    """Usernames are unique, stable, and deterministic in format."""
    manager = SyntheticUserManager()
    username_a = manager.generate_username("scout")
    username_b = manager.generate_username("scout")
    assert username_a.startswith("scout_")
    assert username_a != username_b
    assert "@" not in username_a


def test_synthetic_email_generation() -> None:
    """Emails are unique and follow the lab's controlled local domain."""
    manager = SyntheticUserManager()
    email_a = manager.generate_email("alpha")
    email_b = manager.generate_email("beta")
    assert email_a.endswith("@flowguard.local")
    assert email_b.endswith("@flowguard.local")
    assert email_a != email_b


def test_successful_registration() -> None:
    """A synthetic user can be created via the HTTP registration route."""
    manager = SyntheticUserManager(client=FlowGuardClient())

    def fake_request(*args, **kwargs):
        return FakeResponse(
            201,
            {"message": "User registered successfully", "user": {"id": 42, "username": "alpha_user", "email": "alpha_user@flowguard.local"}},
        )

    with patch("requests.Session.request", side_effect=fake_request):
        user = manager.register_user("alpha_user", "alpha_user@flowguard.local", "StrongPass!123")

    assert user is not None
    assert user.user_id == 42
    assert user.username == "alpha_user"
    assert user.password == "StrongPass!123"
    assert user.token is None


def test_successful_login() -> None:
    """A registered user can authenticate and receive a bearer token."""
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("alice_user", "alice_user@flowguard.local", "StrongPass!123")

    def fake_request(*args, **kwargs):
        url = kwargs.get("url") or (args[1] if len(args) > 1 else "")
        if "/auth/login" in url:
            return FakeResponse(
                200,
                {"message": "Authentication successful", "token": "11111111-2222-3333-4444-555555555555", "user": {"id": 7, "username": "alice_user"}, "expires_at": "2099-11-01T00:00:00Z"},
            )
        return FakeResponse(201, {"message": "User registered successfully", "user": {"id": 7, "username": "alice_user", "email": "alice_user@flowguard.local"}})

    with patch("requests.Session.request", side_effect=fake_request):
        session = manager.login_user(user)

    assert isinstance(session, AuthSession)
    assert session.authenticated is True
    assert session.user.token == "11111111-2222-3333-4444-555555555555"
    assert session.authentication_headers == {"Authorization": "Bearer 11111111-2222-3333-4444-555555555555"}


def test_authentication_failure() -> None:
    """Failed auth returns a non-authenticated session and does not expose credentials."""
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("bad_user", "bad_user@flowguard.local", "WrongPass!123")

    def fake_request(*args, **kwargs):
        return FakeResponse(401, {"error": "Unauthorized", "message": "Invalid username or password."})

    with patch("requests.Session.request", side_effect=fake_request):
        session = manager.login_user(user)

    assert session.authenticated is False
    assert session.user.token is None
    assert session.authentication_headers == {}
    assert "WrongPass!123" not in repr(session)


def test_failed_login_clears_previous_token_and_headers() -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("repeat_login", "repeat_login@flowguard.local", "StrongPass!123")
    login_count = 0

    def fake_request(*args, **kwargs):
        nonlocal login_count
        login_count += 1
        if login_count == 1:
            return FakeResponse(200, {
                "token": "66666666-6666-4666-8666-666666666666",
                "user": {"id": 5, "username": "repeat_login"},
                "expires_at": "2099-11-01T00:00:00Z",
            })
        return FakeResponse(401, {"message": "Invalid username or password."})

    with patch("requests.Session.request", side_effect=fake_request):
        first_session = manager.login_user(user)
        failed_session = manager.login_user(user)

    assert first_session.authenticated is False
    assert failed_session.authenticated is False
    assert user.token is None
    assert user.auth_headers() == {}
    assert manager.get_auth_headers(user.username) == {}


def test_same_username_has_independent_mode_sessions() -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("dual_mode", "dual_mode@flowguard.local", "StrongPass!123")

    def fake_request(*args, **kwargs):
        url = kwargs.get("url", "")
        mode = "vulnerable" if "/vulnerable/" in url else "secure"
        return FakeResponse(200, {
            "token": "77777777-7777-4777-8777-777777777777" if mode == "vulnerable" else "88888888-8888-4888-8888-888888888888",
            "user": {"id": 8, "username": "dual_mode"},
            "expires_at": "2099-11-01T00:00:00Z",
        })

    with patch("requests.Session.request", side_effect=fake_request):
        secure_session = manager.login_user(user, mode="secure")
        vulnerable_session = manager.login_user(user, mode="vulnerable")

    assert secure_session.authenticated is True
    assert vulnerable_session.authenticated is True
    assert manager.get_auth_headers(user.username, mode="secure") == {"Authorization": "Bearer 88888888-8888-4888-8888-888888888888"}
    assert manager.get_auth_headers(user.username, mode="vulnerable") == {"Authorization": "Bearer 77777777-7777-4777-8777-777777777777"}
    assert manager.get_session(user.username, mode="secure") is secure_session
    assert manager.get_session(user.username, mode="vulnerable") is vulnerable_session


@pytest.mark.parametrize("payload", [
    {"token": "valid-token", "user": {"id": 1, "username": "somebody_else"}},
    {"user": {"id": 1, "username": "identity_user"}},
    {"token": "", "user": {"id": 1, "username": "identity_user"}, "expires_at": "2099-11-01T00:00:00Z"},
    {"token": "valid-token", "user": {"id": 1, "username": "identity_user"}, "expires_at": "2000-01-01T00:00:00Z"},
    {"token": "not-a-uuid", "user": {"id": 1, "username": "identity_user"}, "expires_at": "2099-11-01T00:00:00Z"},
])
def test_invalid_login_response_never_authenticates(payload: dict[str, object]) -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("identity_user", "identity_user@flowguard.local", "StrongPass!123")

    with patch("requests.Session.request", return_value=FakeResponse(200, payload)):
        session = manager.login_user(user)

    assert session.authenticated is False
    assert session.authentication_headers == {}
    assert user.auth_headers() == {}
    assert manager.get_auth_headers(user.username) == {}


@pytest.mark.parametrize("expiry", [
    None,
    "missing",
    "not-a-date",
    "2099-01-01T00:00:00",
    "2000-01-01T00:00:00Z",
])
def test_login_rejects_invalid_or_missing_expiry(expiry: object) -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("no_expiry", "no_expiry@flowguard.local", "StrongPass!123")
    payload: dict[str, object] = {"token": "11111111-2222-3333-4444-555555555555", "user": {"username": "no_expiry"}}
    if expiry != "missing":
        payload["expires_at"] = expiry
    with patch("requests.Session.request", return_value=FakeResponse(
        200, payload
    )):
        session = manager.login_user(user)
    assert session.authenticated is False
    assert session.authentication_headers == {}
    assert user.auth_headers() == {}


def test_session_becomes_unauthenticated_after_token_expiry() -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("expiring_user", "expiring_user@flowguard.local", "StrongPass!123")
    with patch("requests.Session.request", return_value=FakeResponse(200, {
        "token": "99999999-9999-4999-8999-999999999999",
        "user": {"username": "expiring_user"},
        "expires_at": "2099-11-01T00:00:00Z",
    })):
        session = manager.login_user(user)

    assert session.authenticated is True
    user._mode_expiries["secure"] = __import__("datetime").datetime(2000, 1, 1, tzinfo=__import__("datetime").timezone.utc)
    assert "authenticated=False" in repr(session)
    assert session.authenticated is False
    assert session.authentication_headers == {}


@pytest.mark.parametrize("token,expiry", [
    (None, "2099-01-01T00:00:00Z"),
    ("not-a-uuid", "2099-01-01T00:00:00Z"),
    ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", None),
    ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "not-a-date"),
    ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", datetime(2099, 1, 1)),
    ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "2000-01-01T00:00:00Z"),
])
def test_synthetic_user_set_token_rejects_invalid_uuid_or_expiry(token: object, expiry: object) -> None:
    user = SyntheticUserManager().create_user("central_token", "central_token@flowguard.local", "StrongPass!123")
    with pytest.raises(ValueError):
        user.set_token("secure", token, expiry)  # type: ignore[arg-type]
    assert user.auth_headers("secure") == {}


def test_synthetic_user_set_token_accepts_uuid_with_future_aware_expiry() -> None:
    user = SyntheticUserManager().create_user("central_valid", "central_valid@flowguard.local", "StrongPass!123")
    token = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    user.set_token("secure", token, datetime.now(timezone.utc) + timedelta(hours=1))
    assert user.auth_headers("secure") == {"Authorization": f"Bearer {token}"}


def test_auth_session_rejects_manually_supplied_invalid_or_mismatched_headers() -> None:
    user = SyntheticUserManager().create_user("manual_session", "manual_session@flowguard.local", "StrongPass!123")
    invalid = AuthSession(
        user,
        authenticated=True,
        authentication_headers={"Authorization": "Bearer invalid-token"},
        session_metadata={"mode": "secure"},
    )
    assert invalid.authenticated is False

    token = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    user.set_token("secure", token, datetime.now(timezone.utc) + timedelta(hours=1))
    mismatched = AuthSession(
        user,
        authenticated=True,
        authentication_headers={"Authorization": "Bearer another-token"},
        session_metadata={"mode": "secure"},
    )
    assert mismatched.authenticated is False
    assert mismatched.authentication_headers == {}


def test_logout_without_token_does_not_claim_invalidation() -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("no_logout_token", "no_logout_token@flowguard.local", "StrongPass!123")
    session = AuthSession(user=user, authenticated=False, session_metadata={"mode": "secure"})
    manager._sessions[(user.username, "secure")] = session

    with patch.object(manager.client, "post") as post:
        assert manager.logout_user(user) is False

    post.assert_not_called()
    assert "logged_out" not in session.session_metadata
    assert "server_invalidation_confirmed" not in session.session_metadata


def test_failed_logout_clears_local_token_but_does_not_claim_server_invalidation() -> None:
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("failed_logout", "failed_logout@flowguard.local", "StrongPass!123")
    session = AuthSession(
        user=user,
        authenticated=True,
        authentication_headers={"Authorization": "Bearer local-token"},
    )
    user.set_token("secure", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", datetime.now(timezone.utc) + timedelta(hours=1))
    session.authentication_headers = {"Authorization": "Bearer cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
    manager._sessions[(user.username, "secure")] = session

    with patch.object(manager.client, "post", return_value=ApiResult(
        status_code=503,
        ok=False,
        payload={"message": "unavailable"},
        elapsed_ms=1,
        request_method="POST",
        endpoint="/secure/api/auth/logout",
        error="unavailable",
    )) as post:
        assert manager.logout_user(user) is False

    post.assert_called_once_with("/auth/logout", mode="secure", headers={"Authorization": "Bearer cccccccc-cccc-4ccc-8ccc-cccccccccccc"})
    assert user.auth_headers("secure") == {}
    assert session.authenticated is False
    assert session.authentication_headers == {}
    assert session.session_metadata["server_invalidation_confirmed"] is False


def test_duplicate_synthetic_username_is_rejected_without_overwrite() -> None:
    manager = SyntheticUserManager()
    original = manager.create_user("duplicate_user", "duplicate@flowguard.local", "StrongPass!123")
    with pytest.raises(ValueError, match="already exists"):
        manager.create_user("duplicate_user", "other@flowguard.local", "AnotherPass!456")
    assert manager.list_users() == [original]


@pytest.mark.parametrize("length", [0, -1, 5, 11, 257, True, 18.5])
def test_generated_password_rejects_invalid_lengths(length: object) -> None:
    with pytest.raises(ValueError):
        SyntheticUserManager().generate_password(length)  # type: ignore[arg-type]


@pytest.mark.parametrize("password", ["", "short", 123])
def test_create_user_rejects_invalid_password(password: object) -> None:
    with pytest.raises(ValueError):
        SyntheticUserManager().create_user("bad_password", "bad@flowguard.local", password)  # type: ignore[arg-type]


def test_registration_conflict_handling() -> None:
    """A duplicate username or email returns None and preserves the manager state."""
    manager = SyntheticUserManager(client=FlowGuardClient())

    def fake_request(*args, **kwargs):
        return FakeResponse(409, {"error": "Conflict", "message": "User with this username or email already exists."})

    with patch("requests.Session.request", side_effect=fake_request):
        user = manager.register_user("taken_user", "taken_user@flowguard.local", "StrongPass!123")

    assert user is None
    assert len(manager.list_users()) == 0


def test_two_users_receive_independent_sessions() -> None:
    """Each synthetic user gets a distinct in-memory session and bearer token."""
    manager = SyntheticUserManager(client=FlowGuardClient())
    user_a = manager.create_user("user_a", "user_a@flowguard.local", "StrongPass!123")
    user_b = manager.create_user("user_b", "user_b@flowguard.local", "AnotherPass!456")

    def fake_request(*args, **kwargs):
        url = kwargs.get("url") or (args[1] if len(args) > 1 else "")
        payload = kwargs.get("json") or {}
        username = payload.get("username")
        if "/auth/login" in url:
            if username == "user_a":
                return FakeResponse(200, {"token": "11111111-1111-4111-8111-111111111111", "user": {"id": 10, "username": "user_a"}, "expires_at": "2099-11-01T00:00:00Z"})
            if username == "user_b":
                return FakeResponse(200, {"token": "22222222-2222-4222-8222-222222222222", "user": {"id": 11, "username": "user_b"}, "expires_at": "2099-11-01T00:00:00Z"})
        return FakeResponse(201, {"user": {"id": 10 if username == "user_a" else 11, "username": payload.get("username"), "email": payload.get("email")}})

    with patch("requests.Session.request", side_effect=fake_request):
        session_a = manager.login_user(user_a)
        session_b = manager.login_user(user_b)

    assert session_a.authenticated is True
    assert session_b.authenticated is True
    assert session_a.user.token != session_b.user.token
    assert session_a.authentication_headers["Authorization"] != session_b.authentication_headers["Authorization"]


def test_bearer_token_isolation() -> None:
    """A user can only access its own bearer token."""
    manager = SyntheticUserManager(client=FlowGuardClient())
    user_a = manager.create_user("token_a", "token_a@flowguard.local", "StrongPass!123")
    user_b = manager.create_user("token_b", "token_b@flowguard.local", "AnotherPass!456")

    def fake_request(*args, **kwargs):
        payload = kwargs.get("json") or {}
        username = payload.get("username")
        if username == "token_a":
            return FakeResponse(200, {"token": "33333333-3333-4333-8333-333333333333", "user": {"id": 1, "username": "token_a"}, "expires_at": "2099-11-01T00:00:00Z"})
        if username == "token_b":
            return FakeResponse(200, {"token": "44444444-4444-4444-8444-444444444444", "user": {"id": 2, "username": "token_b"}, "expires_at": "2099-11-01T00:00:00Z"})
        return FakeResponse(201, {"user": {"id": 99, "username": username}})

    with patch("requests.Session.request", side_effect=fake_request):
        session_a = manager.login_user(user_a)
        session_b = manager.login_user(user_b)

    assert session_a.authentication_headers["Authorization"] == "Bearer 33333333-3333-4333-8333-333333333333"
    assert session_b.authentication_headers["Authorization"] == "Bearer 44444444-4444-4444-8444-444444444444"
    assert session_a.authentication_headers != session_b.authentication_headers


def test_logout_behavior() -> None:
    """Logout invalidates the in-memory bearer token and marks the session inactive."""
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("logout_user", "logout_user@flowguard.local", "StrongPass!123")

    def fake_request(*args, **kwargs):
        url = kwargs.get("url") or (args[1] if len(args) > 1 else "")
        if "/auth/login" in url:
            return FakeResponse(200, {"token": "55555555-5555-4555-8555-555555555555", "user": {"id": 9, "username": "logout_user"}, "expires_at": "2099-11-01T00:00:00Z"})
        if "/auth/logout" in url:
            return FakeResponse(200, {"message": "Successfully logged out"})
        return FakeResponse(201, {"user": {"id": 9, "username": "logout_user", "email": "logout_user@flowguard.local"}})

    with patch("requests.Session.request", side_effect=fake_request):
        session = manager.login_user(user)
        result = manager.logout_user(user)

    assert session.authenticated is False
    assert result is True
    assert user.token is None
    assert manager.get_auth_headers(user.username) == {}


def test_no_credential_leakage_into_logs_or_evidence() -> None:
    """Credentials and bearer tokens are never exposed through repr or evidence capture."""
    manager = SyntheticUserManager(client=FlowGuardClient())
    user = manager.create_user("secret_user", "secret_user@flowguard.local", "UltraSecretPass!123")
    user.set_token(
        "secure",
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        datetime.now(timezone.utc) + timedelta(hours=1),
    )
    session = AuthSession(
        user=user,
        authenticated=True,
        authentication_headers={"Authorization": "Bearer dddddddd-dddd-4ddd-8ddd-dddddddddddd"},
        session_metadata={"mode": "secure", "status": "authenticated"},
    )

    assert "UltraSecretPass!123" not in repr(user)
    assert "dddddddd-dddd-4ddd-8ddd-dddddddddddd" not in repr(user)
    assert "dddddddd-dddd-4ddd-8ddd-dddddddddddd" not in repr(session)
    assert "UltraSecretPass!123" not in str(user.to_dict())
    assert "secret-bearer-token" not in str(session.to_dict())
    with pytest.raises(TypeError):
        asdict(user)
    with pytest.raises(TypeError):
        asdict(session)

    evidence = capture_evidence(
        scenario_id="TC-99",
        endpoint="/sec/api/auth/login",
        request_method="POST",
        request_payload={"username": user.username, "password": user.password},
        request_headers=session.authentication_headers,
        response_payload={"token": user.token, "user": {"username": user.username}},
        response_status_code=200,
        observed_state={"auth": "ok"},
    )

    serialized = evidence.to_dict()
    assert serialized["request_summary"]["payload"]["password"] == "***REDACTED***"
    assert serialized["request_summary"]["headers"]["Authorization"] == "***REDACTED***"
    assert serialized["response_summary"]["payload"]["token"] == "***REDACTED***"


def test_api_result_repr_redacts_credentials_and_bearer_values() -> None:
    result = ApiResult(
        status_code=401,
        ok=False,
        payload={
            "password": "hidden-password",
            "token": "payload-token-secret",
            "message": "Bearer actual-secret-token",
            "nested": {"api_key": "hidden-api-key", "cookie": "hidden-cookie"},
        },
        elapsed_ms=1,
        request_method="POST",
        endpoint="/auth/login?token=url-secret",
        error="authorization: Bearer error-secret",
    )
    rendered = repr(result)
    for secret in ("hidden-password", "actual-secret-token", "hidden-api-key", "hidden-cookie", "url-secret", "error-secret"):
        assert secret not in rendered
    assert result.to_dict()["payload"]["token"] == "***REDACTED***"
    with pytest.raises(TypeError):
        asdict(result)


def test_request_exception_and_evidence_redact_embedded_secrets() -> None:
    client = FlowGuardClient()
    exception = __import__("requests").RequestException(
        "password=exception-password Authorization: Bearer exception-token ADMIN_KEY=admin-secret"
    )
    with patch("requests.Session.request", side_effect=exception):
        result = client.post("/auth/login", json={"password": "request-password"})

    assert "exception-password" not in repr(result)
    assert "exception-token" not in repr(result)
    assert "admin-secret" not in repr(result)
    assert "request-password" not in repr(result)

    evidence = capture_evidence(
        scenario_id="AUTH-REDACTION",
        endpoint="/auth/login?api_key=url-key",
        request_method="POST",
        request_payload={"password": "evidence-password"},
        request_headers={"Cookie": "evidence-cookie", "X-Api-Key": "evidence-api-key"},
        response_payload={"message": "Bearer evidence-token ADMIN_KEY=evidence-admin"},
        response_status_code=500,
        error="authorization: Bearer evidence-error-token password=evidence-error-password",
    )
    rendered_evidence = repr(evidence.to_dict())
    for secret in (
        "url-key", "evidence-password", "evidence-cookie", "evidence-api-key",
        "evidence-token", "evidence-admin", "evidence-error-token", "evidence-error-password",
    ):
        assert secret not in rendered_evidence


def test_http_error_response_redacts_secret_bearing_diagnostics() -> None:
    client = FlowGuardClient()
    response = FakeResponse(401, {
        "message": 'password is response-secret; Authorization: Bearer "response-token"; ADMIN_KEY=response-admin',
    })
    with patch("requests.Session.request", return_value=response):
        result = client.get("/products")

    rendered = repr(result)
    for secret in ("response-secret", "response-token", "response-admin"):
        assert secret not in rendered
    assert result.error is not None
    for secret in ("response-secret", "response-token", "response-admin"):
        assert secret not in result.error


def test_evidence_redacts_values_added_after_capture() -> None:
    evidence = capture_evidence(
        scenario_id="AUTH-LATE-REDACTION",
        endpoint="/auth/me",
        request_method="GET",
    )
    evidence.response_summary["payload"] = {"message": "Bearer late-added-token"}
    assert "late-added-token" not in repr(evidence)
    assert "late-added-token" not in str(evidence.to_dict())
    with pytest.raises(TypeError):
        asdict(evidence)


def test_redaction_handles_quoted_natural_language_urls_and_nested_values() -> None:
    from flowguard.redaction import redact_text, sanitize_value

    cases = (
        ('Authorization: Bearer "quoted-token"', ("quoted-token",)),
        ("password is natural-secret", ("natural-secret",)),
        ("PASSWORD=upper-secret", ("upper-secret",)),
        ("session_token: session-secret", ("session-secret",)),
        ("ADMIN_KEY=admin-secret; api-key=api-secret; cookie=cookie-secret", ("admin-secret", "api-secret", "cookie-secret")),
        ("https://user:pass@localhost/path?token=query-secret&safe=value", ("user:pass", "query-secret")),
        ("password was was-secret", ("was-secret",)),
        ("password contains contains-secret", ("contains-secret",)),
        ("token is token-secret", ("token-secret",)),
        ("API key was api-secret", ("api-secret",)),
        ("cookie contains cookie-secret", ("cookie-secret",)),
    )
    for message, secrets in cases:
        cleaned = redact_text(message)
        for secret in secrets:
            assert secret not in cleaned
    assert redact_text("invalid bearer token") == "invalid bearer token"

    nested = sanitize_value({"PaSsWoRd": "nested-secret", "items": [{"X-API-Key": "nested-api"}, {"Set_Cookie": "nested-cookie"}]})
    assert nested["PaSsWoRd"] == "***REDACTED***"
    assert nested["items"][0]["X-API-Key"] == "***REDACTED***"
    assert nested["items"][1]["Set_Cookie"] == "***REDACTED***"


def test_generic_dataclass_serialization_cannot_traverse_secret_bearing_results() -> None:
    from dataclasses import is_dataclass
    from flowguard.schemas import AssessmentSummary, Finding, ScenarioResult

    scenario = ScenarioResult("AUTH", "Auth", "ERROR", "expected", "actual", error="password is scenario-secret")
    finding = Finding("F1", "AUTH", "title", "high", "api_key: description-secret", "impact", "password was remediation-secret")
    summary = AssessmentSummary("a", "localhost", "secure", scenario_results=[scenario], findings=[finding])

    assert not is_dataclass(scenario)
    assert not is_dataclass(finding)
    with pytest.raises(TypeError):
        asdict(scenario)
    with pytest.raises(TypeError):
        asdict(finding)
    generic_nested = asdict(summary)
    assert generic_nested["scenario_results"][0].error == "password is ***REDACTED***"
    assert generic_nested["findings"][0].description == "api_key: ***REDACTED***"
    for secret in ("scenario-secret", "description-secret", "remediation-secret"):
        assert secret not in repr(generic_nested)
        assert secret not in json.dumps(summary.to_dict())

    scenario.error = "token contains reassigned-secret"
    finding.description = "cookie contains reassigned-cookie"
    assert "reassigned-secret" not in repr(scenario)
    assert "reassigned-cookie" not in repr(finding)
    assert "reassigned-secret" not in json.dumps(summary.to_dict())


def test_assessment_error_serialization_redacts_free_form_secrets() -> None:
    from flowguard.schemas import AssessmentSummary, ScenarioResult

    scenario = ScenarioResult("AUTH", "Auth", "ERROR", "expected", "actual", error="password is assessment-secret")
    summary = AssessmentSummary("assessment", "localhost", "secure", scenario_results=[scenario])
    assert "assessment-secret" not in repr(scenario)
    assert "assessment-secret" not in str(scenario.to_dict())
    assert "assessment-secret" not in str(summary.to_dict())

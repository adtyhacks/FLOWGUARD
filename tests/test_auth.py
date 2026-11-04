"""Tests for synthetic user authentication, scrypt hashing, and UUID tokens."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from shopzone.config import TestingConfig
from shopzone.db import get_session_factory
from shopzone.models import User, UserToken


def test_registration_validation(client):
    """Test user registration constraints and error handling."""
    # Missing username
    res = client.post("/sec/api/auth/register", json={
        "email": "test@flowguard.local",
        "password": "Password123!"
    })
    assert res.status_code == 400
    
    # Password too short (< 6 chars)
    res = client.post("/sec/api/auth/register", json={
        "username": "shortpass_user",
        "email": "short@flowguard.local",
        "password": "123"
    })
    assert res.status_code == 400
    
    # Valid registration
    res = client.post("/sec/api/auth/register", json={
        "username": "valid_user",
        "email": "valid@flowguard.local",
        "password": "SecurePassword123!"
    })
    assert res.status_code == 201
    data = res.get_json()
    assert "user" in data
    assert data["user"]["username"] == "valid_user"
    assert "password" not in data["user"]
    assert "password_hash" not in data["user"]
    
    # Duplicate username should be rejected
    res_dup = client.post("/sec/api/auth/register", json={
        "username": "valid_user",
        "email": "another@flowguard.local",
        "password": "SecurePassword123!"
    })
    assert res_dup.status_code == 409


def test_password_hashed_with_scrypt(app, client):
    """Verify that user passwords are stored using Werkzeug scrypt and never in plaintext."""
    client.post("/sec/api/auth/register", json={
        "username": "scrypt_user",
        "email": "scrypt@flowguard.local",
        "password": "PlainTextSecretPassword!"
    })
    
    session_factory = get_session_factory("secure", TestingConfig)
    session = session_factory()
    try:
        user = session.query(User).filter_by(username="scrypt_user").first()
        assert user is not None
        assert user.password_hash != "PlainTextSecretPassword!"
        # Werkzeug scrypt hashes start with 'scrypt:'
        assert user.password_hash.startswith("scrypt:"), f"Expected scrypt hash prefix, got {user.password_hash[:20]}"
        assert user.check_password("PlainTextSecretPassword!") is True
        assert user.check_password("WrongPassword") is False
    finally:
        session.close()


def test_login_and_token_generation(client):
    """Verify successful login returns a valid UUID token."""
    client.post("/sec/api/auth/register", json={
        "username": "login_user",
        "email": "login@flowguard.local",
        "password": "ValidPassword123!"
    })
    
    # Bad credentials
    bad_login = client.post("/sec/api/auth/login", json={
        "username": "login_user",
        "password": "IncorrectPassword"
    })
    assert bad_login.status_code == 401
    
    # Correct credentials
    login_res = client.post("/sec/api/auth/login", json={
        "username": "login_user",
        "password": "ValidPassword123!"
    })
    assert login_res.status_code == 200
    data = login_res.get_json()
    assert "token" in data
    assert len(data["token"]) == 36  # Standard UUID length
    assert "expires_at" in data


def test_require_auth_middleware(client):
    """Verify @require_auth decorator behavior under various token conditions."""
    # 1. Register & login
    client.post("/sec/api/auth/register", json={
        "username": "middleware_user",
        "email": "middleware@flowguard.local",
        "password": "ValidPassword123!"
    })
    login_res = client.post("/sec/api/auth/login", json={
        "username": "middleware_user",
        "password": "ValidPassword123!"
    })
    token = login_res.get_json()["token"]
    
    # 2. Access /auth/me with valid token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/sec/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.get_json()["user"]["username"] == "middleware_user"
    
    # 3. Access without token header
    no_token = client.get("/sec/api/auth/me")
    assert no_token.status_code == 401
    
    # 4. Access with malformed token header
    malformed = client.get("/sec/api/auth/me", headers={"Authorization": "InvalidScheme 12345"})
    assert malformed.status_code == 401
    
    # 5. Access with non-existent token
    fake_token = client.get("/sec/api/auth/me", headers={"Authorization": "Bearer 00000000-0000-0000-0000-000000000000"})
    assert fake_token.status_code == 401


def test_token_expiration_and_revocation(app, client):
    """Verify expired and revoked tokens are rejected."""
    client.post("/sec/api/auth/register", json={
        "username": "expiry_user",
        "email": "expiry@flowguard.local",
        "password": "ValidPassword123!"
    })
    login_res = client.post("/sec/api/auth/login", json={
        "username": "expiry_user",
        "password": "ValidPassword123!"
    })
    token = login_res.get_json()["token"]
    
    # 1. Test revocation via logout
    headers = {"Authorization": f"Bearer {token}"}
    logout_res = client.post("/sec/api/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    
    # Now token should be rejected as revoked
    post_logout = client.get("/sec/api/auth/me", headers=headers)
    assert post_logout.status_code == 401
    
    # 2. Test expiration directly in database
    session_factory = get_session_factory("secure", TestingConfig)
    session = session_factory()
    try:
        # Create an already-expired token
        user = session.query(User).filter_by(username="expiry_user").first()
        expired_token = UserToken(
            token="11111111-2222-3333-4444-555555555555",
            user_id=user.id,
            created_at=datetime.now(timezone.utc) - timedelta(hours=3),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            is_revoked=False,
        )
        session.add(expired_token)
        session.commit()
    finally:
        session.close()
        
    expired_req = client.get(
        "/sec/api/auth/me",
        headers={"Authorization": "Bearer 11111111-2222-3333-4444-555555555555"}
    )
    assert expired_req.status_code == 401
    assert "expired" in expired_req.get_json()["message"].lower()


def test_logout_reports_failure_when_token_revocation_fails(client):
    client.post("/sec/api/auth/register", json={
        "username": "revoke_failure_user",
        "email": "revoke-failure@flowguard.local",
        "password": "ValidPassword123!",
    })
    login_response = client.post("/sec/api/auth/login", json={
        "username": "revoke_failure_user",
        "password": "ValidPassword123!",
    })
    headers = {"Authorization": f"Bearer {login_response.get_json()['token']}"}

    with patch("shopzone.blueprints.auth_routes.revoke_user_token", return_value=False):
        logout_response = client.post("/sec/api/auth/logout", headers=headers)

    assert logout_response.status_code == 500
    assert logout_response.get_json()["message"] == "Failed to invalidate authentication token."

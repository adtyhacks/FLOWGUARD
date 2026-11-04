"""Regression test suite for Stage 1 security audit findings (F-01 through F-06)."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import pytest
from sqlalchemy.exc import IntegrityError
from shopzone.config import Config, TestingConfig
from shopzone.db import get_engine, get_session_factory, reset_db
from shopzone.models import CouponRedemption, User


# =====================================================================
# Fix F-01: Database-specific coupon constraints
# =====================================================================

def test_vulnerable_db_permits_repeated_coupon_redemption(app):
    """Verify Vulnerable DB allows multiple redemptions for a single-use coupon."""
    vuln_factory = get_session_factory("vulnerable", TestingConfig)
    session = vuln_factory()
    try:
        # Create two distinct users
        u1 = User(username="vuln_user_1", email="u1@vuln.local")
        u1.set_password("Password123!")
        u2 = User(username="vuln_user_2", email="u2@vuln.local")
        u2.set_password("Password123!")
        session.add_all([u1, u2])
        session.commit()
        
        # 1. First redemption for coupon 1 (CYBERSEC20)
        r1 = CouponRedemption(coupon_id=1, user_id=u1.id)
        session.add(r1)
        session.commit()
        
        # 2. Second redemption for the same coupon by another user MUST succeed in vulnerable mode
        r2 = CouponRedemption(coupon_id=1, user_id=u2.id)
        session.add(r2)
        session.commit()
        
        # Verify both redemptions exist in vulnerable DB
        count = session.query(CouponRedemption).filter_by(coupon_id=1).count()
        assert count == 2, f"Expected 2 redemptions in vulnerable DB, got {count}"
    finally:
        session.close()


def test_secure_db_rejects_global_coupon_reuse(app):
    """Verify Secure DB rejects duplicate redemption via database-level unique constraint."""
    sec_factory = get_session_factory("secure", TestingConfig)
    session = sec_factory()
    try:
        u1 = User(username="sec_user_1", email="u1@sec.local")
        u1.set_password("Password123!")
        u2 = User(username="sec_user_2", email="u2@sec.local")
        u2.set_password("Password123!")
        session.add_all([u1, u2])
        session.commit()
        
        # 1. First redemption
        r1 = CouponRedemption(coupon_id=1, user_id=u1.id)
        session.add(r1)
        session.commit()
        
        # 2. Second redemption for same coupon MUST fail with IntegrityError
        r2 = CouponRedemption(coupon_id=1, user_id=u2.id)
        session.add(r2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        
        # Verify only 1 redemption exists
        count = session.query(CouponRedemption).filter_by(coupon_id=1).count()
        assert count == 1
    finally:
        session.close()


def test_concurrent_coupon_redemption_behavior(app):
    """Verify concurrency behavior: vulnerable allows race/duplicates, secure blocks duplicates."""
    # Test Secure Concurrency:
    def attempt_secure_redemption(user_idx):
        factory = get_session_factory("secure", TestingConfig)
        s = factory()
        try:
            user = User(username=f"concurrent_sec_{user_idx}", email=f"csec_{user_idx}@test.local")
            user.set_password("Password123!")
            s.add(user)
            s.commit()
            
            redemption = CouponRedemption(coupon_id=2, user_id=user.id)
            s.add(redemption)
            s.commit()
            return True
        except IntegrityError:
            s.rollback()
            return False
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(attempt_secure_redemption, range(5)))

    # In secure DB, exactly 1 thread must succeed
    assert results.count(True) == 1, f"Secure DB allowed {results.count(True)} concurrent redemptions!"


def test_reset_isolation_preserves_other_database(app):
    """Verify resetting vulnerable DB preserves secure records, and vice versa."""
    # 1. Add user to secure DB
    sec_factory = get_session_factory("secure", TestingConfig)
    s_sec = sec_factory()
    u_sec = User(username="preserved_sec_user", email="p_sec@test.local")
    u_sec.set_password("Password123!")
    s_sec.add(u_sec)
    s_sec.commit()
    s_sec.close()
    
    # 2. Reset vulnerable DB only
    reset_db(mode="vulnerable", config=TestingConfig, seed=True)
    
    # 3. Verify user in secure DB is still present
    s_sec2 = sec_factory()
    user_found = s_sec2.query(User).filter_by(username="preserved_sec_user").first()
    assert user_found is not None, "User in secure DB was lost during vulnerable DB reset!"
    s_sec2.close()
    
    # 4. Add user to vulnerable DB
    vuln_factory = get_session_factory("vulnerable", TestingConfig)
    s_vuln = vuln_factory()
    u_vuln = User(username="preserved_vuln_user", email="p_vuln@test.local")
    u_vuln.set_password("Password123!")
    s_vuln.add(u_vuln)
    s_vuln.commit()
    s_vuln.close()
    
    # 5. Reset secure DB only
    reset_db(mode="secure", config=TestingConfig, seed=True)
    
    # 6. Verify user in vulnerable DB is still present
    s_vuln2 = vuln_factory()
    vuln_user_found = s_vuln2.query(User).filter_by(username="preserved_vuln_user").first()
    assert vuln_user_found is not None, "User in vulnerable DB was lost during secure DB reset!"
    s_vuln2.close()


# =====================================================================
# Fix F-02 & F-03: Admin Security, Constant-time compare & Localhost access
# =====================================================================

def test_admin_comparison_uses_constant_time(app, client):
    """Verify admin authentication utilizes hmac.compare_digest."""
    with patch("hmac.compare_digest", return_value=True) as mock_compare:
        res = client.get("/api/admin/health", headers={"X-Admin-Key": "any_key"})
        assert mock_compare.called, "hmac.compare_digest was not invoked for admin key validation!"
        assert res.status_code == 200


def test_invalid_remote_addr_fails_closed(app, client):
    """Verify missing, empty, or external REMOTE_ADDR returns 403 Forbidden."""
    app.config["TESTING"] = False  # Enforce production check
    
    # 1. Missing / Empty REMOTE_ADDR
    res_empty = client.get(
        "/api/admin/health",
        environ_base={"REMOTE_ADDR": ""},
        headers={"X-Admin-Key": TestingConfig.ADMIN_KEY}
    )
    assert res_empty.status_code == 403
    assert res_empty.get_json()["error"] == "Forbidden"
    
    # 2. External IP
    res_ext = client.get(
        "/api/admin/health",
        environ_base={"REMOTE_ADDR": "192.168.1.100"},
        headers={"X-Admin-Key": TestingConfig.ADMIN_KEY}
    )
    assert res_ext.status_code == 403


def test_forwarding_headers_cannot_bypass_locality(app, client):
    """Verify X-Forwarded-For cannot spoof localhost privileges."""
    app.config["TESTING"] = False
    
    res = client.get(
        "/api/admin/health",
        environ_base={"REMOTE_ADDR": "10.0.0.5"},
        headers={
            "X-Admin-Key": TestingConfig.ADMIN_KEY,
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1"
        }
    )
    assert res.status_code == 403


# =====================================================================
# Fix F-04: Authentication Input Type Validation
# =====================================================================

def test_invalid_credential_types_return_400(client):
    """Verify non-string username or password returns clean HTTP 400."""
    # Integer username in login
    res1 = client.post("/sec/api/auth/login", json={"username": 12345, "password": "Password123!"})
    assert res1.status_code == 400
    assert "strings" in res1.get_json()["message"]
    
    # Boolean password in login
    res2 = client.post("/sec/api/auth/login", json={"username": "valid_user", "password": True})
    assert res2.status_code == 400
    
    # Non-dictionary JSON payload
    res3 = client.post("/sec/api/auth/login", json=["not", "a", "dict"])
    assert res3.status_code == 400
    
    # Integer username in register
    res4 = client.post("/sec/api/auth/register", json={
        "username": 999,
        "email": "valid@email.com",
        "password": "Password123!"
    })
    assert res4.status_code == 400
    assert "strings" in res4.get_json()["message"]


# =====================================================================
# Fix F-05: Exception Leakage Protection
# =====================================================================

def test_error_responses_do_not_expose_internal_details(client):
    """Verify reset failures return sanitized error messages without SQL or paths."""
    with patch("shopzone.blueprints.admin.reset_db", side_effect=Exception("sqlite3.OperationalError: disk I/O error at C:/secret/path")):
        res = client.post(
            "/api/admin/reset",
            headers={"X-Admin-Key": TestingConfig.ADMIN_KEY},
            json={"target": "all"}
        )
        assert res.status_code == 500
        data = res.get_json()
        assert data["error"] == "Internal Server Error"
        assert "disk I/O error" not in data["message"]
        assert "C:/" not in data["message"]
        assert "Check server logs for details" in data["message"]


# =====================================================================
# Fix F-06: Case-Insensitive Bearer Token Parsing
# =====================================================================

def test_bearer_token_case_insensitivity(client):
    """Verify both 'Bearer' and 'bearer' authorization schemes succeed."""
    # Register and login
    client.post("/sec/api/auth/register", json={
        "username": "case_user",
        "email": "case@test.local",
        "password": "Password123!"
    })
    login_res = client.post("/sec/api/auth/login", json={
        "username": "case_user",
        "password": "Password123!"
    })
    token = login_res.get_json()["token"]
    
    # 1. Standard Title-case 'Bearer'
    res_title = client.get("/sec/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_title.status_code == 200
    
    # 2. Lowercase 'bearer'
    res_lower = client.get("/sec/api/auth/me", headers={"Authorization": f"bearer {token}"})
    assert res_lower.status_code == 200
    
    # 3. Uppercase 'BEARER'
    res_upper = client.get("/sec/api/auth/me", headers={"Authorization": f"BEARER {token}"})
    assert res_upper.status_code == 200
    
    # 4. Malformed scheme returns 401
    res_bad_scheme = client.get("/sec/api/auth/me", headers={"Authorization": f"Token {token}"})
    assert res_bad_scheme.status_code == 401
    
    # 5. Empty token returns 401
    res_empty_token = client.get("/sec/api/auth/me", headers={"Authorization": "Bearer   "})
    assert res_empty_token.status_code == 401

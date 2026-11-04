"""Tests for protected admin endpoints, reset mechanisms, and startup validation."""

import pytest
from shopzone.config import TestingConfig, validate_admin_key


def test_admin_key_startup_validation():
    """Verify that empty or None ADMIN_KEY raises a fatal ValueError."""
    with pytest.raises(ValueError) as excinfo:
        validate_admin_key(None)
    assert "ADMIN_KEY" in str(excinfo.value)
    
    with pytest.raises(ValueError) as excinfo:
        validate_admin_key("   ")
    assert "ADMIN_KEY" in str(excinfo.value)
    
    # Valid key passes
    valid = validate_admin_key("my_valid_secret_key")
    assert valid == "my_valid_secret_key"


def test_admin_health_endpoint(client):
    """Verify health endpoint security and database status reporting."""
    # 1. Missing header
    res_no_key = client.get("/api/admin/health")
    assert res_no_key.status_code == 401
    
    # 2. Invalid header
    res_bad_key = client.get("/api/admin/health", headers={"X-Admin-Key": "wrong_key"})
    assert res_bad_key.status_code == 401
    
    # 3. Valid header
    res_valid = client.get("/api/admin/health", headers={"X-Admin-Key": TestingConfig.ADMIN_KEY})
    assert res_valid.status_code == 200
    data = res_valid.get_json()
    assert data["status"] == "healthy"
    assert data["databases"]["vulnerable"] == "online"
    assert data["databases"]["secure"] == "online"


def test_admin_reset_endpoint(client):
    """Verify admin reset re-initializes and re-seeds clean tables."""
    # Add a dummy user first
    client.post("/sec/api/auth/register", json={
        "username": "user_to_be_wiped",
        "email": "wiped@flowguard.local",
        "password": "Password123!"
    })
    
    # Confirm user exists via login
    login_before = client.post("/sec/api/auth/login", json={
        "username": "user_to_be_wiped",
        "password": "Password123!"
    })
    assert login_before.status_code == 200
    
    # Trigger admin reset
    reset_res = client.post(
        "/api/admin/reset",
        headers={"X-Admin-Key": TestingConfig.ADMIN_KEY},
        json={"target": "all"}
    )
    assert reset_res.status_code == 200
    assert "success" in reset_res.get_json()["status"]
    
    # User should now be wiped out
    login_after = client.post("/sec/api/auth/login", json={
        "username": "user_to_be_wiped",
        "password": "Password123!"
    })
    assert login_after.status_code == 401


def test_admin_verify_coupon_endpoint(client):
    """Verify read-only ground-truth coupon verification endpoint."""
    # Query seeded coupon CYBERSEC20
    res = client.get(
        "/api/admin/verify/coupon/secure/CYBERSEC20",
        headers={"X-Admin-Key": TestingConfig.ADMIN_KEY}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["found"] is True
    assert data["coupon"]["code"] == "CYBERSEC20"
    assert data["coupon"]["discount_pct"] == 20
    assert data["coupon"]["max_uses"] == 1
    assert data["coupon"]["times_used"] == 0
    assert data["redemption_count"] == 0


def test_product_catalog_endpoint(client):
    """Verify product catalog endpoints return seeded products in minor units."""
    res = client.get("/api/products")
    assert res.status_code == 200
    data = res.get_json()
    assert "products" in data
    assert data["count"] >= 5
    
    # Check specific product
    prod_res = client.get("/api/products/1")
    assert prod_res.status_code == 200
    prod_data = prod_res.get_json()["product"]
    assert prod_data["id"] == 1
    assert "FlowGuard Security Key Pro" in prod_data["name"]
    assert isinstance(prod_data["price_minor_units"], int)
    assert prod_data["price_minor_units"] == 450000



def test_admin_create_coupon_strict_integer_validation(client):
    """Verify strict integer validation for discount_pct and max_uses, rejecting Booleans."""
    headers = {"X-Admin-Key": TestingConfig.ADMIN_KEY}

    # 1. Rejection of Booleans for discount_pct
    res_true_disc = client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "BOOL_DISC_T", "discount_pct": True, "max_uses": 1},
    )
    assert res_true_disc.status_code == 400
    assert "discount_pct must be an integer" in res_true_disc.get_json()["message"]

    res_false_disc = client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "BOOL_DISC_F", "discount_pct": False, "max_uses": 1},
    )
    assert res_false_disc.status_code == 400
    assert "discount_pct must be an integer" in res_false_disc.get_json()["message"]

    # 2. Rejection of Booleans for max_uses
    res_true_uses = client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "BOOL_USE_T", "discount_pct": 20, "max_uses": True},
    )
    assert res_true_uses.status_code == 400
    assert "max_uses must be a positive integer" in res_true_uses.get_json()["message"]

    res_false_uses = client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "BOOL_USE_F", "discount_pct": 20, "max_uses": False},
    )
    assert res_false_uses.status_code == 400
    assert "max_uses must be a positive integer" in res_false_uses.get_json()["message"]

    # 3. Valid integers accepted
    res_valid = client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "STRICT_INT_OK", "discount_pct": 25, "max_uses": 5},
    )
    assert res_valid.status_code == 201
    assert res_valid.get_json()["status"] == "success"

    verify_res = client.get("/api/admin/verify/coupon/secure/STRICT_INT_OK", headers=headers)
    assert verify_res.status_code == 200
    cpn_data = verify_res.get_json()["coupon"]
    assert cpn_data["discount_pct"] == 25
    assert cpn_data["max_uses"] == 5

    # 4. Out-of-range values rejected
    for invalid_disc in [-5, 0, 101, 200, "20", 20.5, [20]]:
        r = client.post(
            "/api/admin/coupon/secure",
            headers=headers,
            json={"code": f"OOR_DISC_{abs(hash(str(invalid_disc)))}", "discount_pct": invalid_disc, "max_uses": 1},
        )
        assert r.status_code == 400

    for invalid_uses in [-1, 0, "1", 1.5, [1]]:
        r = client.post(
            "/api/admin/coupon/secure",
            headers=headers,
            json={"code": f"OOR_USE_{abs(hash(str(invalid_uses)))}", "discount_pct": 20, "max_uses": invalid_uses},
        )
        assert r.status_code == 400

    # 5. Invalid input does not modify existing coupon records
    # CYBERSEC20 is initialized with discount_pct=20, max_uses=1
    client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "CYBERSEC20", "discount_pct": True, "max_uses": 1},
    )
    client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "CYBERSEC20", "discount_pct": 20, "max_uses": False},
    )
    client.post(
        "/api/admin/coupon/secure",
        headers=headers,
        json={"code": "CYBERSEC20", "discount_pct": 999, "max_uses": 1},
    )

    intact_check = client.get("/api/admin/verify/coupon/secure/CYBERSEC20", headers=headers)
    assert intact_check.status_code == 200
    intact_coupon = intact_check.get_json()["coupon"]
    assert intact_coupon["discount_pct"] == 20
    assert intact_coupon["max_uses"] == 1
    assert intact_coupon["times_used"] == 0

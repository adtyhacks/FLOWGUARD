"""Tests for ShopZone core e-commerce workflows (Cart, Coupons, Checkout, Payment, Orders)."""

import pytest
from shopzone.config import TestingConfig
from shopzone.db import get_session_factory
from shopzone.models import CartItem, Coupon, Order, Payment, Product, User


def _register_and_login(client, mode: str, username: str = "shopper") -> tuple[str, int]:
    """Helper: register and login a test user, returning (auth_header, user_id)."""
    client.post(f"/{mode}/api/auth/register", json={
        "username": username,
        "email": f"{username}@test.local",
        "password": "Password123!",
    })
    res = client.post(f"/{mode}/api/auth/login", json={
        "username": username,
        "password": "Password123!",
    })
    token = res.get_json()["token"]
    user_id = res.get_json()["user"]["id"]
    return {"Authorization": f"Bearer {token}"}, user_id


# =========================================================================
# Part A: Cart Operations
# =========================================================================

@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
def test_cart_lifecycle(client, mode):
    """Test complete cart operations: add, view, update quantity, delete, clear."""
    headers, user_id = _register_and_login(client, mode, f"cart_user_{mode}")

    # 1. Cart initially empty
    res = client.get(f"/{mode}/api/cart", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["item_count"] == 0

    # 2. Add product #1 (FlowGuard Security Key Pro, price 450000)
    add_res = client.post(f"/{mode}/api/cart/items", headers=headers, json={
        "product_id": 1,
        "quantity": 2,
    })
    assert add_res.status_code == 201
    item_id = add_res.get_json()["cart_item"]["id"]

    # 3. View cart - total should be 2 * 450000 = 900000
    cart_res = client.get(f"/{mode}/api/cart", headers=headers)
    assert cart_res.status_code == 200
    data = cart_res.get_json()
    assert data["item_count"] == 1
    assert data["total_minor_units"] == 900000

    # 4. Update quantity to 3 -> total should be 3 * 450000 = 1350000
    put_res = client.put(f"/{mode}/api/cart/items/{item_id}", headers=headers, json={"quantity": 3})
    assert put_res.status_code == 200
    cart_res2 = client.get(f"/{mode}/api/cart", headers=headers)
    assert cart_res2.get_json()["total_minor_units"] == 1350000

    # 5. Add second product #3 (Webcam Cover, 49900)
    client.post(f"/{mode}/api/cart/items", headers=headers, json={"product_id": 3, "quantity": 1})
    cart_res3 = client.get(f"/{mode}/api/cart", headers=headers)
    assert cart_res3.get_json()["item_count"] == 2

    # 6. Delete first item
    del_res = client.delete(f"/{mode}/api/cart/items/{item_id}", headers=headers)
    assert del_res.status_code == 200
    cart_res4 = client.get(f"/{mode}/api/cart", headers=headers)
    assert cart_res4.get_json()["item_count"] == 1

    # 7. Clear cart
    clear_res = client.delete(f"/{mode}/api/cart", headers=headers)
    assert clear_res.status_code == 200
    cart_res5 = client.get(f"/{mode}/api/cart", headers=headers)
    assert cart_res5.get_json()["item_count"] == 0


@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
def test_cart_validations(client, mode):
    """Test cart validation for non-existent products and stock limits."""
    headers, _ = _register_and_login(client, mode, f"val_user_{mode}")

    # Non-existent product -> 404
    res1 = client.post(f"/{mode}/api/cart/items", headers=headers, json={"product_id": 9999, "quantity": 1})
    assert res1.status_code == 404

    # Quantity exceeding stock (stock for product 1 is 50) -> 400
    res2 = client.post(f"/{mode}/api/cart/items", headers=headers, json={"product_id": 1, "quantity": 500})
    assert res2.status_code == 400

    # Invalid payload format -> 400
    res3 = client.post(f"/{mode}/api/cart/items", headers=headers, json="invalid")
    assert res3.status_code == 400


# =========================================================================
# Part B & C: Checkout & Order Creation
# =========================================================================

@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
def test_checkout_empty_cart_fails(client, mode):
    """Checkout with an empty cart must return 400."""
    headers, _ = _register_and_login(client, mode, f"empty_cart_{mode}")
    res = client.post(f"/{mode}/api/orders/checkout", headers=headers, json={"idempotency_key": "k1"})
    assert res.status_code == 400
    assert "empty" in res.get_json()["message"].lower()


@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
def test_checkout_success_lifecycle(app, client, mode):
    """Successful checkout creates order, snapshots items, clears cart, status is PENDING_PAYMENT."""
    headers, user_id = _register_and_login(client, mode, f"chk_user_{mode}")

    # Add product 1 (qty 2 = 900000)
    client.post(f"/{mode}/api/cart/items", headers=headers, json={"product_id": 1, "quantity": 2})

    # Checkout
    res = client.post(f"/{mode}/api/orders/checkout", headers=headers, json={"idempotency_key": f"key-{mode}-1"})
    assert res.status_code == 201
    order_data = res.get_json()["order"]
    order_id = order_data["id"]

    assert order_data["status"] == "PENDING_PAYMENT"
    assert order_data["total_minor_units"] == 900000
    assert len(order_data["items"]) == 1
    assert order_data["items"][0]["quantity"] == 2

    # Verify cart is cleared
    cart_res = client.get(f"/{mode}/api/cart", headers=headers)
    assert cart_res.get_json()["item_count"] == 0

    # Verify order in database
    factory = get_session_factory(mode, TestingConfig)
    s = factory()
    try:
        db_order = s.query(Order).filter_by(id=order_id).first()
        assert db_order is not None
        assert db_order.status == "PENDING_PAYMENT"
        assert db_order.total_minor_units == 900000
        assert len(db_order.items) == 1
    finally:
        s.close()


# =========================================================================
# Part D & E: Payment & State Transitions
# =========================================================================

@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
def test_payment_and_confirmation_happy_path(app, client, mode):
    """Happy path: CART -> checkout -> PENDING_PAYMENT -> payment -> PAID -> confirm -> CONFIRMED."""
    headers, _ = _register_and_login(client, mode, f"happy_{mode}")

    # 1. Add item & checkout
    client.post(f"/{mode}/api/cart/items", headers=headers, json={"product_id": 4, "quantity": 1})
    chk = client.post(f"/{mode}/api/orders/checkout", headers=headers, json={"idempotency_key": f"pay-happy-{mode}"})
    order_id = chk.get_json()["order"]["id"]

    # 2. Process dummy payment
    pay_res = client.post(f"/{mode}/api/payment/process", headers=headers, json={"order_id": order_id})
    assert pay_res.status_code == 200
    assert pay_res.get_json()["order_status"] == "PAID"
    assert pay_res.get_json()["payment"]["status"] == "SUCCESS"

    # 3. Confirm order
    conf_res = client.post(f"/{mode}/api/orders/{order_id}/confirm", headers=headers)
    assert conf_res.status_code == 200
    assert conf_res.get_json()["order"]["status"] == "CONFIRMED"

    # 4. Verify DB state
    factory = get_session_factory(mode, TestingConfig)
    s = factory()
    try:
        db_order = s.query(Order).filter_by(id=order_id).first()
        assert db_order.status == "CONFIRMED"
        db_payment = s.query(Payment).filter_by(order_id=order_id).first()
        assert db_payment is not None
        assert db_payment.status == "SUCCESS"
    finally:
        s.close()


@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
def test_order_cancellation_from_pending(client, mode):
    """An order in PENDING_PAYMENT can be cancelled."""
    headers, _ = _register_and_login(client, mode, f"cancel_{mode}")
    client.post(f"/{mode}/api/cart/items", headers=headers, json={"product_id": 1, "quantity": 1})
    chk = client.post(f"/{mode}/api/orders/checkout", headers=headers, json={"idempotency_key": f"canc-{mode}"})
    order_id = chk.get_json()["order"]["id"]

    res = client.post(f"/{mode}/api/orders/{order_id}/cancel", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["order"]["status"] == "CANCELLED"

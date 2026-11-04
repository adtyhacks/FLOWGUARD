"""Stage 2 Audit Remediation Regression Tests.

Covers findings D-01 through D-04:
- D-01: Controlled concurrent checkout regression test (vulnerable duplicate creation vs secure idempotency).
- D-02: Premature coupon redemption fix (validation only on apply; redemption during checkout).
- D-03: Coupon quota restoration on cancellation (restores only from PENDING_PAYMENT, prevents double restoration, blocks restoration on PAID).
- D-04: Generic exception handling during checkout (safe rollback, structured 500, no internal detail leaks).
"""

from concurrent.futures import ThreadPoolExecutor
import threading
from unittest.mock import patch
import pytest
from shopzone.blueprints.secure.sec_orders import set_checkout_race_hook
from shopzone.blueprints.secure.sec_payment import set_payment_race_hook
from shopzone.config import TestingConfig
from shopzone.db import get_session_factory
from shopzone.models import CartItem, Coupon, CouponRedemption, Order, OrderItem, Payment, Product


def _setup_user_with_cart(client, mode: str, username: str, product_id: int = 1, qty: int = 1) -> tuple[dict, int]:
    """Helper: register, login, and populate cart."""
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
    headers = {"Authorization": f"Bearer {token}"}

    client.post(f"/{mode}/api/cart/items", headers=headers, json={
        "product_id": product_id,
        "quantity": qty,
    })
    return headers, user_id


# =========================================================================
# D-02: Coupon Lifecycle & Abandoned Checkout
# =========================================================================

def test_abandoned_checkout_leaves_coupon_available(client):
    """D-02: Applying a coupon validates it without consuming it. Abandoned checkout leaves coupon available."""
    headers, user_id = _setup_user_with_cart(client, "secure", "user_abandon_cpn", product_id=1, qty=1)

    # 1. Apply coupon CYBERSEC20
    apply_res = client.post("/secure/api/coupons/apply", headers=headers, json={"code": "CYBERSEC20"})
    assert apply_res.status_code == 200
    data = apply_res.get_json()
    assert data["discount_pct"] == 20
    assert "redemption_id" not in data, "D-02: /coupons/apply must not create a redemption record!"

    # 2. Abandon checkout (never call /orders/checkout)

    # 3. Verify ground truth in DB: times_used is 0, is_active is True, zero CouponRedemption records
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        coupon = s.query(Coupon).filter_by(code="CYBERSEC20").first()
        assert coupon.times_used == 0
        assert coupon.is_active is True

        redemptions = s.query(CouponRedemption).filter_by(coupon_id=coupon.id).all()
        assert len(redemptions) == 0, f"Expected 0 redemptions, found {len(redemptions)}"
    finally:
        s.close()


def test_another_user_can_redeem_after_abandoned_checkout(client):
    """D-02: User B can redeem a single-use coupon even if User A applied it and abandoned checkout."""
    headersA, _ = _setup_user_with_cart(client, "secure", "abandon_user_A", product_id=1, qty=1)
    headersB, _ = _setup_user_with_cart(client, "secure", "abandon_user_B", product_id=1, qty=1)

    # User A applies coupon CYBERSEC20 and abandons checkout
    resA = client.post("/secure/api/coupons/apply", headers=headersA, json={"code": "CYBERSEC20"})
    assert resA.status_code == 200

    # User B checks out with CYBERSEC20 -> must succeed!
    resB = client.post("/secure/api/orders/checkout", headers=headersB, json={
        "idempotency_key": "k-abandon-B",
        "coupon_code": "CYBERSEC20",
    })
    assert resB.status_code == 201
    assert resB.get_json()["order"]["total_minor_units"] == 360000

    # Ground truth: exactly 1 redemption in DB belonging to User B
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        coupon = s.query(Coupon).filter_by(code="CYBERSEC20").first()
        assert coupon.times_used == 1
        assert coupon.is_active is False

        redemptions = s.query(CouponRedemption).filter_by(coupon_id=coupon.id).all()
        assert len(redemptions) == 1
    finally:
        s.close()


# =========================================================================
# D-03: Coupon Quota Restoration on Cancellation
# =========================================================================

def test_order_cancellation_restores_coupon_availability(client):
    """D-03: Cancelling a PENDING_PAYMENT order restores coupon quota and allows subsequent redemption."""
    headers1, _ = _setup_user_with_cart(client, "secure", "cancel_restore_u1", product_id=1, qty=1)
    headers2, _ = _setup_user_with_cart(client, "secure", "cancel_restore_u2", product_id=1, qty=1)

    # User 1 checks out with single-use coupon CYBERSEC20
    chk1 = client.post("/secure/api/orders/checkout", headers=headers1, json={
        "idempotency_key": "k-cancel-1",
        "coupon_code": "CYBERSEC20",
    })
    assert chk1.status_code == 201
    order1_id = chk1.get_json()["order"]["id"]

    # Verify coupon is temporarily consumed
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        cpn = s.query(Coupon).filter_by(code="CYBERSEC20").first()
        assert cpn.times_used == 1
        assert cpn.is_active is False
    finally:
        s.close()

    # User 1 cancels order
    cancel_res = client.post(f"/secure/api/orders/{order1_id}/cancel", headers=headers1)
    assert cancel_res.status_code == 200
    assert cancel_res.get_json()["order"]["status"] == "CANCELLED"

    # Verify coupon is restored in DB
    s = factory()
    try:
        cpn = s.query(Coupon).filter_by(code="CYBERSEC20").first()
        assert cpn.times_used == 0
        assert cpn.is_active is True
        redemptions = s.query(CouponRedemption).filter_by(coupon_id=cpn.id).all()
        assert len(redemptions) == 0, "Redemption record was not removed on cancellation!"
    finally:
        s.close()

    # User 2 checks out with the restored coupon -> succeeds!
    chk2 = client.post("/secure/api/orders/checkout", headers=headers2, json={
        "idempotency_key": "k-cancel-2",
        "coupon_code": "CYBERSEC20",
    })
    assert chk2.status_code == 201
    assert chk2.get_json()["order"]["total_minor_units"] == 360000


def test_repeated_cancellation_does_not_double_restore_quota(client):
    """D-03: Repeated cancellation requests on an already cancelled order are rejected and do not decrement times_used."""
    headers, _ = _setup_user_with_cart(client, "secure", "repeat_cancel_user", product_id=1, qty=1)

    chk = client.post("/secure/api/orders/checkout", headers=headers, json={
        "idempotency_key": "k-repeat-canc",
        "coupon_code": "CYBERSEC20",
    })
    order_id = chk.get_json()["order"]["id"]

    # First cancellation succeeds
    res1 = client.post(f"/secure/api/orders/{order_id}/cancel", headers=headers)
    assert res1.status_code == 200

    # Second cancellation fails with 400
    res2 = client.post(f"/secure/api/orders/{order_id}/cancel", headers=headers)
    assert res2.status_code == 400
    assert "Cannot cancel" in res2.get_json()["message"]

    # Ground truth: times_used is 0 (not negative!)
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        cpn = s.query(Coupon).filter_by(code="CYBERSEC20").first()
        assert cpn.times_used == 0
    finally:
        s.close()


def test_paid_order_cancellation_does_not_restore_coupon(client):
    """D-03: Cancelling a PAID order does NOT restore the coupon quota or delete the redemption."""
    headers1, _ = _setup_user_with_cart(client, "secure", "paid_cancel_u1", product_id=1, qty=1)
    headers2, _ = _setup_user_with_cart(client, "secure", "paid_cancel_u2", product_id=1, qty=1)

    # 1. Checkout with coupon
    chk = client.post("/secure/api/orders/checkout", headers=headers1, json={
        "idempotency_key": "k-paid-canc",
        "coupon_code": "CYBERSEC20",
    })
    order_id = chk.get_json()["order"]["id"]

    # 2. Pay for order
    pay_res = client.post("/secure/api/payment/process", headers=headers1, json={"order_id": order_id})
    assert pay_res.status_code == 200
    assert pay_res.get_json()["order_status"] == "PAID"

    # 3. Cancel the PAID order
    cancel_res = client.post(f"/secure/api/orders/{order_id}/cancel", headers=headers1)
    assert cancel_res.status_code == 200
    assert cancel_res.get_json()["order"]["status"] == "CANCELLED"

    # 4. Verify DB: coupon is NOT restored because order was already PAID
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        cpn = s.query(Coupon).filter_by(code="CYBERSEC20").first()
        assert cpn.times_used == 1
        assert cpn.is_active is False
        redemptions = s.query(CouponRedemption).filter_by(coupon_id=cpn.id).all()
        assert len(redemptions) == 1, "Redemption was improperly removed from a PAID order!"
    finally:
        s.close()

    # 5. User 2 attempting to use CYBERSEC20 is rejected with 409
    chk2 = client.post("/secure/api/orders/checkout", headers=headers2, json={
        "idempotency_key": "k-paid-canc-u2",
        "coupon_code": "CYBERSEC20",
    })
    assert chk2.status_code == 409


# =========================================================================
# Concurrent Coupon Redemption Competition
# =========================================================================

def test_concurrent_single_use_coupon_competition(client):
    """Multiple users concurrently checking out with the same single-use coupon: exactly one succeeds."""
    headers_list = []
    for i in range(3):
        h, _ = _setup_user_with_cart(client, "secure", f"comp_user_{i}", product_id=1, qty=1)
        headers_list.append(h)

    barrier = threading.Barrier(3)
    set_checkout_race_hook(lambda: barrier.wait())

    try:
        def do_checkout(idx):
            return client.post("/secure/api/orders/checkout", headers=headers_list[idx], json={
                "idempotency_key": f"key-comp-{idx}",
                "coupon_code": "CYBERSEC20",
            })

        with ThreadPoolExecutor(max_workers=3) as executor:
            responses = list(executor.map(do_checkout, range(3)))

        # Exactly 1 request succeeds with 201; other 2 receive 409 Conflict
        successes = [r for r in responses if r.status_code == 201]
        conflicts = [r for r in responses if r.status_code == 409]
        assert len(successes) == 1, f"Expected exactly 1 winner, got {len(successes)}"
        assert len(conflicts) == 2, f"Expected 2 conflicts, got {len(conflicts)}"

        # Ground truth: exactly 1 redemption in DB
        factory = get_session_factory("secure", TestingConfig)
        s = factory()
        try:
            cpn = s.query(Coupon).filter_by(code="CYBERSEC20").first()
            assert cpn.times_used == 1
            redemptions = s.query(CouponRedemption).filter_by(coupon_id=cpn.id).all()
            assert len(redemptions) == 1
        finally:
            s.close()
    finally:
        set_checkout_race_hook(None)


# =========================================================================
# D-04: Checkout Exception Handling & Transaction Rollback
# =========================================================================

def test_checkout_failure_rolls_back_cleanly(client):
    """Transaction integrity: failure during checkout rolls back cleanly without leaving partial records or deleting cart."""
    headers, user_id = _setup_user_with_cart(client, "secure", "clean_rollback_u", product_id=1, qty=2)

    # Attempt checkout with invalid coupon
    res = client.post("/secure/api/orders/checkout", headers=headers, json={
        "idempotency_key": "k-fail-rollback",
        "coupon_code": "NON_EXISTENT_CODE",
    })
    assert res.status_code == 404

    # Verify cart items are preserved
    cart_res = client.get("/secure/api/cart", headers=headers)
    assert cart_res.get_json()["item_count"] == 1
    assert cart_res.get_json()["items"][0]["quantity"] == 2

    # Verify no order was created
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        orders = s.query(Order).filter_by(user_id=user_id).all()
        assert len(orders) == 0
    finally:
        s.close()


def test_unexpected_checkout_exception_returns_500_and_rolls_back(client):
    """D-04: Unexpected exceptions trigger explicit rollback and return structured 500 without leaking internals."""
    headers, user_id = _setup_user_with_cart(client, "secure", "crash_u", product_id=1, qty=1)

    # Simulate an unexpected server crash during order creation via race hook
    def simulate_crash():
        raise RuntimeError("Simulated unexpected database failure or filesystem error")

    set_checkout_race_hook(simulate_crash)
    try:
        res = client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": "k-crash"})
        assert res.status_code == 500
        data = res.get_json()
        assert data["error"] == "Internal Server Error"
        assert data["message"] == "An unexpected error occurred during checkout. Please try again."
        assert "Simulated unexpected" not in str(data), "Internal error leaked to client!"

        # Ground truth: no order was created, cart items remain intact
        factory = get_session_factory("secure", TestingConfig)
        s = factory()
        try:
            orders = s.query(Order).filter_by(idempotency_key="k-crash").all()
            assert len(orders) == 0, "Partial order record was committed despite failure!"

            cart_items = s.query(CartItem).filter_by(user_id=user_id).all()
            assert len(cart_items) == 1, "Cart was cleared despite checkout failure!"
        finally:
            s.close()
    finally:
        set_checkout_race_hook(None)


def test_unexpected_payment_exception_returns_500_and_rolls_back(client):
    """Payment hardening: unexpected exception during payment rolls back, returns 500, preserves order state, and leaves no partial payment."""
    headers, user_id = _setup_user_with_cart(client, "secure", "pay_crash_u", product_id=1, qty=1)

    # 1. Checkout successfully -> order is in PENDING_PAYMENT
    chk = client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": "k-pay-crash"})
    assert chk.status_code == 201
    order_id = chk.get_json()["order"]["id"]
    assert chk.get_json()["order"]["status"] == "PENDING_PAYMENT"

    # 2. Inject unexpected crash during payment processing
    def simulate_payment_crash():
        raise RuntimeError("Simulated unexpected gateway or database timeout during payment")

    set_payment_race_hook(simulate_payment_crash)
    try:
        res = client.post("/secure/api/payment/process", headers=headers, json={"order_id": order_id})
        assert res.status_code == 500
        data = res.get_json()
        assert data["error"] == "Internal Server Error"
        assert data["message"] == "An unexpected error occurred during payment processing. Please try again."
        assert "Simulated unexpected" not in str(data), "Sensitive internal error details leaked to client!"

        # 3. Ground truth DB verification
        factory = get_session_factory("secure", TestingConfig)
        s = factory()
        try:
            # Order remains in PENDING_PAYMENT (not PAID or CONFIRMED)
            order = s.query(Order).filter_by(id=order_id).first()
            assert order is not None
            assert order.status == "PENDING_PAYMENT"

            # No payment record exists for this order
            payment = s.query(Payment).filter_by(order_id=order_id).first()
            assert payment is None, "Partial payment record committed despite failure!"
        finally:
            s.close()
    finally:
        set_payment_race_hook(None)


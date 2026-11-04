"""Tests demonstrating the seven security invariants in both Vulnerable and Secure modes.

For every invariant, verifies:
1. Vulnerable mode demonstrably violates the business logic invariant.
2. Secure mode demonstrably enforces and preserves the invariant.
3. Database ground truth confirms the observed behavior.
"""

from concurrent.futures import ThreadPoolExecutor
import threading
import pytest
from shopzone.blueprints.secure.sec_orders import set_checkout_race_hook as set_sec_checkout_race_hook
from shopzone.blueprints.vulnerable.vuln_orders import set_checkout_race_hook as set_vuln_checkout_race_hook
from shopzone.config import TestingConfig
from shopzone.db import get_session_factory
from shopzone.models import Coupon, CouponRedemption, Order, Payment, Product, User


def _setup_user_with_cart(client, mode: str, username: str, product_id: int = 1, qty: int = 1) -> tuple[dict, int]:
    """Register, login, and populate cart with specified product."""
    client.post(f"/{mode}/api/auth/register", json={
        "username": username,
        "email": f"{username}@test.local",
        "password": "Password123!",
    })
    login_res = client.post(f"/{mode}/api/auth/login", json={
        "username": username,
        "password": "Password123!",
    })
    token = login_res.get_json()["token"]
    user_id = login_res.get_json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post(f"/{mode}/api/cart/items", headers=headers, json={
        "product_id": product_id,
        "quantity": qty,
    })
    return headers, user_id


# =========================================================================
# TC-01: Payment Confirmation Bypass (BI-1)
# =========================================================================

def test_tc01_payment_bypass_vulnerable(client):
    """Vulnerable: An order can be confirmed without payment."""
    headers, _ = _setup_user_with_cart(client, "vulnerable", "vuln_bypass_user")

    # Checkout -> order is in PENDING_PAYMENT
    chk = client.post("/vulnerable/api/orders/checkout", headers=headers, json={"idempotency_key": "k-tc01-v"})
    order_id = chk.get_json()["order"]["id"]
    assert chk.get_json()["order"]["status"] == "PENDING_PAYMENT"

    # DIRECT CONFIRM WITHOUT PAYMENT
    res = client.post(f"/vulnerable/api/orders/{order_id}/confirm", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["order"]["status"] == "CONFIRMED"

    # Ground truth: order is CONFIRMED with ZERO payment records
    factory = get_session_factory("vulnerable", TestingConfig)
    s = factory()
    try:
        order = s.query(Order).filter_by(id=order_id).first()
        assert order.status == "CONFIRMED"
        payment = s.query(Payment).filter_by(order_id=order_id).first()
        assert payment is None, "Payment record unexpectedly exists!"
    finally:
        s.close()


def test_tc01_payment_bypass_secure(client):
    """Secure: An order in PENDING_PAYMENT CANNOT be confirmed without payment."""
    headers, _ = _setup_user_with_cart(client, "secure", "sec_bypass_user")

    chk = client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": "k-tc01-s"})
    order_id = chk.get_json()["order"]["id"]
    assert chk.get_json()["order"]["status"] == "PENDING_PAYMENT"

    # Attempt to confirm without payment -> must return 400
    res = client.post(f"/secure/api/orders/{order_id}/confirm", headers=headers)
    assert res.status_code == 400
    assert "PAID" in res.get_json()["message"]

    # Ground truth: status remains PENDING_PAYMENT
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        order = s.query(Order).filter_by(id=order_id).first()
        assert order.status == "PENDING_PAYMENT"
    finally:
        s.close()


# =========================================================================
# TC-02: Global Single-Use Coupon Reuse (BI-2)
# =========================================================================

def test_tc02_coupon_reuse_vulnerable(client):
    """Vulnerable: The same single-use coupon CYBERSEC20 can be redeemed multiple times."""
    headers1, _ = _setup_user_with_cart(client, "vulnerable", "vuln_cpn_user_1", product_id=1, qty=1)
    headers2, _ = _setup_user_with_cart(client, "vulnerable", "vuln_cpn_user_2", product_id=1, qty=1)

    # User 1 checks out with CYBERSEC20 (20% off 450000 = 360000)
    res1 = client.post("/vulnerable/api/orders/checkout", headers=headers1, json={
        "idempotency_key": "k-cpn-v-1",
        "coupon_code": "CYBERSEC20",
    })
    assert res1.status_code == 201
    assert res1.get_json()["order"]["total_minor_units"] == 360000

    # User 2 checks out with SAME coupon CYBERSEC20 -> vulnerable mode permits reuse!
    res2 = client.post("/vulnerable/api/orders/checkout", headers=headers2, json={
        "idempotency_key": "k-cpn-v-2",
        "coupon_code": "CYBERSEC20",
    })
    assert res2.status_code == 201
    assert res2.get_json()["order"]["total_minor_units"] == 360000

    # Ground truth: 2 redemptions exist in vulnerable DB
    factory = get_session_factory("vulnerable", TestingConfig)
    s = factory()
    try:
        redemptions = s.query(CouponRedemption).filter_by(coupon_id=1).all()
        assert len(redemptions) == 2, f"Expected 2 redemptions, got {len(redemptions)}"
    finally:
        s.close()


def test_tc02_coupon_reuse_secure(client):
    """Secure: A single-use coupon can only be redeemed once globally."""
    headers1, _ = _setup_user_with_cart(client, "secure", "sec_cpn_user_1", product_id=1, qty=1)
    headers2, _ = _setup_user_with_cart(client, "secure", "sec_cpn_user_2", product_id=1, qty=1)

    # User 1 redeems CYBERSEC20 successfully
    res1 = client.post("/secure/api/orders/checkout", headers=headers1, json={
        "idempotency_key": "k-cpn-s-1",
        "coupon_code": "CYBERSEC20",
    })
    assert res1.status_code == 201
    assert res1.get_json()["order"]["total_minor_units"] == 360000

    # User 2 attempts to use SAME coupon -> rejected with 409
    res2 = client.post("/secure/api/orders/checkout", headers=headers2, json={
        "idempotency_key": "k-cpn-s-2",
        "coupon_code": "CYBERSEC20",
    })
    assert res2.status_code == 409
    msg = res2.get_json()["message"].lower()
    assert "already been redeemed" in msg or "no longer available" in msg

    # Ground truth: exactly 1 redemption in secure DB
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        redemptions = s.query(CouponRedemption).filter_by(coupon_id=1).all()
        assert len(redemptions) == 1
    finally:
        s.close()


# =========================================================================
# TC-03: Sequential Duplicate Checkout Replay (BI-3)
# =========================================================================

def test_tc03_duplicate_checkout_vulnerable(client):
    """Vulnerable: Sequential duplicate checkouts create multiple duplicate orders."""
    headers, _ = _setup_user_with_cart(client, "vulnerable", "vuln_dup_user")

    # 1. First checkout
    res1 = client.post("/vulnerable/api/orders/checkout", headers=headers, json={"idempotency_key": "dup-key-v"})
    assert res1.status_code == 201
    order1_id = res1.get_json()["order"]["id"]

    # Re-populate cart for second checkout
    client.post("/vulnerable/api/cart/items", headers=headers, json={"product_id": 1, "quantity": 1})

    # 2. Second checkout with IDENTICAL idempotency_key
    res2 = client.post("/vulnerable/api/orders/checkout", headers=headers, json={"idempotency_key": "dup-key-v"})
    assert res2.status_code == 201
    order2_id = res2.get_json()["order"]["id"]

    # In vulnerable mode, a new duplicate order is created!
    assert order1_id != order2_id

    # Ground truth: 2 orders exist with the same idempotency key
    factory = get_session_factory("vulnerable", TestingConfig)
    s = factory()
    try:
        dup_orders = s.query(Order).filter_by(idempotency_key="dup-key-v").all()
        assert len(dup_orders) == 2
    finally:
        s.close()


def test_tc03_duplicate_checkout_secure(client):
    """Secure: Identical replay returns existing order (200 OK); different payload returns 409."""
    headers, _ = _setup_user_with_cart(client, "secure", "sec_dup_user")

    # 1. First checkout
    res1 = client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": "dup-key-s"})
    assert res1.status_code == 201
    order1_id = res1.get_json()["order"]["id"]

    # 2. Identical replay with same key -> returns existing order with 200 OK
    res2 = client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": "dup-key-s"})
    assert res2.status_code == 200
    assert res2.get_json()["idempotent_replay"] is True
    assert res2.get_json()["order"]["id"] == order1_id

    # 3. Same key with different coupon payload -> returns 409 Conflict
    res3 = client.post("/secure/api/orders/checkout", headers=headers, json={
        "idempotency_key": "dup-key-s",
        "coupon_code": "CYBERSEC20",
    })
    assert res3.status_code == 409

    # Ground truth: exactly 1 order in secure DB
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        orders = s.query(Order).filter_by(idempotency_key="dup-key-s").all()
        assert len(orders) == 1
    finally:
        s.close()


# =========================================================================
# TC-04: Order IDOR (BI-4)
# =========================================================================

def test_tc04_order_idor_vulnerable(client):
    """Vulnerable: User B can read User A's order by guessing the ID."""
    headersA, _ = _setup_user_with_cart(client, "vulnerable", "idor_user_A")
    headersB, _ = _setup_user_with_cart(client, "vulnerable", "idor_user_B")

    # User A creates order
    resA = client.post("/vulnerable/api/orders/checkout", headers=headersA, json={"idempotency_key": "idor-v-A"})
    order_id = resA.get_json()["order"]["id"]

    # User B requests User A's order -> vulnerable mode serves it with 200 OK!
    resB = client.get(f"/vulnerable/api/orders/{order_id}", headers=headersB)
    assert resB.status_code == 200
    assert resB.get_json()["order"]["id"] == order_id


def test_tc04_order_idor_secure(client):
    """Secure: User B attempting to view User A's order receives 404 Not Found."""
    headersA, _ = _setup_user_with_cart(client, "secure", "sec_idor_user_A")
    headersB, _ = _setup_user_with_cart(client, "secure", "sec_idor_user_B")

    resA = client.post("/secure/api/orders/checkout", headers=headersA, json={"idempotency_key": "idor-s-A"})
    order_id = resA.get_json()["order"]["id"]

    # User B requests User A's order -> secure mode hides existence with 404
    resB = client.get(f"/secure/api/orders/{order_id}", headers=headersB)
    assert resB.status_code == 404
    assert "not found" in resB.get_json()["message"].lower()


# =========================================================================
# TC-05: Workflow State Machine Violations (BI-5)
# =========================================================================

def test_tc05_state_machine_violations_vulnerable(client):
    """Vulnerable: Arbitrary status mutations permitted (cancel confirmed order, confirm pending order)."""
    headers, _ = _setup_user_with_cart(client, "vulnerable", "vuln_state_user")
    chk = client.post("/vulnerable/api/orders/checkout", headers=headers, json={"idempotency_key": "sm-v"})
    order_id = chk.get_json()["order"]["id"]

    # Jump directly to CONFIRMED
    res1 = client.post(f"/vulnerable/api/orders/{order_id}/confirm", headers=headers)
    assert res1.status_code == 200
    assert res1.get_json()["order"]["status"] == "CONFIRMED"

    # Cancel an already CONFIRMED order -> permitted in vulnerable mode!
    res2 = client.post(f"/vulnerable/api/orders/{order_id}/cancel", headers=headers)
    assert res2.status_code == 200
    assert res2.get_json()["order"]["status"] == "CANCELLED"


def test_tc05_state_machine_violations_secure(client):
    """Secure: Illegal transitions are rejected with 400 Bad Request."""
    headers, _ = _setup_user_with_cart(client, "secure", "sec_state_user")
    chk = client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": "sm-s"})
    order_id = chk.get_json()["order"]["id"]

    # 1. Illegal transition: PENDING_PAYMENT -> CONFIRMED (must pay first)
    res1 = client.post(f"/secure/api/orders/{order_id}/confirm", headers=headers)
    assert res1.status_code == 400

    # 2. Complete payment -> status becomes PAID
    pay_res = client.post("/secure/api/payment/process", headers=headers, json={"order_id": order_id})
    assert pay_res.status_code == 200

    # 3. Confirm order -> status becomes CONFIRMED
    conf_res = client.post(f"/secure/api/orders/{order_id}/confirm", headers=headers)
    assert conf_res.status_code == 200

    # 4. Illegal transition: CONFIRMED -> CANCELLED (cannot cancel confirmed order)
    cancel_res = client.post(f"/secure/api/orders/{order_id}/cancel", headers=headers)
    assert cancel_res.status_code == 400
    assert "Cannot cancel" in cancel_res.get_json()["message"]


# =========================================================================
# TC-06: Controlled Concurrent Checkout / Race Condition (BI-7)
# =========================================================================

def test_tc06_concurrent_checkout_vulnerable(client):
    """Vulnerable: Controlled concurrent checkout requests with identical idempotency key create duplicate orders."""
    headers, user_id = _setup_user_with_cart(client, "vulnerable", "concurrent_chk_vuln", product_id=1, qty=1)

    shared_key = "race-chk-key-vulnerable"
    barrier = threading.Barrier(5)

    set_vuln_checkout_race_hook(lambda: barrier.wait())
    try:
        def do_checkout(thread_id):
            return client.post("/vulnerable/api/orders/checkout", headers=headers, json={"idempotency_key": shared_key})

        with ThreadPoolExecutor(max_workers=5) as executor:
            responses = list(executor.map(do_checkout, range(5)))

        # Vulnerable mode creates duplicate orders: multiple 201 Created responses
        success_responses = [r for r in responses if r.status_code == 201]
        assert len(success_responses) > 1, f"Expected >1 successful order creation, got {len(success_responses)}"

        # Ground truth: duplicate orders committed with identical idempotency_key
        factory = get_session_factory("vulnerable", TestingConfig)
        s = factory()
        try:
            orders = s.query(Order).filter_by(idempotency_key=shared_key).all()
            assert len(orders) > 1, f"Expected duplicate orders in DB, found {len(orders)}"
        finally:
            s.close()
    finally:
        set_vuln_checkout_race_hook(None)


def test_tc06_concurrent_checkout_secure(app, client):
    """Secure: Controlled concurrent checkout requests with identical idempotency key create at most 1 order."""
    headers, user_id = _setup_user_with_cart(client, "secure", "concurrent_chk_user", product_id=1, qty=1)

    shared_key = "race-chk-key-secure"
    barrier = threading.Barrier(5)

    set_sec_checkout_race_hook(lambda: barrier.wait())
    try:
        def do_checkout(thread_id):
            return client.post("/secure/api/orders/checkout", headers=headers, json={"idempotency_key": shared_key})

        with ThreadPoolExecutor(max_workers=5) as executor:
            responses = list(executor.map(do_checkout, range(5)))

        # Exactly one request creates the order (201); others receive idempotent replays (200) or conflict (409)
        created_responses = [r for r in responses if r.status_code == 201]
        assert len(created_responses) == 1, f"Expected exactly 1 order creation (201), got {len(created_responses)}"

        for r in responses:
            assert r.status_code in (200, 201, 409)

        # Ground truth: exactly 1 order exists in DB with this key
        factory = get_session_factory("secure", TestingConfig)
        s = factory()
        try:
            orders = s.query(Order).filter_by(idempotency_key=shared_key).all()
            assert len(orders) == 1, f"Expected 1 order under concurrency, got {len(orders)}"
        finally:
            s.close()
    finally:
        set_sec_checkout_race_hook(None)


# =========================================================================
# TC-07: Client-Side Price Tampering (BI-6)
# =========================================================================

def test_tc07_price_tampering_vulnerable(client):
    """Vulnerable: Client-submitted total_amount overrides server catalog prices."""
    # Product #1 price is 450000 (₹4500)
    headers, _ = _setup_user_with_cart(client, "vulnerable", "price_tamper_vuln", product_id=1, qty=1)

    # Client tampers with total_amount: sets it to 100 paise (₹1)
    res = client.post("/vulnerable/api/orders/checkout", headers=headers, json={
        "idempotency_key": "k-tamper-v",
        "total_amount": 100,
    })
    assert res.status_code == 201
    order_data = res.get_json()["order"]
    order_id = order_data["id"]

    # Vulnerable mode blindly accepted the client's 100 paise price!
    assert order_data["total_minor_units"] == 100

    # Ground truth: DB stores tampered price
    factory = get_session_factory("vulnerable", TestingConfig)
    s = factory()
    try:
        order = s.query(Order).filter_by(id=order_id).first()
        assert order.total_minor_units == 100
    finally:
        s.close()


def test_tc07_price_tampering_secure(client):
    """Secure: Client-submitted total_amount is completely ignored; server computes canonical price."""
    headers, _ = _setup_user_with_cart(client, "secure", "price_tamper_sec", product_id=1, qty=1)

    # Client attempts to tamper total_amount to 100 paise
    res = client.post("/secure/api/orders/checkout", headers=headers, json={
        "idempotency_key": "k-tamper-s",
        "total_amount": 100,
    })
    assert res.status_code == 201
    order_data = res.get_json()["order"]
    order_id = order_data["id"]

    # Secure mode ignored the client total; computed canonical server price 450000
    assert order_data["total_minor_units"] == 450000

    # Ground truth: DB stores authoritative price
    factory = get_session_factory("secure", TestingConfig)
    s = factory()
    try:
        order = s.query(Order).filter_by(id=order_id).first()
        assert order.total_minor_units == 450000
    finally:
        s.close()

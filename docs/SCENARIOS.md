# FLOWGUARD Security Scenarios Technical Reference (TC-01 – TC-07)

This document provides a comprehensive technical reference for the seven automated business-logic security assessment scenarios implemented in FLOWGUARD.

---

## Scenario Overview Matrix

| Scenario ID | Scenario Name | Canonical Finding ID | Severity | Weight | CWE Mapping |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **TC-01** | Payment Bypass | `FG-TC01-001` | **CRITICAL** | 25 | [CWE-840](https://cwe.mitre.org/data/definitions/840.html) |
| **TC-02** | Coupon Reuse | `FG-TC02-001` | **HIGH** | 15 | [CWE-670](https://cwe.mitre.org/data/definitions/670.html) |
| **TC-03** | Duplicate Order Creation | `FG-TC03-001` | **HIGH** | 15 | [CWE-840](https://cwe.mitre.org/data/definitions/840.html) |
| **TC-04** | Order IDOR | `FG-TC04-001` | **CRITICAL** | 25 | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| **TC-05** | Invalid Workflow Transitions | `FG-TC05-001` | **HIGH** | 15 | [CWE-840](https://cwe.mitre.org/data/definitions/840.html) |
| **TC-06** | Concurrent Checkout Race | `FG-TC06-001` | **HIGH** | 15 | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) |
| **TC-07** | Client-Side Price Tampering | `FG-TC07-001` | **HIGH** | 15 | [CWE-472](https://cwe.mitre.org/data/definitions/472.html) |

---

## TC-01: Payment Bypass

### 1. Overview
- **Finding ID**: `FG-TC01-001`
- **Severity**: **CRITICAL** (25 Points)
- **CWE**: **CWE-840 (Business Logic Errors)**
- **Invariant**: An order in `PENDING_PAYMENT` state cannot transition to `CONFIRMED` without an authoritative, completed payment record.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable order confirmation endpoint (`/vuln/api/orders/<id>/confirm`) transitions the order status directly from `PENDING_PAYMENT` to `CONFIRMED` without verifying whether a corresponding payment record exists in the database:
```python
# shopzone/blueprints/vulnerable/vuln_orders.py
order.status = "CONFIRMED"
db.commit()
return jsonify({"message": "Order confirmed successfully", "order": order.to_dict()}), 200
```

### 3. Secure Defense Implementation
The secure endpoint (`/sec/api/orders/<id>/confirm`) strictly validates that a completed payment record exists and is bound to the order:
```python
# shopzone/blueprints/secure/sec_orders.py
payment = db.query(Payment).filter_by(order_id=order.id, status="COMPLETED").first()
if not payment:
    return jsonify({"error": "Bad Request", "message": "Cannot confirm order without verified payment."}), 400
order.status = "CONFIRMED"
db.commit()
```

### 4. Ground-Truth Verification
FLOWGUARD inspects the server state out-of-band via:
1. `GET /api/admin/verify/order/<mode>/<order_id>` -> Checks `order.status`.
2. `GET /api/admin/verify/payment/<mode>/<order_id>` -> Confirms `payment.found == False`.
If the order reached `CONFIRMED` while no payment record exists, the vulnerability is confirmed (`FAIL`).

---

## TC-02: Coupon Reuse

### 1. Overview
- **Finding ID**: `FG-TC02-001`
- **Severity**: **HIGH** (15 Points)
- **CWE**: **CWE-670 (Always-Incorrect Control Flow Implementation)**
- **Invariant**: A promotional coupon configured as globally single-use (`max_uses=1`) must be redeemed at most once across all users.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable coupon endpoint checks `times_used` non-atomically in Python and allows multiple checkouts:
```python
# shopzone/blueprints/vulnerable/vuln_coupons.py
if coupon.times_used >= coupon.max_uses:
    return jsonify({"error": "Conflict", "message": "Coupon has reached its maximum usage limit."}), 409
time.sleep(0.025) # Exploitable race window
redemption = CouponRedemption(coupon_id=coupon.id, user_id=g.current_user.id)
db.add(redemption)
coupon.times_used += 1
db.commit()
```
The database lacks a unique constraint on `coupon_redemptions(coupon_id)`.

### 3. Secure Defense Implementation
Secure mode enforces a database-level `UNIQUE` constraint on `coupon_id` in the `coupon_redemptions` table and marks the coupon inactive atomically during checkout:
```python
# shopzone/blueprints/secure/sec_orders.py
existing_redemption = db.query(CouponRedemption).filter_by(coupon_id=coupon.id).first()
if existing_redemption or not coupon.is_active or coupon.times_used >= coupon.max_uses:
    return jsonify({"error": "Conflict", "message": "This coupon has already been redeemed."}), 409
```

### 4. Ground-Truth Verification
FLOWGUARD registers User A and User B. Both attempt to apply and checkout using the same coupon.
- Ground truth query: `GET /api/admin/verify/coupon/<mode>/<code>`.
- Vulnerable outcome: `redemption_count >= 2` -> Flaw confirmed (`FAIL`).
- Secure outcome: User B is rejected with HTTP 409, `redemption_count == 1` -> Verified (`PASS`).

---

## TC-03: Duplicate Order Creation

### 1. Overview
- **Finding ID**: `FG-TC03-001`
- **Severity**: **HIGH** (15 Points)
- **CWE**: **CWE-840 (Business Logic Errors)**
- **Invariant**: Replaying a checkout request with an identical idempotency key must return the original order without creating duplicate database records or deducting duplicate inventory.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable checkout route completely ignores the `idempotency_key` parameter in the request payload. Every repeated submission generates a new distinct order row and decrements inventory:
```python
# shopzone/blueprints/vulnerable/vuln_orders.py
new_order = Order(user_id=g.current_user.id, total_minor_units=final_total, ...)
db.add(new_order)
db.commit()
```

### 3. Secure Defense Implementation
Secure mode checks for existing orders created with the given `idempotency_key`:
```python
# shopzone/blueprints/secure/sec_orders.py
existing_order = db.query(Order).filter_by(
    user_id=g.current_user.id,
    idempotency_key=idempotency_key
).first()

if existing_order:
    # If payloads match, return cached order (Idempotent Replay)
    if existing_order.cart_matches(cart_items):
        return jsonify({
            "message": "Order retrieved (idempotent replay)",
            "order": existing_order.to_dict(),
            "idempotent_replay": True
        }), 200
    # If payload differs, reject with conflict
    return jsonify({"error": "Conflict", "message": "Idempotency key re-used with differing payload."}), 409
```

### 4. Ground-Truth Verification
FLOWGUARD submits a checkout request with Key `K1`, then immediately replays the exact submission with Key `K1`.
- Vulnerable outcome: Two orders exist in `GET /vuln/api/orders` matching `K1` -> Flaw confirmed (`FAIL`).
- Secure outcome: Exactly one order exists in ground truth; second response returns `idempotent_replay=True` -> Verified (`PASS`).

---

## TC-04: Order IDOR

### 1. Overview
- **Finding ID**: `FG-TC04-001`
- **Severity**: **CRITICAL** (25 Points)
- **CWE**: **CWE-639 (Authorization Bypass Through User-Controlled Key)**
- **Invariant**: A user must not be permitted to view or mutate orders belonging to other user accounts.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable order details route retrieves orders purely by primary key ID without verifying ownership:
```python
# shopzone/blueprints/vulnerable/vuln_orders.py
order = db.query(Order).filter_by(id=order_id).first()
if not order:
    return jsonify({"error": "Not Found"}), 404
return jsonify({"order": order.to_dict()}), 200 # Leaks other tenant's order!
```

### 3. Secure Defense Implementation
Secure mode restricts queries to the authenticated tenant:
```python
# shopzone/blueprints/secure/sec_orders.py
order = db.query(Order).filter_by(id=order_id, user_id=g.current_user.id).first()
if not order:
    # Fails closed without revealing existence
    return jsonify({"error": "Not Found", "message": "Order not found."}), 404
```

### 4. Ground-Truth Verification
FLOWGUARD registers User A and creates Order $O_A$. FLOWGUARD registers User B and attempts to access `/orders/<O_A>` as User B.
- Vulnerable outcome: User B receives HTTP 200 and Order $O_A$ data -> Flaw confirmed (`FAIL`).
- Secure outcome: User B receives HTTP 404; User A retains legitimate access -> Verified (`PASS`).

---

## TC-05: Invalid Workflow Transitions

### 1. Overview
- **Finding ID**: `FG-TC05-001`
- **Severity**: **HIGH** (15 Points)
- **CWE**: **CWE-840 (Business Logic Errors)**
- **Invariant**: Order lifecycles must strictly adhere to valid state transitions (`PENDING -> PAID -> CONFIRMED`). Terminal states (`CANCELLED`) cannot be resurrected or transitioned.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable order transition handlers do not enforce a transition graph:
```python
# shopzone/blueprints/vulnerable/vuln_orders.py
# In cancel handler:
order.status = "CANCELLED"
# In confirm handler:
order.status = "CONFIRMED" # Allows confirming a CANCELLED order!
```

### 3. Secure Defense Implementation
Secure mode enforces a Finite State Machine:
```python
# shopzone/blueprints/secure/sec_orders.py
VALID_TRANSITIONS = {
    "PENDING_PAYMENT": {"CONFIRMED", "CANCELLED"},
    "CONFIRMED": {"SHIPPED", "CANCELLED"},
    "SHIPPED": {"DELIVERED"},
    "DELIVERED": set(), # Terminal
    "CANCELLED": set(), # Terminal
}
if target_status not in VALID_TRANSITIONS.get(order.status, set()):
    return jsonify({"error": "Bad Request", "message": f"Illegal transition from {order.status} to {target_status}."}), 400
```

### 4. Ground-Truth Verification
FLOWGUARD cancels an order, then attempts to confirm it, and verifies via `GET /api/admin/verify/order/<mode>/<id>`.
- Vulnerable outcome: Order status updates to `CONFIRMED` -> Flaw confirmed (`FAIL`).
- Secure outcome: Target rejects transition with HTTP 400; status remains `CANCELLED` -> Verified (`PASS`).

---

## TC-06: Concurrent Checkout Race

### 1. Overview
- **Finding ID**: `FG-TC06-001`
- **Severity**: **HIGH** (15 Points)
- **CWE**: **CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)**
- **Invariant**: Simultaneous concurrent checkouts using identical idempotency keys must resolve to exactly one order.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable checkout route reads the cart items, executes a Python check, and commits without atomic row locking:
```python
# shopzone/blueprints/vulnerable/vuln_orders.py
items = db.query(CartItem).filter_by(user_id=g.current_user.id).all()
# Concurrent threads read items simultaneously before deletion
order = Order(...)
db.add(order)
db.commit()
```

### 3. Secure Defense Implementation
Secure mode executes checkout within an atomic `BEGIN IMMEDIATE` transaction and relies on a database unique constraint on `(user_id, idempotency_key)`:
```python
# shopzone/blueprints/secure/sec_orders.py
try:
    with db.begin_nested():
        # Atomic lock and constraint validation
        ...
except IntegrityError:
    # Concurrent duplicate caught by database constraint
    return jsonify({"error": "Conflict", "message": "Concurrent duplicate checkout blocked."}), 409
```

### 4. Ground-Truth Verification
FLOWGUARD uses `threading.Barrier(4)` to synchronize 4 threads submitting identical checkout requests simultaneously.
- Vulnerable outcome: Ground truth contains $\ge 2$ distinct orders with the identical key -> Flaw confirmed (`FAIL`).
- Secure outcome: Exactly 1 order created in ground truth; all successful responses reference the winner ID -> Verified (`PASS`).
- **Timing Sensitivity & Inconclusive Classification**: Because concurrent race conditions are inherently timing-sensitive, if operating system thread scheduling or database locks process requests sequentially without observing the race window or corroborating ground-truth evidence, TC-06 safely returns `INCONCLUSIVE`. In such runs, assessment completeness evaluates to 85.71% and triggers fail-closed warnings. Under FLOWGUARD policy, an incomplete assessment can never be certified as secure.

---

## TC-07: Client-Side Price Tampering

### 1. Overview
- **Finding ID**: `FG-TC07-001`
- **Severity**: **HIGH** (15 Points)
- **CWE**: **CWE-472 (External Control of Assumed-Immutable Web Parameter)**
- **Invariant**: Order pricing must be calculated authoritatively on the server side using canonical catalog prices. Client-supplied price or total parameters must be ignored.

### 2. Flaw Mechanism (Vulnerable Mode)
The vulnerable checkout route honors the client-submitted `total_amount` parameter:
```python
# shopzone/blueprints/vulnerable/vuln_orders.py
client_total = data.get("total_amount")
if client_total is not None:
    final_total = int(client_total) # Attacker buys $45.00 product for $0.01!
```

### 3. Secure Defense Implementation
Secure mode strictly calculates prices from the product database:
```python
# shopzone/blueprints/secure/sec_orders.py
server_total = 0
for cart_item in cart_items:
    product = db.query(Product).filter_by(id=cart_item.product_id).first()
    server_total += product.price_minor_units * cart_item.quantity
# Completely ignores data.get("total_amount")
```

### 4. Ground-Truth Verification
FLOWGUARD adds an item priced at 450,000 minor units ($45.00) to the cart, but submits `total_amount = 100` ($0.01) during checkout.
- Vulnerable outcome: Ground-truth order shows `total_minor_units == 100` -> Flaw confirmed (`FAIL`).
- Secure outcome: Ground-truth order shows `total_minor_units == 450000` -> Verified (`PASS`).

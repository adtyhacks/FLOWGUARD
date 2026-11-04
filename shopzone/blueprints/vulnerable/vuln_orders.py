"""Vulnerable mode checkout and order management — /vuln/api/orders/*

DOCUMENTED FLAWS:
- TC-01: Payment confirmation bypass (no state check on confirm)
- TC-03: Duplicate order creation (idempotency key ignored)
- TC-04: IDOR (no ownership check on order access)
- TC-05: Invalid state transitions accepted
- TC-07: Client-supplied total_amount accepted
"""

from datetime import datetime, timezone
from flask import Blueprint, g, jsonify, request
from ...auth.middleware import require_auth
from ...models import CartItem, Coupon, CouponRedemption, Order, OrderItem, Product

# Controlled synchronization hook for testing race conditions (e.g. TC-06)
_checkout_race_hook = None


def set_checkout_race_hook(hook):
    """Set a hook to be called immediately after cart verification during checkout."""
    global _checkout_race_hook
    _checkout_race_hook = hook


def register_vuln_order_routes(bp: Blueprint) -> None:
    """Register vulnerable order endpoints."""

    @bp.route("/orders/checkout", methods=["POST"])
    @require_auth
    def checkout():
        data = request.get_json(silent=True) or {}
        db = g.db
        user_id = g.current_user.id

        # Load cart
        cart_items = db.query(CartItem).filter_by(user_id=user_id).all()
        if not cart_items:
            return jsonify({"error": "Bad Request", "message": "Cart is empty."}), 400

        # Controlled synchronization hook for TC-06 race reproduction
        if _checkout_race_hook is not None:
            _checkout_race_hook()

        # DOCUMENTED FLAW (TC-07): Accept client-submitted total if provided
        client_total = data.get("total_amount")

        # Calculate server total for fallback
        server_total = 0
        for ci in cart_items:
            product = db.query(Product).filter_by(id=ci.product_id).first()
            if product:
                server_total += product.price_minor_units * ci.quantity

        # DOCUMENTED FLAW (TC-07): Use client total if provided, otherwise server total
        if isinstance(client_total, int) and client_total >= 0:
            final_total = client_total
        else:
            final_total = server_total

        # Coupon discount
        coupon_code = data.get("coupon_code")
        coupon_id = None
        if isinstance(coupon_code, str) and coupon_code.strip():
            coupon = db.query(Coupon).filter_by(code=coupon_code.strip().upper()).first()
            if coupon and coupon.is_active:
                discount = (final_total * coupon.discount_pct) // 100
                final_total = max(0, final_total - discount)
                coupon_id = coupon.id

        # DOCUMENTED FLAW (TC-03): Idempotency key is completely ignored.
        # Every checkout request creates a new order regardless of duplicate keys.
        idempotency_key = data.get("idempotency_key")

        order = Order(
            user_id=user_id,
            status="PENDING_PAYMENT",
            total_minor_units=final_total,
            coupon_id=coupon_id,
            idempotency_key=idempotency_key,
        )
        db.add(order)
        db.flush()

        # Snapshot cart items into order items
        for ci in cart_items:
            product = db.query(Product).filter_by(id=ci.product_id).first()
            if product:
                oi = OrderItem(
                    order_id=order.id,
                    product_id=ci.product_id,
                    quantity=ci.quantity,
                    unit_price_minor_units=product.price_minor_units,
                )
                db.add(oi)

        # Record coupon redemption if applicable (no uniqueness enforced)
        if coupon_id and coupon:
            redemption = CouponRedemption(
                coupon_id=coupon_id,
                user_id=user_id,
                order_id=order.id,
            )
            db.add(redemption)
            coupon.times_used += 1

        # Clear cart after checkout
        db.query(CartItem).filter_by(user_id=user_id).delete()
        db.commit()

        return jsonify({
            "message": "Order created",
            "order": order.to_dict(),
        }), 201

    @bp.route("/orders", methods=["GET"])
    @require_auth
    def list_orders():
        db = g.db
        orders = db.query(Order).filter_by(user_id=g.current_user.id).order_by(Order.created_at.desc()).all()
        return jsonify({
            "orders": [o.to_dict() for o in orders],
            "count": len(orders),
        }), 200

    @bp.route("/orders/<int:order_id>", methods=["GET"])
    @require_auth
    def get_order(order_id: int):
        db = g.db
        # DOCUMENTED FLAW (TC-04): No ownership check. Any authenticated user
        # can view any order by knowing the order ID.
        order = db.query(Order).filter_by(id=order_id).first()
        if not order:
            return jsonify({"error": "Not Found", "message": "Order not found."}), 404

        return jsonify({"order": order.to_dict()}), 200

    @bp.route("/orders/<int:order_id>/confirm", methods=["POST"])
    @require_auth
    def confirm_order(order_id: int):
        db = g.db
        order = db.query(Order).filter_by(id=order_id).first()
        if not order:
            return jsonify({"error": "Not Found", "message": "Order not found."}), 404

        # DOCUMENTED FLAW (TC-01, TC-05): No state validation.
        # Order can be confirmed regardless of payment status or current state.
        order.status = "CONFIRMED"
        order.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            "message": "Order confirmed",
            "order": order.to_dict(),
        }), 200

    @bp.route("/orders/<int:order_id>/cancel", methods=["POST"])
    @require_auth
    def cancel_order(order_id: int):
        db = g.db
        order = db.query(Order).filter_by(id=order_id).first()
        if not order:
            return jsonify({"error": "Not Found", "message": "Order not found."}), 404

        # DOCUMENTED FLAW (TC-05): No state validation. Any order can be cancelled.
        order.status = "CANCELLED"
        order.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            "message": "Order cancelled",
            "order": order.to_dict(),
        }), 200

"""Secure mode payment processing — /sec/api/payment/*

Enforces:
- Order ownership validation
- Order must be in PENDING_PAYMENT state
- Payment amount matches order total
- Duplicate payment prevention via unique constraint on payments.order_id
- Atomic payment + status transition
"""

import uuid
from datetime import datetime, timezone
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy.exc import IntegrityError
from ...auth.middleware import require_auth
from ...models import Order, Payment

# Controlled synchronization / fault-injection hook for testing
_payment_race_hook = None


def set_payment_race_hook(hook):
    """Set a hook to be called during payment transaction for test synchronization or fault injection."""
    global _payment_race_hook
    _payment_race_hook = hook


def register_sec_payment_routes(bp: Blueprint) -> None:
    """Register secure payment endpoints."""

    @bp.route("/payment/process", methods=["POST"])
    @require_auth
    def process_payment():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON payload."}), 400

        order_id = data.get("order_id")
        if not isinstance(order_id, int):
            return jsonify({"error": "Bad Request", "message": "order_id (int) is required."}), 400

        db = g.db

        # Ownership check
        order = db.query(Order).filter_by(id=order_id, user_id=g.current_user.id).first()
        if not order:
            return jsonify({"error": "Not Found", "message": "Order not found."}), 404

        # State validation — must be PENDING_PAYMENT
        if order.status != "PENDING_PAYMENT":
            return jsonify({
                "error": "Bad Request",
                "message": f"Cannot process payment for order in state '{order.status}'. Must be PENDING_PAYMENT."
            }), 400

        # Duplicate payment check
        existing_payment = db.query(Payment).filter_by(order_id=order_id).first()
        if existing_payment:
            return jsonify({
                "error": "Conflict",
                "message": "Payment already exists for this order.",
                "payment": existing_payment.to_dict(),
            }), 409

        # Atomic payment creation + order state transition
        try:
            if _payment_race_hook is not None:
                _payment_race_hook()

            payment_ref = f"pay_{uuid.uuid4().hex[:16]}"
            payment = Payment(
                order_id=order.id,
                payment_ref=payment_ref,
                amount_minor_units=order.total_minor_units,
                status="SUCCESS",
            )
            db.add(payment)

            order.status = "PAID"
            order.updated_at = datetime.now(timezone.utc)
            db.commit()

        except IntegrityError:
            db.rollback()
            return jsonify({
                "error": "Conflict",
                "message": "Payment could not be processed (duplicate detected)."
            }), 409
        except Exception as e:
            db.rollback()
            current_app.logger.error("Payment processing failed unexpectedly: %s", str(e), exc_info=True)
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred during payment processing. Please try again.",
            }), 500

        return jsonify({
            "message": "Payment processed successfully",
            "payment": payment.to_dict(),
            "order_status": order.status,
        }), 200

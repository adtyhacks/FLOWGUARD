"""Vulnerable mode payment processing — /vuln/api/payment/*

DOCUMENTED FLAW: Payment processing does not validate order state, ownership,
or payment amount. Any order can be marked as PAID.
"""

import uuid
from datetime import datetime, timezone
from flask import Blueprint, g, jsonify, request
from ...auth.middleware import require_auth
from ...models import Order, Payment


def register_vuln_payment_routes(bp: Blueprint) -> None:
    """Register vulnerable payment endpoints."""

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

        # DOCUMENTED FLAW: No ownership check — any user can pay for any order
        order = db.query(Order).filter_by(id=order_id).first()
        if not order:
            return jsonify({"error": "Not Found", "message": "Order not found."}), 404

        # DOCUMENTED FLAW: No state validation — order need not be PENDING_PAYMENT
        # DOCUMENTED FLAW: No duplicate payment check

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

        return jsonify({
            "message": "Payment processed",
            "payment": payment.to_dict(),
            "order_status": order.status,
        }), 200

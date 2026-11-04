"""Vulnerable mode coupon operations — /vuln/api/coupons/*

DOCUMENTED FLAW (TC-02): No enforcement of globally single-use coupons.
The vulnerable implementation checks times_used in Python without atomicity,
and intentionally introduces a TOCTOU race window via time.sleep().
"""

import time
from flask import Blueprint, g, jsonify, request
from ...auth.middleware import require_auth
from ...models import Coupon, CouponRedemption


def register_vuln_coupon_routes(bp: Blueprint) -> None:
    """Register vulnerable coupon endpoints."""

    @bp.route("/coupons/apply", methods=["POST"])
    @require_auth
    def apply_coupon():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON payload."}), 400

        code = data.get("code")
        if not isinstance(code, str) or not code.strip():
            return jsonify({"error": "Bad Request", "message": "Coupon code (string) is required."}), 400

        code = code.strip().upper()
        db = g.db

        coupon = db.query(Coupon).filter_by(code=code).first()
        if not coupon:
            return jsonify({"error": "Not Found", "message": "Coupon not found."}), 404

        if not coupon.is_active:
            return jsonify({"error": "Conflict", "message": "Coupon is no longer active."}), 409

        # DOCUMENTED FLAW: Non-atomic read-then-check with TOCTOU race window
        # Reads times_used, checks in Python, sleeps, then writes.
        # This allows concurrent requests to pass the check simultaneously.
        if coupon.times_used >= coupon.max_uses:
            return jsonify({"error": "Conflict", "message": "Coupon has reached its maximum usage limit."}), 409

        # DOCUMENTED FLAW: Artificial delay creating exploitable race condition for TC-06
        time.sleep(0.025)

        # DOCUMENTED FLAW: No unique constraint check on coupon_redemptions in vulnerable DB.
        # Multiple users (or the same user) can redeem the same coupon.
        redemption = CouponRedemption(
            coupon_id=coupon.id,
            user_id=g.current_user.id,
        )
        db.add(redemption)

        coupon.times_used += 1
        db.commit()

        return jsonify({
            "message": "Coupon applied successfully",
            "coupon": coupon.to_dict(),
            "discount_pct": coupon.discount_pct,
            "redemption_id": redemption.id,
        }), 200

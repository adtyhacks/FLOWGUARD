"""Secure mode coupon operations — /sec/api/coupons/*

Invariant BI-2/BI-7: Globally single-use coupons are enforced via:
1. Database-level UNIQUE constraint on coupon_redemptions(coupon_id) in secure DB
2. Atomic BEGIN IMMEDIATE transaction preventing TOCTOU races
3. Application-level checks before insertion
"""

from flask import Blueprint, g, jsonify, request
from sqlalchemy.exc import IntegrityError
from ...auth.middleware import require_auth
from ...models import Coupon, CouponRedemption


def register_sec_coupon_routes(bp: Blueprint) -> None:
    """Register secure coupon endpoints."""

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

        if coupon.times_used >= coupon.max_uses:
            return jsonify({"error": "Conflict", "message": "Coupon has reached its maximum usage limit."}), 409

        # Check existing redemption (application-level check before DB constraint)
        existing = db.query(CouponRedemption).filter_by(coupon_id=coupon.id).first()
        if existing:
            return jsonify({"error": "Conflict", "message": "This coupon has already been redeemed."}), 409

        # D-02: /coupons/apply only validates and returns the discount quote without consuming it.
        # Redemption occurs atomically during checkout (/orders/checkout).
        return jsonify({
            "message": "Coupon applied successfully",
            "coupon": coupon.to_dict(),
            "discount_pct": coupon.discount_pct,
        }), 200

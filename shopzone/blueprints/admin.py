"""Protected administrative and read-only verification endpoints."""

from functools import wraps
import hmac
from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import text
from ..db import get_engine, get_session_factory, reset_db
from ..models import Coupon, CouponRedemption, Order, Payment

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


def require_admin(f):
    """Enforce constant-time X-Admin-Key validation and strict localhost origin check."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Localhost check - fail closed if REMOTE_ADDR is empty or invalid
        client_ip = (request.remote_addr or "").strip()
        allowed_ips = ("127.0.0.1", "::1", "localhost", "testclient")
        if (not client_ip or client_ip not in allowed_ips) and not current_app.config.get("TESTING"):
            return jsonify({
                "error": "Forbidden",
                "message": "Admin endpoints are restricted to local lab execution only."
            }), 403
            
        # 2. Key check - constant-time comparison to prevent timing side channels
        provided_key = request.headers.get("X-Admin-Key", "").strip()
        expected_key = current_app.config.get("ADMIN_KEY", "")
        
        if not provided_key or not hmac.compare_digest(provided_key, expected_key):
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid or missing X-Admin-Key header."
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/health", methods=["GET"])
@require_admin
def admin_health():
    """Verify database engines and connectivity for both modes."""
    db_status = {}
    config = current_app.config
    
    for mode in ["vulnerable", "secure"]:
        try:
            engine = get_engine(mode, config)
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1")).scalar()
                db_status[mode] = "online" if result == 1 else "error"
        except Exception as e:
            db_status[mode] = f"offline: {str(e)}"
            
    is_healthy = all(status == "online" for status in db_status.values())
    
    return jsonify({
        "status": "healthy" if is_healthy else "degraded",
        "databases": db_status,
        "mode_isolation": "physically_separate_sqlite_files",
    }), 200 if is_healthy else 500


@admin_bp.route("/reset", methods=["POST"])
@require_admin
def admin_reset():
    """Wipe and re-seed database tables for clean test execution."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "all").strip().lower()
    
    if target not in ("vulnerable", "secure", "all"):
        return jsonify({
            "error": "Bad Request",
            "message": "Invalid target. Must be 'vulnerable', 'secure', or 'all'."
        }), 400
        
    try:
        reset_db(mode=target, config=current_app.config, seed=True)
        return jsonify({
            "status": "success",
            "message": f"Database(s) '{target}' successfully reset and re-seeded with canonical catalog data."
        }), 200
    except Exception as e:
        current_app.logger.error("Database reset failed for target '%s': %s", target, str(e), exc_info=True)
        return jsonify({
            "error": "Internal Server Error",
            "message": "Database reset failed. Check server logs for details."
        }), 500


# =========================================================================
# Read-Only Verification Endpoints (Correction 5)
# Used by FLOWGUARD to inspect observable ground-truth server state post-attack
# =========================================================================

@admin_bp.route("/verify/order/<mode>/<int:order_id>", methods=["GET"])
@require_admin
def verify_order(mode: str, order_id: int):
    """Inspect order state from the specified mode's database."""
    if mode not in ("vulnerable", "secure"):
        return jsonify({"error": "Bad Request", "message": "Mode must be 'vulnerable' or 'secure'."}), 400
        
    session_factory = get_session_factory(mode, current_app.config)
    session = session_factory()
    try:
        order = session.query(Order).filter_by(id=order_id).first()
        if not order:
            return jsonify({"found": False, "order": None}), 404
        return jsonify({
            "found": True,
            "order": order.to_dict(),
        }), 200
    finally:
        session.close()


@admin_bp.route("/verify/payment/<mode>/<int:order_id>", methods=["GET"])
@require_admin
def verify_payment(mode: str, order_id: int):
    """Inspect payment state for an order from the specified mode's database."""
    if mode not in ("vulnerable", "secure"):
        return jsonify({"error": "Bad Request", "message": "Mode must be 'vulnerable' or 'secure'."}), 400
        
    session_factory = get_session_factory(mode, current_app.config)
    session = session_factory()
    try:
        payment = session.query(Payment).filter_by(order_id=order_id).first()
        if not payment:
            return jsonify({"found": False, "payment": None}), 404
        return jsonify({
            "found": True,
            "payment": payment.to_dict(),
        }), 200
    finally:
        session.close()


@admin_bp.route("/verify/coupon/<mode>/<code>", methods=["GET"])
@require_admin
def verify_coupon(mode: str, code: str):
    """Inspect coupon usage and redemption records from the specified mode's database."""
    if mode not in ("vulnerable", "secure"):
        return jsonify({"error": "Bad Request", "message": "Mode must be 'vulnerable' or 'secure'."}), 400
        
    session_factory = get_session_factory(mode, current_app.config)
    session = session_factory()
    try:
        coupon = session.query(Coupon).filter_by(code=code.upper()).first()
        if not coupon:
            return jsonify({"found": False, "coupon": None}), 404
            
        redemptions = [r.to_dict() for r in coupon.redemptions]
        return jsonify({
            "found": True,
            "coupon": coupon.to_dict(),
            "redemptions": redemptions,
            "redemption_count": len(redemptions),
        }), 200
    finally:
        session.close()


@admin_bp.route("/coupon/<mode>", methods=["POST"])
@require_admin
def admin_create_or_reset_coupon(mode: str):
    """Provision a fresh synthetic coupon or reset an existing coupon's redemption state.
    
    Operates strictly within the specified mode's database, leaving all other records intact.
    """
    if mode not in ("vulnerable", "secure"):
        return jsonify({"error": "Bad Request", "message": "Mode must be 'vulnerable' or 'secure'."}), 400

    data = request.get_json(silent=True) or {}
    code = data.get("code")
    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "Bad Request", "message": "Coupon code (string) is required."}), 400

    code = code.strip().upper()
    discount_pct = data.get("discount_pct", 20)
    max_uses = data.get("max_uses", 1)

    if type(discount_pct) is not int or discount_pct <= 0 or discount_pct > 100:
        return jsonify({"error": "Bad Request", "message": "discount_pct must be an integer between 1 and 100."}), 400
    if type(max_uses) is not int or max_uses <= 0:
        return jsonify({"error": "Bad Request", "message": "max_uses must be a positive integer."}), 400

    session_factory = get_session_factory(mode, current_app.config)
    session = session_factory()
    try:
        coupon = session.query(Coupon).filter_by(code=code).first()
        if coupon:
            session.query(CouponRedemption).filter_by(coupon_id=coupon.id).delete()
            coupon.times_used = 0
            coupon.is_active = True
            coupon.discount_pct = discount_pct
            coupon.max_uses = max_uses
            session.commit()
            return jsonify({
                "status": "success",
                "action": "reset",
                "coupon": coupon.to_dict(),
            }), 200
        else:
            new_coupon = Coupon(
                code=code,
                discount_pct=discount_pct,
                max_uses=max_uses,
                times_used=0,
                is_active=True,
            )
            session.add(new_coupon)
            session.commit()
            return jsonify({
                "status": "success",
                "action": "created",
                "coupon": new_coupon.to_dict(),
            }), 201
    except Exception as e:
        session.rollback()
        current_app.logger.error("Admin coupon creation/reset failed: %s", str(e), exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        session.close()

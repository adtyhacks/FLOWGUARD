"""Secure Mode Blueprint (/sec/api).

Enforces all business invariants:
- BI-1: Payment confirmation gate
- BI-2: Globally single-use coupon enforcement
- BI-3: Idempotent checkout processing
- BI-4: Order ownership verification (IDOR protection via 404)
- BI-5: Strict state machine transition validation
- BI-6: Server-authoritative pricing (ignoring client price/total)
- BI-7: Atomic database transactions under concurrency
"""

from flask import Blueprint
from ..auth_routes import register_auth_endpoints
from ..products import register_product_endpoints
from .sec_cart import register_sec_cart_routes
from .sec_coupons import register_sec_coupon_routes
from .sec_orders import register_sec_order_routes
from .sec_payment import register_sec_payment_routes

sec_bp = Blueprint("secure", __name__, url_prefix="/sec/api")

# Register all route groups
register_auth_endpoints(sec_bp)
register_product_endpoints(sec_bp)
register_sec_cart_routes(sec_bp)
register_sec_coupon_routes(sec_bp)
register_sec_order_routes(sec_bp)
register_sec_payment_routes(sec_bp)

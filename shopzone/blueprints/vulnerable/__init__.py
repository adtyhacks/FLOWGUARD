"""Vulnerable Mode Blueprint (/vuln/api).

Contains deliberately introduced business-logic flaws for security testing.
Each flaw is documented with the test case ID it supports (TC-01 through TC-07).
"""

from flask import Blueprint
from ..auth_routes import register_auth_endpoints
from ..products import register_product_endpoints
from .vuln_cart import register_vuln_cart_routes
from .vuln_coupons import register_vuln_coupon_routes
from .vuln_orders import register_vuln_order_routes
from .vuln_payment import register_vuln_payment_routes

vuln_bp = Blueprint("vulnerable", __name__, url_prefix="/vuln/api")

# Register all route groups
register_auth_endpoints(vuln_bp)
register_product_endpoints(vuln_bp)
register_vuln_cart_routes(vuln_bp)
register_vuln_coupon_routes(vuln_bp)
register_vuln_order_routes(vuln_bp)
register_vuln_payment_routes(vuln_bp)

"""ShopZone Blueprints Package."""

from .admin import admin_bp
from .products import products_bp
from .secure import sec_bp
from .vulnerable import vuln_bp

__all__ = ["admin_bp", "products_bp", "sec_bp", "vuln_bp"]

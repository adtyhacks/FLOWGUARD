"""Product catalog endpoints for ShopZone."""

from flask import Blueprint, g, jsonify
from ..models import Product

products_bp = Blueprint("products", __name__)


def register_product_endpoints(bp: Blueprint) -> None:
    """Register product endpoints on a blueprint."""
    
    @bp.route("/products", methods=["GET"])
    def list_products():
        db = g.db
        products = db.query(Product).order_by(Product.id.asc()).all()
        return jsonify({
            "products": [p.to_dict() for p in products],
            "count": len(products),
        }), 200

    @bp.route("/products/<int:product_id>", methods=["GET"])
    def get_product(product_id: int):
        db = g.db
        product = db.query(Product).filter_by(id=product_id).first()
        if not product:
            return jsonify({
                "error": "Not Found",
                "message": f"Product with ID {product_id} not found."
            }), 404
        return jsonify({
            "product": product.to_dict()
        }), 200


# Register on the mode-neutral products_bp
register_product_endpoints(products_bp)

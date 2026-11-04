"""Vulnerable mode cart operations — /vuln/api/cart/*

No specific vulnerabilities in cart itself; cart is a precondition for checkout flaws.
"""

from flask import Blueprint, g, jsonify, request
from ...auth.middleware import require_auth
from ...models import CartItem, Product


def register_vuln_cart_routes(bp: Blueprint) -> None:
    """Register vulnerable cart endpoints on the provided blueprint."""

    @bp.route("/cart", methods=["GET"])
    @require_auth
    def get_cart():
        db = g.db
        items = db.query(CartItem).filter_by(user_id=g.current_user.id).all()
        items_data = [item.to_dict() for item in items]
        total = sum(i["subtotal_minor_units"] for i in items_data)
        return jsonify({
            "items": items_data,
            "total_minor_units": total,
            "item_count": len(items_data),
        }), 200

    @bp.route("/cart/items", methods=["POST"])
    @require_auth
    def add_to_cart():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON payload."}), 400

        product_id = data.get("product_id")
        quantity = data.get("quantity", 1)

        if not isinstance(product_id, int) or not isinstance(quantity, int) or quantity < 1:
            return jsonify({"error": "Bad Request", "message": "product_id (int) and quantity (int >= 1) required."}), 400

        db = g.db
        product = db.query(Product).filter_by(id=product_id).first()
        if not product:
            return jsonify({"error": "Not Found", "message": f"Product {product_id} not found."}), 404

        if quantity > product.stock:
            return jsonify({"error": "Bad Request", "message": "Requested quantity exceeds available stock."}), 400

        existing = db.query(CartItem).filter_by(user_id=g.current_user.id, product_id=product_id).first()
        if existing:
            existing.quantity += quantity
            db.commit()
            return jsonify({"message": "Cart updated", "cart_item": existing.to_dict()}), 200
        else:
            item = CartItem(user_id=g.current_user.id, product_id=product_id, quantity=quantity)
            db.add(item)
            db.commit()
            return jsonify({"message": "Added to cart", "cart_item": item.to_dict()}), 201

    @bp.route("/cart/items/<int:item_id>", methods=["PUT"])
    @require_auth
    def update_cart_item(item_id: int):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON payload."}), 400

        quantity = data.get("quantity")
        if not isinstance(quantity, int) or quantity < 1:
            return jsonify({"error": "Bad Request", "message": "quantity (int >= 1) required."}), 400

        db = g.db
        item = db.query(CartItem).filter_by(id=item_id, user_id=g.current_user.id).first()
        if not item:
            return jsonify({"error": "Not Found", "message": "Cart item not found."}), 404

        item.quantity = quantity
        db.commit()
        return jsonify({"message": "Cart item updated", "cart_item": item.to_dict()}), 200

    @bp.route("/cart/items/<int:item_id>", methods=["DELETE"])
    @require_auth
    def delete_cart_item(item_id: int):
        db = g.db
        item = db.query(CartItem).filter_by(id=item_id, user_id=g.current_user.id).first()
        if not item:
            return jsonify({"error": "Not Found", "message": "Cart item not found."}), 404

        db.delete(item)
        db.commit()
        return jsonify({"message": "Cart item removed"}), 200

    @bp.route("/cart", methods=["DELETE"])
    @require_auth
    def clear_cart():
        db = g.db
        db.query(CartItem).filter_by(user_id=g.current_user.id).delete()
        db.commit()
        return jsonify({"message": "Cart cleared"}), 200

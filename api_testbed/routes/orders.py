from flask import Blueprint, request, jsonify, g
from ..config import Config
from ..database import get_db_connection
from .auth import require_auth

orders_bp = Blueprint("orders", __name__, url_prefix="/api/v1/orders")

@orders_bp.route("", methods=["GET"])
@require_auth
def list_orders():
    user_id = g.current_user.get("user_id")
    conn = get_db_connection()
    orders = conn.execute("SELECT id, item_name, quantity, total_amount, status, created_at FROM orders WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return jsonify({
        "status": "success",
        "orders": [dict(o) for o in orders]
    }), 200

@orders_bp.route("/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id):
    """
    Get order details by order_id.
    VULNERABLE (BOLA / IDOR):
      - Bob can inspect Alice's purchase receipts, private shipping address, and credit card totals.
    SECURE:
      - Validates order ownership before responding.
    """
    user_id = g.current_user.get("user_id")
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    conn = get_db_connection()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()

    if not order:
        return jsonify({"error": "Not Found", "message": "Order not found"}), 404

    if Config.SECURE_MODE:
        if order["user_id"] != user_id and not is_admin:
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: Unauthorized access to order receipt."
            }), 403

    return jsonify({
        "status": "success",
        "order": {
            "id": order["id"],
            "user_id": order["user_id"],
            "item_name": order["item_name"],
            "quantity": order["quantity"],
            "total_amount": order["total_amount"],
            "shipping_address": order["shipping_address"],
            "status": order["status"],
            "created_at": order["created_at"]
        }
    }), 200

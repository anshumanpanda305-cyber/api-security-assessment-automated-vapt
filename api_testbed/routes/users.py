from flask import Blueprint, request, jsonify, g
from ..config import Config
from ..database import get_db_connection
from .auth import require_auth

users_bp = Blueprint("users", __name__, url_prefix="/api/v1/users")

@users_bp.route("/<int:user_id>/profile", methods=["GET"])
@require_auth
def get_user_profile(user_id):
    """
    User profile retrieval endpoint.
    VULNERABLE:
      - BOLA / IDOR: No ownership check. Any logged-in user can access any other user's profile.
      - Excessive Data Exposure: Returns password_hash, SSN, credit_balance.
    SECURE:
      - Authorization check: user can only view their own profile (or admin).
      - Data filtering: Excludes password_hash and sensitive internal fields.
    """
    current_user_id = g.current_user.get("user_id")
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    if Config.SECURE_MODE:
        # Strict Object Level Authorization
        if current_user_id != user_id and not is_admin:
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: You do not have permission to view this profile."
            }), 403

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Not Found", "message": "User not found"}), 404

    if Config.SECURE_MODE:
        # Filtered safe response
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "created_at": user["created_at"]
        }), 200
    else:
        # VULNERABLE: Returns sensitive credentials and fields
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "is_admin": bool(user["is_admin"]),
            "credit_balance": user["credit_balance"],
            "ssn_last4": user["ssn_last4"],
            "password_hash": user["password_hash"], # Excessive Data Exposure
            "created_at": user["created_at"]
        }), 200

@users_bp.route("/<int:user_id>/profile", methods=["PUT"])
@require_auth
def update_user_profile(user_id):
    """
    User profile update endpoint.
    VULNERABLE:
      - BOLA: Can update any other user's record.
      - Mass Assignment: Allows modifying 'role', 'is_admin', and 'credit_balance'.
    SECURE:
      - Ownership check.
      - Whitelist update fields (email only).
    """
    current_user_id = g.current_user.get("user_id")
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    if Config.SECURE_MODE:
        if current_user_id != user_id and not is_admin:
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: You can only update your own profile."
            }), 403

    data = request.get_json(silent=True) or {}
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Not Found", "message": "User not found"}), 404

    if Config.SECURE_MODE:
        # Whitelisted fields only
        new_email = data.get("email", user["email"])
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    else:
        # VULNERABLE: Mass assignment allows updating privileged columns
        new_email = data.get("email", user["email"])
        new_role = data.get("role", user["role"])
        new_is_admin = 1 if data.get("is_admin") in (True, 1, "1", "true") else user["is_admin"]
        new_balance = data.get("credit_balance", user["credit_balance"])

        conn.execute(
            "UPDATE users SET email = ?, role = ?, is_admin = ?, credit_balance = ? WHERE id = ?",
            (new_email, new_role, new_is_admin, new_balance, user_id)
        )

    conn.commit()
    updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Profile updated successfully",
        "user": {
            "id": updated["id"],
            "username": updated["username"],
            "email": updated["email"],
            "role": updated["role"],
            "is_admin": bool(updated["is_admin"]),
            "credit_balance": updated["credit_balance"]
        }
    }), 200

from flask import Blueprint, request, jsonify, g
from ..config import Config
from ..database import get_db_connection
from .auth import require_auth

admin_bp = Blueprint("admin", __name__, url_prefix="/api/v1/admin")

@admin_bp.route("/users", methods=["GET"])
@require_auth
def admin_list_users():
    """
    Administrative user management endpoint.
    VULNERABLE (BFLA - Broken Function Level Authorization):
      - Checks authentication, but forgets to check if role == 'admin'.
      - Any standard user can access full user database and password hashes!
    SECURE:
      - Validates role == 'admin' and is_admin == True.
    """
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    if Config.SECURE_MODE:
        if not is_admin:
            return jsonify({
                "error": "Forbidden",
                "message": "Administrative privileges required to access this endpoint."
            }), 403

    conn = get_db_connection()
    users = conn.execute("SELECT id, username, email, role, is_admin, credit_balance, created_at FROM users").fetchall()
    conn.close()

    return jsonify({
        "status": "success",
        "total_users": len(users),
        "users": [dict(u) for u in users]
    }), 200

@admin_bp.route("/system/status", methods=["GET"])
@require_auth
def system_status():
    """Administrative system diagnostics."""
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    if Config.SECURE_MODE:
        if not is_admin:
            return jsonify({
                "error": "Forbidden",
                "message": "Administrative privileges required."
            }), 403

    import platform
    import sys

    return jsonify({
        "status": "operational",
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "python_version": sys.version,
            "mode": "SECURE" if Config.SECURE_MODE else "VULNERABLE"
        }
    }), 200

@admin_bp.route("/export-db", methods=["POST"])
@require_auth
def export_database():
    """Administrative database export trigger."""
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    if Config.SECURE_MODE:
        if not is_admin:
            return jsonify({"error": "Forbidden", "message": "Admin authorization failed"}), 403

    return jsonify({
        "status": "success",
        "message": "Database backup archive generated",
        "archive_url": "/backups/vapt_testbed_backup.sqlite"
    }), 200

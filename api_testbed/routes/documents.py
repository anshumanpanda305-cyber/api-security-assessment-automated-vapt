from flask import Blueprint, request, jsonify, g
from ..config import Config
from ..database import get_db_connection
from .auth import require_auth

documents_bp = Blueprint("documents", __name__, url_prefix="/api/v1/documents")

@documents_bp.route("", methods=["GET"])
@require_auth
def list_documents():
    """List documents for the currently logged in user."""
    user_id = g.current_user.get("user_id")
    conn = get_db_connection()
    docs = conn.execute("SELECT id, title, classification, created_at FROM documents WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return jsonify({
        "status": "success",
        "documents": [dict(d) for d in docs]
    }), 200

@documents_bp.route("/<int:doc_id>", methods=["GET"])
@require_auth
def get_document(doc_id):
    """
    Get a single document by ID.
    VULNERABLE (BOLA / IDOR - OWASP API1):
      - Directly queries document by ID without verifying if the requesting user owns the document.
      - Bob (User 2) can view Alice's (User 1) confidential documents by passing doc_id=1.
    SECURE:
      - Validates that doc['user_id'] == current_user['user_id'] or user is admin.
    """
    user_id = g.current_user.get("user_id")
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    conn = get_db_connection()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()

    if not doc:
        return jsonify({"error": "Not Found", "message": "Document not found"}), 404

    if Config.SECURE_MODE:
        # Strict Object-Level Authorization Check
        if doc["user_id"] != user_id and not is_admin:
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: You are not authorized to view this document."
            }), 403

    return jsonify({
        "status": "success",
        "document": {
            "id": doc["id"],
            "owner_user_id": doc["user_id"],
            "title": doc["title"],
            "content": doc["content"],
            "classification": doc["classification"],
            "created_at": doc["created_at"]
        }
    }), 200

@documents_bp.route("/<int:doc_id>", methods=["DELETE"])
@require_auth
def delete_document(doc_id):
    """Delete a document by ID with BOLA in vulnerable mode."""
    user_id = g.current_user.get("user_id")
    is_admin = g.current_user.get("is_admin", False) or g.current_user.get("role") == "admin"

    conn = get_db_connection()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()

    if not doc:
        conn.close()
        return jsonify({"error": "Not Found", "message": "Document not found"}), 404

    if Config.SECURE_MODE:
        if doc["user_id"] != user_id and not is_admin:
            conn.close()
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: You can only delete your own documents."
            }), 403

    conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": f"Document {doc_id} deleted successfully"}), 200

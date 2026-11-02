import sqlite3
from flask import Blueprint, request, jsonify
from ..config import Config
from ..database import get_db_connection

products_bp = Blueprint("products", __name__, url_prefix="/api/v1/products")

@products_bp.route("/search", methods=["GET"])
def search_products():
    """
    Product search endpoint.
    VULNERABLE (SQL Injection - OWASP API8 / CWE-89):
      - Directly formats user input string into SQLite query!
      - Allows UNION-based extraction of user credentials or boolean/error-based injection.
    SECURE:
      - Uses parameterized SQLite queries with placeholder '?'.
    """
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"status": "success", "products": []}), 200

    conn = get_db_connection()
    try:
        if Config.SECURE_MODE:
            # Secure parameterized query
            query = "SELECT id, name, category, price, stock, description FROM products WHERE name LIKE ? OR description LIKE ?"
            param = f"%{q}%"
            cursor = conn.execute(query, (param, param))
            rows = cursor.fetchall()
        else:
            # VULNERABLE: Direct string formatting into SQL query
            raw_query = f"SELECT id, name, category, price, stock, description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
            cursor = conn.cursor()
            cursor.execute(raw_query)
            rows = cursor.fetchall()

        products = []
        for r in rows:
            products.append({
                "id": r[0],
                "name": r[1],
                "category": r[2],
                "price": r[3],
                "stock": r[4],
                "description": r[5]
            })

        conn.close()
        return jsonify({
            "status": "success",
            "query": q,
            "count": len(products),
            "products": products
        }), 200

    except sqlite3.OperationalError as e:
        conn.close()
        if Config.SECURE_MODE:
            return jsonify({"error": "Bad Request", "message": "Invalid search parameters"}), 400
        else:
            # Leaking SQL error message directly to the client (Error-based SQLi indicator)
            return jsonify({
                "error": "Database Operational Error",
                "sql_error": str(e),
                "debug_query": raw_query
            }), 500

@products_bp.route("", methods=["GET"])
def list_products():
    """
    List products catalog with pagination.
    VULNERABLE: Unrestricted Resource Consumption (limit can be 1,000,000).
    SECURE: Strict limit clamping (max 50 items).
    """
    limit_str = request.args.get("limit", "10")
    offset_str = request.args.get("offset", "0")

    try:
        limit = int(limit_str)
        offset = int(offset_str)
    except ValueError:
        limit, offset = 10, 0

    if Config.SECURE_MODE:
        # Enforce reasonable bounds to prevent resource exhaustion
        limit = max(1, min(limit, 50))
        offset = max(0, offset)

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, category, price, stock, description FROM products LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()
    conn.close()

    return jsonify({
        "status": "success",
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "products": [dict(r) for r in rows]
    }), 200

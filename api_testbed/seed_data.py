import os
from .database import get_db_connection, init_db, hash_password
from .config import Config

def seed_database():
    """Seed the SQLite database with realistic initial data for VAPT testing."""
    # Ensure tables exist
    init_db()

    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear existing data for clean re-runs
    cursor.execute("DELETE FROM documents")
    cursor.execute("DELETE FROM orders")
    cursor.execute("DELETE FROM products")
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM login_attempts")

    # 1. Seed Users
    # Alice: Victim User (ID: 1)
    # Bob: Attacker / Normal User (ID: 2)
    # Charlie: Another normal user (ID: 3)
    # Admin: Administrator User (ID: 4)
    users = [
        (1, "alice", "alice@enterprise-corp.local", hash_password("Password123!"), "user", 0, 250.0, "1122"),
        (2, "bob", "bob@enterprise-corp.local", hash_password("Password123!"), "user", 0, 50.0, "3344"),
        (3, "charlie", "charlie@enterprise-corp.local", hash_password("Password123!"), "user", 0, 120.0, "5566"),
        (4, "admin", "admin@enterprise-corp.local", hash_password("AdminSecurePass!"), "admin", 1, 9999.0, "9999")
    ]

    cursor.executemany("""
    INSERT INTO users (id, username, email, password_hash, role, is_admin, credit_balance, ssn_last4)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, users)

    # 2. Seed Documents (BOLA Target)
    documents = [
        (1, 1, "Q4 Financial Forecast & M&A Strategy", "Confidential: Acquisition target TechNova Inc at $45M valuation. Board approved.", "RESTRICTED"),
        (2, 1, "Alice Executive Compensation Package", "Base salary: $185,000. Annual stock option grant: 10,000 RSUs. Routing #021000021.", "CONFIDENTIAL"),
        (3, 2, "Bob's Project Todo List", "Items: 1. Complete sprint task 2. Submit expense report 3. Clean desk.", "INTERNAL"),
        (4, 3, "Charlie Public Presentation Slides", "Public slide deck for API Security Summit 2026.", "PUBLIC"),
        (5, 4, "Enterprise Infrastructure Master Keys", "AWS Root Account ARN: arn:aws:iam::123456789012:root. Production Bastion SSH Key.", "RESTRICTED")
    ]

    cursor.executemany("""
    INSERT INTO documents (id, user_id, title, content, classification)
    VALUES (?, ?, ?, ?, ?)
    """, documents)

    # 3. Seed Orders (BOLA Target)
    orders = [
        (1, 1, "MacBook Pro M3 Max 16-inch 64GB", 1, 3999.00, "742 Evergreen Terrace, Springfield (Private Residence)"),
        (2, 1, "Enterprise Threat Intel Subscription", 1, 12000.00, "Corporate HQ - 100 Main St, Suite 400"),
        (3, 2, "Logitech MX Master 3S Mouse", 1, 99.99, "123 Bob Street, Apt 4B"),
        (4, 3, "Dell UltraSharp 32-inch 4K Monitor", 2, 1599.98, "456 Charlie Ave, Floor 2"),
        (5, 4, "Data Center Server Rack Enclosure", 1, 4500.00, "SecOps Data Center Cage 12")
    ]

    cursor.executemany("""
    INSERT INTO orders (id, user_id, item_name, quantity, total_amount, shipping_address)
    VALUES (?, ?, ?, ?, ?, ?)
    """, orders)

    # 4. Seed Products (Catalog for SQL Injection & Resource testing)
    products = [
        (1, "SecureGate Hardware Firewall Pro", "Security", 1299.99, 15, "Enterprise-grade hardware firewall with deep packet inspection."),
        (2, "CryptoKey FIDO2 Security Token", "Authentication", 49.99, 150, "Hardware USB-C security key supporting WebAuthn and PKI."),
        (3, "CloudShield WAF License - 1 Year", "Software", 499.00, 50, "Web application firewall protection with automated threat blocking."),
        (4, "ZeroTrust Endpoint Agent", "Endpoint", 15.00, 1000, "Endpoint detection and continuous posture assessment agent."),
        (5, "ThreatScope SIEM Starter Pack", "Monitoring", 2499.00, 10, "Security information and event management collector."),
        (6, "Quantum Vault HSM Module", "Hardware", 8500.00, 5, "FIPS 140-2 Level 3 certified Hardware Security Module.")
    ]

    cursor.executemany("""
    INSERT INTO products (id, name, category, price, stock, description)
    VALUES (?, ?, ?, ?, ?, ?)
    """, products)

    conn.commit()
    conn.close()
    print("[+] Database seeded successfully with test records.")

if __name__ == "__main__":
    seed_database()

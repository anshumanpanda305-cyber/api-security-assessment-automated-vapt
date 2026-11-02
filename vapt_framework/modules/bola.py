from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class BolaScanner(BaseModule):
    name = "Broken Object Level Authorization (BOLA/IDOR) Scanner"
    description = "Tests cross-tenant object access across documents, orders, and user profiles using multi-user tokens"
    category = "API1:2023 - Broken Object Level Authorization"

    def run(self) -> List[Vulnerability]:
        findings = []

        bob_token = self.context.get("bob_token")
        alice_token = self.context.get("alice_token")

        if not bob_token:
            # Login as Bob (Attacker)
            res, _, _ = self.requester.request(
                method="POST",
                path="/api/v1/auth/login",
                json_data={
                    "username": self.config.get("test_accounts.bob.username", "bob"),
                    "password": self.config.get("test_accounts.bob.password", "Password123!")
                }
            )
            if res.status_code == 200:
                bob_token = res.json().get("access_token")
                self.context["bob_token"] = bob_token

        if not bob_token:
            return findings

        # TARGET 1: Documents BOLA (/api/v1/documents/{id})
        # Alice owns Document 1 ("Q4 Financial Forecast & M&A Strategy")
        # Bob (user_id=2) attempts to read Document 1
        doc_res, doc_req_poc, doc_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/documents/1",
            token=bob_token
        )

        if doc_res.status_code == 200:
            doc_data = doc_res.json().get("document", {})
            owner_id = doc_data.get("owner_user_id")
            if owner_id == 1 or "M&A" in str(doc_data):
                findings.append(Vulnerability(
                    vuln_id="VAPT-BOLA-001",
                    title="Broken Object Level Authorization (BOLA) in Document Retrieval",
                    severity="CRITICAL",
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    owasp_category="API1:2023 - Broken Object Level Authorization",
                    cwe_id="CWE-639: Authorization Bypass Through User-Controlled Key",
                    endpoint="/api/v1/documents/{id}",
                    method="GET",
                    description=(
                        "The document retrieval endpoint fails to validate whether the requesting authenticated user "
                        "has authorization to view the requested document. An authenticated attacker (Bob, ID: 2) "
                        "successfully retrieved confidential M&A strategy documents belonging to Alice (ID: 1) "
                        "by simply substituting the document ID parameter."
                    ),
                    business_impact=(
                        "Mass unauthorized data exfiltration. Attackers can iterate through numeric or predictable document "
                        "identifiers to download all corporate documents, financial records, and confidential assets "
                        "across all tenants."
                    ),
                    remediation=(
                        "1. Implement server-side authorization checks comparing the resource owner ID (document.user_id) "
                        "with the user identity from the verified JWT claims (current_user.id).\n"
                        "2. Implement role-based or attribute-based access control (RBAC/ABAC) policies.\n"
                        "3. Use indirect or non-guessable identifiers (e.g. UUIDv4) in combination with ownership validation."
                    ),
                    poc_request=doc_req_poc,
                    poc_response=doc_res_poc,
                    evidence=f"Attacker (Bob, ID: 2) accessed Alice's Document 1: Title='{doc_data.get('title')}', Classification='{doc_data.get('classification')}'"
                ))

        # TARGET 2: Orders BOLA (/api/v1/orders/{id})
        # Alice owns Order 1 (MacBook Pro shipped to Alice's private address)
        order_res, order_req_poc, order_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/orders/1",
            token=bob_token
        )

        if order_res.status_code == 200:
            order_data = order_res.json().get("order", {})
            order_user_id = order_data.get("user_id")
            if order_user_id == 1 or "MacBook" in str(order_data):
                findings.append(Vulnerability(
                    vuln_id="VAPT-BOLA-002",
                    title="Broken Object Level Authorization (BOLA) in Order Receipts",
                    severity="HIGH",
                    cvss_score=7.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    owasp_category="API1:2023 - Broken Object Level Authorization",
                    cwe_id="CWE-639: Authorization Bypass Through User-Controlled Key",
                    endpoint="/api/v1/orders/{id}",
                    method="GET",
                    description=(
                        "The order details endpoint fails to restrict access to the customer who placed the order. "
                        "An authenticated user can access another customer's order receipt, order history, and physical shipping address."
                    ),
                    business_impact=(
                        "Exposure of Personally Identifiable Information (PII) including full delivery addresses, "
                        "purchase histories, and payment totals, causing severe regulatory and GDPR violations."
                    ),
                    remediation=(
                        "Validate that order.user_id matches the authenticated user's ID before returning order details. "
                        "Return HTTP 403 Forbidden or 404 Not Found if unauthorized."
                    ),
                    poc_request=order_req_poc,
                    poc_response=order_res_poc,
                    evidence=f"Attacker Bob accessed Alice's Order 1: Item='{order_data.get('item_name')}', Shipping Address='{order_data.get('shipping_address')}'"
                ))

        # TARGET 3: User Profile BOLA (/api/v1/users/{id}/profile)
        profile_res, profile_req_poc, profile_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/users/1/profile",
            token=bob_token
        )

        if profile_res.status_code == 200:
            profile_data = profile_res.json()
            if profile_data.get("id") == 1 or profile_data.get("username") == "alice":
                findings.append(Vulnerability(
                    vuln_id="VAPT-BOLA-003",
                    title="Insecure Direct Object Reference (IDOR) on User Profile Endpoint",
                    severity="HIGH",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    owasp_category="API1:2023 - Broken Object Level Authorization",
                    cwe_id="CWE-639: Authorization Bypass Through User-Controlled Key",
                    endpoint="/api/v1/users/{id}/profile",
                    method="GET",
                    description=(
                        "The profile endpoint allows any authenticated user to view the full profile and internal "
                        "attributes of any other registered user by changing the ID in the URL path."
                    ),
                    business_impact="Account enumeration and unauthorized profiling of users across the enterprise.",
                    remediation="Restrict access to the logged-in user's own profile or require administrator privileges.",
                    poc_request=profile_req_poc,
                    poc_response=profile_res_poc,
                    evidence=f"Attacker Bob accessed Alice's profile (ID 1): Email='{profile_data.get('email')}'"
                ))

        return findings

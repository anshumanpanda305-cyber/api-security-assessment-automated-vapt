from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class MassAssignmentScanner(BaseModule):
    name = "Object Property Level Authorization Scanner (Mass Assignment & Data Exposure)"
    description = "Tests for unauthorized property binding (mass assignment) and excessive data exposure in JSON responses"
    category = "API3:2023 - Broken Object Property Level Authorization"

    def run(self) -> List[Vulnerability]:
        findings = []
        bob_token = self.context.get("bob_token")
        if not bob_token:
            return findings

        # 1. Excessive Data Exposure Check
        prof_res, prof_req_poc, prof_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/users/2/profile",
            token=bob_token
        )

        if prof_res.status_code == 200:
            data = prof_res.json()
            leaked_fields = []
            if "password_hash" in data:
                leaked_fields.append("password_hash")
            if "ssn_last4" in data:
                leaked_fields.append("ssn_last4")

            if leaked_fields:
                findings.append(Vulnerability(
                    vuln_id="VAPT-PROP-001",
                    title="Excessive Data Exposure in User Profile Response",
                    severity="HIGH",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    owasp_category="API3:2023 - Broken Object Property Level Authorization",
                    cwe_id="CWE-213: Exposure of Sensitive Information Due to Incompatible Policies",
                    endpoint="/api/v1/users/{id}/profile",
                    method="GET",
                    description=(
                        f"The API endpoint returns internal and sensitive database fields ({', '.join(leaked_fields)}) "
                        "in its response payload. While clients might only display public profile details, "
                        "attackers intercepting HTTP traffic directly extract sensitive credentials and personal data."
                    ),
                    business_impact=(
                        "Credential exposure. Leaked password hashes can be cracked offline, leading to full "
                        "account takeover and identity theft."
                    ),
                    remediation=(
                        "1. Implement strict Data Transfer Objects (DTOs) or response serializers that explicitly whitelist "
                        "public fields.\n"
                        "2. Never serialize internal database models directly to API JSON responses.\n"
                        "3. Explicitly purge sensitive attributes like password hashes and SSNs."
                    ),
                    poc_request=prof_req_poc,
                    poc_response=prof_res_poc,
                    evidence=f"Sensitive fields found in response: {leaked_fields}"
                ))

        # 2. Mass Assignment Privilege Escalation Check
        update_res, update_req_poc, update_res_poc = self.requester.request(
            method="PUT",
            path="/api/v1/users/2/profile",
            token=bob_token,
            json_data={
                "email": "bob_updated@enterprise-corp.local",
                "role": "admin",
                "is_admin": True,
                "credit_balance": 999999.0
            }
        )

        if update_res.status_code == 200:
            up_data = update_res.json().get("user", {})
            if up_data.get("role") == "admin" or up_data.get("is_admin") is True or up_data.get("credit_balance") == 999999.0:
                findings.append(Vulnerability(
                    vuln_id="VAPT-PROP-002",
                    title="Mass Assignment Enabling Privilege Escalation",
                    severity="HIGH",
                    cvss_score=8.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    owasp_category="API3:2023 - Broken Object Property Level Authorization",
                    cwe_id="CWE-915: Improperly Controlled Modification of Dynamically Determined Object Attributes",
                    endpoint="/api/v1/users/{id}/profile",
                    method="PUT",
                    description=(
                        "The user profile update endpoint binds arbitrary client-supplied JSON parameters "
                        "directly to database columns without input property validation. A standard user successfully "
                        "escalated their own role to 'admin' and assigned themselves 999,999 in credit balance."
                    ),
                    business_impact=(
                        "Privilege escalation and unauthorized balance manipulation. Attackers grant themselves administrative "
                        "rights and manipulate financial or transactional records."
                    ),
                    remediation=(
                        "1. Implement strict schema validation and parameter whitelisting for all incoming payloads.\n"
                        "2. Separate user-editable fields (e.g. bio, display name) from internal state fields (role, is_admin, balance).\n"
                        "3. Enforce immutability on sensitive object properties at the API controller layer."
                    ),
                    poc_request=update_req_poc,
                    poc_response=update_res_poc,
                    evidence=f"User updated privileged fields: role='{up_data.get('role')}', is_admin={up_data.get('is_admin')}, credit_balance={up_data.get('credit_balance')}"
                ))

        return findings

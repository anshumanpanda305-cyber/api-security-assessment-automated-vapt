from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class BflaScanner(BaseModule):
    name = "Broken Function Level Authorization (BFLA) Scanner"
    description = "Tests privilege escalation by calling administrative functions using standard user credentials"
    category = "API5:2023 - Broken Function Level Authorization"

    def run(self) -> List[Vulnerability]:
        findings = []
        bob_token = self.context.get("bob_token")

        if not bob_token:
            return findings

        # Test 1: Administrative User Management (/api/v1/admin/users)
        admin_res, admin_req_poc, admin_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/admin/users",
            token=bob_token
        )

        if admin_res.status_code == 200:
            data = admin_res.json()
            findings.append(Vulnerability(
                vuln_id="VAPT-BFLA-001",
                title="Broken Function Level Authorization - Unrestricted Admin Access",
                severity="CRITICAL",
                cvss_score=8.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                owasp_category="API5:2023 - Broken Function Level Authorization",
                cwe_id="CWE-285: Improper Authorization",
                endpoint="/api/v1/admin/users",
                method="GET",
                description=(
                    "The administrative endpoint '/api/v1/admin/users' verifies that a token is provided, "
                    "but fails to enforce role-based access control (RBAC). A low-privileged standard user (Bob) "
                    "can invoke administrative functions to enumerate all system accounts and user details."
                ),
                business_impact=(
                    "Vertical privilege escalation. Low-privileged users can execute administrative operations, "
                    "access internal employee databases, and manipulate privileged enterprise resources."
                ),
                remediation=(
                    "1. Implement strict server-side role and permission checks on all administrative endpoints "
                    "(e.g., ensure user.role == 'admin' and user.is_admin == True).\n"
                    "2. Adopt a centralized authorization policy enforcement point (PEP) or middleware decorator.\n"
                    "3. Return HTTP 403 Forbidden whenever a non-administrative principal attempts access."
                ),
                poc_request=admin_req_poc,
                poc_response=admin_res_poc,
                evidence=f"Standard user Bob (role: 'user') received HTTP 200 with {data.get('total_users', 'multiple')} system user accounts."
            ))

        # Test 2: Administrative Database Export (/api/v1/admin/export-db)
        export_res, export_req_poc, export_res_poc = self.requester.request(
            method="POST",
            path="/api/v1/admin/export-db",
            token=bob_token
        )

        if export_res.status_code == 200:
            findings.append(Vulnerability(
                vuln_id="VAPT-BFLA-002",
                title="Unauthorized Administrative Database Export Trigger",
                severity="CRITICAL",
                cvss_score=8.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                owasp_category="API5:2023 - Broken Function Level Authorization",
                cwe_id="CWE-285: Improper Authorization",
                endpoint="/api/v1/admin/export-db",
                method="POST",
                description=(
                    "A standard non-administrative user was able to execute the administrative database export routine, "
                    "allowing unauthorized initiation of full database backups."
                ),
                business_impact="Unauthorized data backup generation and full database dump exposure.",
                remediation="Enforce administrative authorization checks before triggering backup or export tasks.",
                poc_request=export_req_poc,
                poc_response=export_res_poc,
                evidence="Standard user Bob successfully executed administrative POST /api/v1/admin/export-db with HTTP 200 OK."
            ))

        return findings

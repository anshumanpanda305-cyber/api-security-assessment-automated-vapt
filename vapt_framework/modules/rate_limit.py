from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class RateLimitScanner(BaseModule):
    name = "Unrestricted Resource Consumption & Rate Limiting Scanner"
    description = "Tests authentication and sensitive endpoints for lack of request throttling and brute-force protections"
    category = "API4:2023 - Unrestricted Resource Consumption"

    def run(self) -> List[Vulnerability]:
        findings = []

        burst_count = 10
        received_429 = False
        last_req_poc = ""
        last_res_poc = ""

        # Rapidly issue invalid login requests
        for i in range(burst_count):
            res, req_poc, res_poc = self.requester.request(
                method="POST",
                path="/api/v1/auth/login",
                json_data={
                    "username": "rate_test_user",
                    "password": f"WrongPassword_{i}!"
                }
            )
            last_req_poc = req_poc
            last_res_poc = res_poc

            if res.status_code == 429:
                received_429 = True
                break

        if not received_429:
            findings.append(Vulnerability(
                vuln_id="VAPT-RATE-001",
                title="Missing Rate Limiting on Authentication Endpoint",
                severity="MEDIUM",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_category="API4:2023 - Unrestricted Resource Consumption",
                cwe_id="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                endpoint="/api/v1/auth/login",
                method="POST",
                description=(
                    "The authentication endpoint does not enforce rate limiting or lockout policies on repeated "
                    f"failed authentication requests. {burst_count} rapid consecutive login requests were executed "
                    "without triggering an HTTP 429 Too Many Requests or exponential backoff."
                ),
                business_impact=(
                    "Enables credential stuffing, brute-force password guessing attacks, and distributed denial of service (DDoS)."
                ),
                remediation=(
                    "1. Enforce IP-based and user-account-based rate limiting on authentication routes (e.g. 5 attempts/minute).\n"
                    "2. Return HTTP 429 Too Many Requests with a 'Retry-After' header.\n"
                    "3. Implement CAPTCHA or progressive delays on repeated failures."
                ),
                poc_request=last_req_poc,
                poc_response=last_res_poc,
                evidence=f"Issued {burst_count} rapid login attempts; all processed without HTTP 429 response."
            ))

        return findings

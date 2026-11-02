from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class MisconfigScanner(BaseModule):
    name = "Security Misconfiguration Scanner"
    description = "Tests for CORS misconfigurations, missing defense-in-depth security headers, and debug endpoint leakage"
    category = "API8:2023 - Security Misconfiguration"

    def run(self) -> List[Vulnerability]:
        findings = []

        # 1. CORS Assessment
        cors_res, cors_req_poc, cors_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/documents",
            headers={"Origin": "https://evil-attacker.com"}
        )

        acao = cors_res.headers.get("Access-Control-Allow-Origin", "")
        acac = cors_res.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*" or (acao == "https://evil-attacker.com" and acac == "true"):
            findings.append(Vulnerability(
                vuln_id="VAPT-MISC-001",
                title="Insecure Cross-Origin Resource Sharing (CORS) Policy",
                severity="HIGH" if acac == "true" else "MEDIUM",
                cvss_score=7.1 if acac == "true" else 5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" if acac == "true" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_category="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
                endpoint="/api/v1/*",
                method="GET / OPTIONS",
                description=(
                    "The API server dynamically reflects arbitrary Origin headers with "
                    f"Access-Control-Allow-Credentials: {acac} (or provides a wildcard '*' policy). "
                    "This allows malicious websites visited by an authenticated victim to issue cross-origin requests "
                    "and read sensitive API responses directly."
                ),
                business_impact=(
                    "Cross-Site Data Theft. Attackers can lure authenticated employees to a malicious site "
                    "and exfiltrate documents, profile information, and private customer data."
                ),
                remediation=(
                    "1. Avoid setting Access-Control-Allow-Origin to '*' on authenticated endpoints.\n"
                    "2. Avoid reflecting the client's Origin header blindly.\n"
                    "3. Implement an explicit whitelist of trusted frontend domains."
                ),
                poc_request=cors_req_poc,
                poc_response=cors_res_poc,
                evidence=f"Reflected Origin='{acao}' with Allow-Credentials='{acac}'"
            ))

        # 2. Missing Security Headers
        root_res, root_req_poc, root_res_poc = self.requester.request(
            method="GET",
            path="/"
        )

        missing_headers = []
        expected_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000"
        }

        for h, expected in expected_headers.items():
            if h not in root_res.headers:
                missing_headers.append(h)

        if missing_headers:
            findings.append(Vulnerability(
                vuln_id="VAPT-MISC-002",
                title="Missing Standard Defense-in-Depth HTTP Security Headers",
                severity="LOW",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_category="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-693: Protection Mechanism Failure",
                endpoint="Global Headers",
                method="ALL",
                description=(
                    f"The server is missing standard protective security headers: {', '.join(missing_headers)}. "
                    "These headers instruct modern web browsers and API consumers to enforce MIME sniffing protection, "
                    "clickjacking defense, and HTTPS transport security."
                ),
                business_impact="Increased susceptibility to MIME-type confusion attacks and clickjacking.",
                remediation=(
                    "Configure API middleware or reverse proxy (Nginx/Cloudflare) to send:\n"
                    "- X-Content-Type-Options: nosniff\n"
                    "- X-Frame-Options: DENY\n"
                    "- Content-Security-Policy: default-src 'self'\n"
                    "- Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
                poc_request=root_req_poc,
                poc_response=root_res_poc,
                evidence=f"Missing headers from response: {missing_headers}"
            ))

        # 3. Server Banner & Technology Fingerprinting Disclosure
        server_val = root_res.headers.get("Server", "")
        powered_val = root_res.headers.get("X-Powered-By", "")
        if "werkzeug" in server_val.lower() or "python" in server_val.lower() or powered_val:
            findings.append(Vulnerability(
                vuln_id="VAPT-MISC-003",
                title="Server Technology & Version Fingerprint Disclosure",
                severity="INFO",
                cvss_score=2.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_category="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                endpoint="Global Headers",
                method="ALL",
                description=(
                    f"The server leaks detailed framework and version information via headers: "
                    f"Server='{server_val}', X-Powered-By='{powered_val}'. "
                    "This helps attackers target known CVEs specific to the running version."
                ),
                business_impact="Assists attackers during reconnaissance and vulnerability mapping.",
                remediation="Suppress or sanitize Server and X-Powered-By headers in production environments.",
                poc_request=root_req_poc,
                poc_response=root_res_poc,
                evidence=f"Leaked headers: Server='{server_val}', X-Powered-By='{powered_val}'"
            ))

        # 4. Debug Configuration Exposure
        debug_res, debug_req_poc, debug_res_poc = self.requester.request(
            method="GET",
            path="/api/v1/tools/debug/config"
        )
        if debug_res.status_code == 200:
            findings.append(Vulnerability(
                vuln_id="VAPT-MISC-004",
                title="Unauthenticated Debug Configuration Endpoint Disclosed",
                severity="HIGH",
                cvss_score=8.2,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                owasp_category="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-215: Insertion of Sensitive Information Into Debugging Code",
                endpoint="/api/v1/tools/debug/config",
                method="GET",
                description=(
                    "An unauthenticated debug endpoint '/api/v1/tools/debug/config' is accessible in production, "
                    "exposing secret keys, database file locations, and internal environment variables."
                ),
                business_impact="Critical credential and configuration exposure allowing lateral movement and full compromise.",
                remediation="Disable all diagnostic, profiling, and debug endpoints in production deployments.",
                poc_request=debug_req_poc,
                poc_response=debug_res_poc,
                evidence="Debug endpoint returned active secret keys and server configuration."
            ))

        return findings

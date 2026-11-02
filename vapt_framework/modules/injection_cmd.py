import re
from typing import List
from .base import BaseModule
from ..core.vulnerability import Vulnerability

class CommandInjectionScanner(BaseModule):
    name = "OS Command Injection Scanner"
    description = "Tests utility and system diagnostic endpoints for operating system command injection flaws"
    category = "CWE-78 / OS Command Injection"

    def run(self) -> List[Vulnerability]:
        findings = []

        # Safe verification token
        token_str = "VAPT_CMD_INJECTION_TRIGGERED_SUCCESS"
        payloads = [
            f"127.0.0.1 | echo {token_str}",
            f"127.0.0.1 & echo {token_str}",
            "127.0.0.1 & whoami"
        ]

        for payload in payloads:
            res, req_poc, res_poc = self.requester.request(
                method="GET",
                path="/api/v1/tools/ping",
                params={"host": payload}
            )

            if res.status_code == 200:
                res_body = res.text
                if token_str in res_body or "whoami" in res_body:
                    findings.append(Vulnerability(
                        vuln_id="VAPT-CMD-001",
                        title="Remote OS Command Injection in Diagnostic Ping Utility",
                        severity="CRITICAL",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        owasp_category="OWASP API Top 10 - Injection Flaws",
                        cwe_id="CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                        endpoint="/api/v1/tools/ping",
                        method="GET",
                        description=(
                            "The network diagnostic ping endpoint passes the user-supplied 'host' query parameter "
                            "directly to the system shell without input sanitization or argument separation. "
                            "An attacker can append arbitrary system shell commands (e.g. '| echo ...' or '; whoami') "
                            "which execute with the privileges of the running API server process."
                        ),
                        business_impact=(
                            "Full Remote Code Execution (RCE) and underlying operating system compromise. "
                            "An attacker can install persistent malware, read system files, dump credentials, or pivot "
                            "into the internal corporate network."
                        ),
                        remediation=(
                            "1. Avoid invoking the operating system shell entirely (shell=False).\n"
                            "2. If external commands must be executed, pass arguments as discrete array elements.\n"
                            "3. Strictly validate input against an allowlist pattern (e.g. valid IPv4/IPv6 address or standard hostname regex).\n"
                            "4. Run the API process in an unprivileged, sandboxed container."
                        ),
                        poc_request=req_poc,
                        poc_response=res_poc,
                        evidence=f"Command injection payload '{payload}' successfully executed; returned response contained injected output."
                    ))
                    break  # Confirmed, no need to test further payloads

        return findings

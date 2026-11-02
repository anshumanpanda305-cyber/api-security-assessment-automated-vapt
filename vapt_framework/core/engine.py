import os
import sys
import time
import warnings
from typing import List, Dict, Any, Optional
from colorama import Fore, Style, init

from .scope import TargetScopeValidator, ScopeValidationError
from .requester import VaptRequester
from .vulnerability import Vulnerability
from .config import FrameworkConfig
from ..reporting.generator import ReportGenerator
from ..modules import ALL_MODULES

# Ensure standard output can handle UTF-8 if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

warnings.filterwarnings("ignore", message=".*InsecureKeyLengthWarning.*")
warnings.filterwarnings("ignore", message=".*The HMAC key is.*")

init(autoreset=True)

class VaptEngine:
    """
    Core orchestration engine for API Security Assessment and VAPT.
    """
    def __init__(
        self,
        target_url: str,
        config_path: Optional[str] = None,
        proxy: Optional[str] = None,
        output_dir: str = "reports"
    ):
        self.config = FrameworkConfig(config_path)
        self.target_url = target_url or self.config.get("target.base_url", "http://127.0.0.1:5000")
        self.proxy = proxy or (self.config.get("proxy.url") if self.config.get("proxy.enabled") else None)
        self.output_dir = output_dir

        # 1. Scope Enforcement (Ethical boundary guard)
        authorized = self.config.get("target.authorized_hosts", ["127.0.0.1", "localhost", "::1"])
        self.scope_validator = TargetScopeValidator(authorized)
        self.scope_validator.validate_url(self.target_url)

        # 2. Requester
        timeout = self.config.get("scanner.timeout", 8)
        self.requester = VaptRequester(base_url=self.target_url, proxy=self.proxy, timeout=timeout)

        # 3. Execution Context
        self.context: Dict[str, Any] = {}
        self.findings: List[Vulnerability] = []

    def run_all(self, modules_to_run: Optional[List[str]] = None) -> List[Vulnerability]:
        """Run security modules and collect findings."""
        print(f"\n{Fore.CYAN}{'='*68}")
        print(f"{Fore.CYAN}  API SECURITY ASSESSMENT & AUTOMATED VAPT FRAMEWORK")
        print(f"{Fore.CYAN}{'='*68}{Style.RESET_ALL}")
        print(f"[*] Target Base URL : {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}")
        print(f"[*] Scope Guard     : {Fore.GREEN}Active (Restricted to localhost / authorized){Style.RESET_ALL}")
        if self.proxy:
            print(f"[*] Burp Suite Proxy: {Fore.MAGENTA}{self.proxy} (Traffic Interception Active){Style.RESET_ALL}")
        else:
            print(f"[*] Proxy           : {Fore.WHITE}Disabled (Direct communication){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*68}{Style.RESET_ALL}\n")

        all_findings = []

        for ModClass in ALL_MODULES:
            if modules_to_run and ModClass.__name__ not in modules_to_run and ModClass.name not in modules_to_run:
                continue

            mod_instance = ModClass(
                requester=self.requester,
                config=self.config,
                context=self.context
            )

            print(f"[*] Running: {Fore.WHITE}{mod_instance.name}{Style.RESET_ALL} ... ", end="", flush=True)
            start_t = time.time()
            try:
                mod_findings = mod_instance.run()
                elapsed = time.time() - start_t
                all_findings.extend(mod_findings)

                if mod_findings:
                    print(f"{Fore.RED}[!] {len(mod_findings)} Vulnerability(s) Detected ({elapsed:.2f}s){Style.RESET_ALL}")
                    for f in mod_findings:
                        sev_color = Fore.RED if f.severity in ("CRITICAL", "HIGH") else (Fore.YELLOW if f.severity == "MEDIUM" else Fore.BLUE)
                        # Use clean ASCII tree characters for maximum Windows compatibility
                        print(f"    \\-- {sev_color}[{f.severity}] {f.title} ({f.endpoint}){Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Clean / Passed ({elapsed:.2f}s){Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}[ERROR] Module execution error: {e}{Style.RESET_ALL}")

        # Deduplicate & Sort by severity
        seen_ids = set()
        unique_findings = []
        for f in all_findings:
            if f.vuln_id not in seen_ids:
                seen_ids.add(f.vuln_id)
                unique_findings.append(f)

        unique_findings.sort(key=lambda x: x.get_severity_weight(), reverse=True)
        self.findings = unique_findings

        self._print_summary_table()
        return self.findings

    def generate_reports(self, prefix: str = "vapt_scan") -> Dict[str, str]:
        """Generate HTML, JSON, and Markdown reports."""
        reporter = ReportGenerator(self.output_dir)
        json_file = f"{prefix}.json"
        html_file = f"{prefix}.html"
        md_file = f"{prefix}.md"

        json_path = reporter.generate_json_report(self.findings, self.target_url, json_file)
        html_path = reporter.generate_html_report(self.findings, self.target_url, html_file)
        md_path = reporter.generate_markdown_report(self.findings, self.target_url, md_file)

        print(f"\n{Fore.GREEN}[+] Scan reports generated successfully:{Style.RESET_ALL}")
        print(f"    |-- HTML Report    : {Fore.CYAN}{html_path}{Style.RESET_ALL}")
        print(f"    |-- JSON Export    : {Fore.CYAN}{json_path}{Style.RESET_ALL}")
        print(f"    \\-- Markdown Brief : {Fore.CYAN}{md_path}{Style.RESET_ALL}")

        return {
            "html": html_path,
            "json": json_path,
            "markdown": md_path
        }

    def _print_summary_table(self):
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in stats:
                stats[f.severity] += 1

        print(f"\n{Fore.CYAN}{'='*68}")
        print(f"  VULNERABILITY ASSESSMENT SUMMARY")
        print(f"{'='*68}{Style.RESET_ALL}")
        print(f"  Total Findings Discovered : {Fore.WHITE}{len(self.findings)}{Style.RESET_ALL}")
        print(f"  Critical Risk             : {Fore.RED}{stats['CRITICAL']}{Style.RESET_ALL}")
        print(f"  High Risk                 : {Fore.RED}{stats['HIGH']}{Style.RESET_ALL}")
        print(f"  Medium Risk               : {Fore.YELLOW}{stats['MEDIUM']}{Style.RESET_ALL}")
        print(f"  Low Risk                  : {Fore.BLUE}{stats['LOW']}{Style.RESET_ALL}")
        print(f"  Informational             : {Fore.WHITE}{stats['INFO']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*68}{Style.RESET_ALL}")

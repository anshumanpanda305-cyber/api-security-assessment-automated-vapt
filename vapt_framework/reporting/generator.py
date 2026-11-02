import os
import json
import datetime
from typing import List, Dict, Any
from jinja2 import Template
from ..core.vulnerability import Vulnerability
from .html_template import HTML_REPORT_TEMPLATE

class ReportGenerator:
    """Generates structured HTML, JSON, and Markdown reports."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _calculate_stats(self, findings: List[Vulnerability]) -> Dict[str, int]:
        counts = {
            "TOTAL": len(findings),
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        for f in findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    def generate_json_report(
        self,
        findings: List[Vulnerability],
        target_url: str,
        filename: str = "vapt_report.json"
    ) -> str:
        filepath = os.path.join(self.output_dir, filename)
        stats = self._calculate_stats(findings)

        report_data = {
            "scan_metadata": {
                "report_name": "API Security Assessment & Automated VAPT Framework Report",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "target_url": target_url,
                "framework": "OWASP API Security Top 10",
                "stats": stats
            },
            "findings": [f.to_dict() for f in findings]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return filepath

    def generate_html_report(
        self,
        findings: List[Vulnerability],
        target_url: str,
        filename: str = "vapt_report.html",
        title: str = "API Penetration Testing & Vulnerability Assessment Report"
    ) -> str:
        filepath = os.path.join(self.output_dir, filename)
        stats = self._calculate_stats(findings)
        overall_status = "CRITICAL RISK" if stats["CRITICAL"] > 0 else (
            "HIGH RISK" if stats["HIGH"] > 0 else (
                "MEDIUM RISK" if stats["MEDIUM"] > 0 else (
                    "LOW RISK" if stats["LOW"] > 0 else "PASSED"
                )
            )
        )

        template = Template(HTML_REPORT_TEMPLATE)
        rendered_html = template.render(
            report_title=title,
            target_url=target_url,
            scan_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            counts=stats,
            overall_status=overall_status,
            findings=findings
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return filepath

    def generate_markdown_report(
        self,
        findings: List[Vulnerability],
        target_url: str,
        filename: str = "vapt_report.md"
    ) -> str:
        filepath = os.path.join(self.output_dir, filename)
        stats = self._calculate_stats(findings)

        lines = [
            "# API Security Assessment & Automated VAPT Report",
            "",
            f"- **Target URL:** `{target_url}`",
            f"- **Generated:** `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
            f"- **Total Findings:** **{stats['TOTAL']}** (Critical: {stats['CRITICAL']}, High: {stats['HIGH']}, Medium: {stats['MEDIUM']}, Low: {stats['LOW']}, Info: {stats['INFO']})",
            "",
            "---",
            "",
            "## Vulnerability Findings Summary",
            "",
            "| ID | Severity | Category | Title | Endpoint |",
            "|---|---|---|---|---|"
        ]

        for f in findings:
            lines.append(f"| `{f.vuln_id}` | **{f.severity}** | {f.owasp_category} | {f.title} | `{f.method} {f.endpoint}` |")

        lines.append("")
        lines.append("## Detailed Technical Findings & Proof of Concept")
        lines.append("")

        for f in findings:
            lines.extend([
                f"### [{f.vuln_id}] {f.title}",
                f"- **Severity:** `{f.severity}` (CVSS {f.cvss_score})",
                f"- **OWASP:** {f.owasp_category}",
                f"- **CWE:** {f.cwe_id}",
                f"- **Endpoint:** `{f.method} {f.endpoint}`",
                "",
                "**Description:**",
                f"{f.description}",
                "",
                "**Business Impact:**",
                f"{f.business_impact}",
                "",
                "**Remediation:**",
                f"{f.remediation}",
                "",
                "**Proof of Concept - HTTP Request:**",
                "```http",
                f"{f.poc_request}",
                "```",
                "",
                "**Proof of Concept - HTTP Response:**",
                "```http",
                f"{f.poc_response}",
                "```",
                "",
                "---",
                ""
            ])

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return filepath

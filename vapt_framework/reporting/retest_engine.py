import json
import os
import datetime
from typing import Dict, Any, List

class RetestEngine:
    """
    Compares baseline assessment findings against retest findings to verify
    security patches, calculate remediation rates, and reduce false positives.
    """
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def compare_scans(self, baseline_report_path: str, retest_report_path: str) -> Dict[str, Any]:
        with open(baseline_report_path, "r", encoding="utf-8") as f:
            base_data = json.load(f)

        with open(retest_report_path, "r", encoding="utf-8") as f:
            retest_data = json.load(f)

        base_findings = {f["vuln_id"]: f for f in base_data.get("findings", [])}
        retest_findings = {f["vuln_id"]: f for f in retest_data.get("findings", [])}

        resolved = []
        persistent = []
        new_findings = []

        for v_id, b_vuln in base_findings.items():
            if v_id in retest_findings:
                persistent.append(b_vuln)
            else:
                resolved.append(b_vuln)

        for v_id, r_vuln in retest_findings.items():
            if v_id not in base_findings:
                new_findings.append(r_vuln)

        total_base = len(base_findings)
        remediation_rate = (len(resolved) / total_base * 100.0) if total_base > 0 else 100.0

        comparison_result = {
            "retest_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "baseline_report": baseline_report_path,
            "retest_report": retest_report_path,
            "metrics": {
                "baseline_total": total_base,
                "retest_total": len(retest_findings),
                "resolved_count": len(resolved),
                "persistent_count": len(persistent),
                "new_count": len(new_findings),
                "remediation_rate_percent": round(remediation_rate, 1)
            },
            "resolved_vulnerabilities": resolved,
            "persistent_vulnerabilities": persistent,
            "new_vulnerabilities": new_findings
        }

        # Save retest comparison JSON
        out_json = os.path.join(self.output_dir, "retest_verification_report.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(comparison_result, f, indent=2)

        # Generate HTML retest verification dashboard
        self._generate_retest_html(comparison_result)

        return comparison_result

    def _generate_retest_html(self, data: Dict[str, Any]):
        out_html = os.path.join(self.output_dir, "retest_verification_report.html")
        m = data["metrics"]

        resolved_rows = ""
        for r in data["resolved_vulnerabilities"]:
            resolved_rows += f"""
            <tr>
                <td><span style="background: rgba(16,185,129,0.2); color: #34d399; padding: 3px 8px; border-radius: 4px; font-weight: bold; border: 1px solid #10b981;">RESOLVED</span></td>
                <td><code>{r['vuln_id']}</code></td>
                <td><strong>{r['title']}</strong></td>
                <td>{r['owasp_category']}</td>
                <td><span style="color: #cbd5e1;">{r['severity']}</span></td>
            </tr>
            """

        persistent_rows = ""
        for p in data["persistent_vulnerabilities"]:
            persistent_rows += f"""
            <tr>
                <td><span style="background: rgba(239,68,68,0.2); color: #f87171; padding: 3px 8px; border-radius: 4px; font-weight: bold; border: 1px solid #ef4444;">PERSISTENT</span></td>
                <td><code>{p['vuln_id']}</code></td>
                <td><strong>{p['title']}</strong></td>
                <td>{p['owasp_category']}</td>
                <td><span style="color: #f87171;">{p['severity']}</span></td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VAPT Retesting & Remediation Verification Report</title>
    <style>
        body {{
            background: #0f172a;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ border-bottom: 1px solid #334155; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .badge {{ background: #10b981; color: #022c22; padding: 4px 12px; border-radius: 9999px; font-weight: bold; font-size: 0.85rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: #1e293b; border: 1px solid #334155; padding: 1.5rem; border-radius: 8px; text-align: center; }}
        .stat-num {{ font-size: 2.25rem; font-weight: 800; margin: 0.25rem 0; }}
        .stat-label {{ font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; font-weight: 600; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0b1120; font-size: 0.85rem; text-transform: uppercase; color: #94a3b8; }}
        h2 {{ margin-top: 2rem; font-size: 1.3rem; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="badge">Retest Verification Audit</span>
            <h1 style="font-size: 2rem; margin-top: 0.5rem;">Security Fix Verification & False Positive Reduction</h1>
            <p style="color: #94a3b8;">Automated verification comparing baseline findings against hardened API implementation.</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Baseline Findings</div>
                <div class="stat-num" style="color: #f97316;">{m['baseline_total']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Successfully Resolved</div>
                <div class="stat-num" style="color: #10b981;">{m['resolved_count']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Persistent / Unfixed</div>
                <div class="stat-num" style="color: #ef4444;">{m['persistent_count']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Remediation Rate</div>
                <div class="stat-num" style="color: #6366f1;">{m['remediation_rate_percent']}%</div>
            </div>
        </div>

        <h2>Verified Resolved Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Vulnerability ID</th>
                    <th>Title</th>
                    <th>OWASP Category</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
                {resolved_rows if resolved_rows else "<tr><td colspan='5' style='text-align: center; color: #94a3b8;'>No resolved vulnerabilities</td></tr>"}
            </tbody>
        </table>

        {f"<h2>Persistent Vulnerabilities Requiring Attention</h2><table><thead><tr><th>Status</th><th>ID</th><th>Title</th><th>Category</th><th>Severity</th></tr></thead><tbody>{persistent_rows}</tbody></table>" if persistent_rows else ""}
    </div>
</body>
</html>
        """
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html_content)

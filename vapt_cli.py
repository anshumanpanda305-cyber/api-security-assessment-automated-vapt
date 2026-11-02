import argparse
import sys
import os
from colorama import Fore, Style, init

from vapt_framework.core.engine import VaptEngine
from vapt_framework.core.scope import ScopeValidationError
from vapt_framework.reporting.retest_engine import RetestEngine

# Ensure console supports UTF-8 safely
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

init(autoreset=True)

def print_banner():
    banner = f"""{Fore.CYAN}
  +====================================================================+
  |    API SECURITY ASSESSMENT & AUTOMATED VAPT SCANNER FRAMEWORK      |
  |          OWASP API Security Top 10 * Burp Suite Compatible         |
  +====================================================================+{Style.RESET_ALL}"""
    print(banner)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Automated API Vulnerability Assessment and Penetration Testing (VAPT) Framework"
    )
    parser.add_argument("--target", "-t", type=str, default="http://127.0.0.1:5000", help="Target API Base URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--proxy", "-p", type=str, default=None, help="Burp Suite proxy address (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--config", "-c", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--output", "-o", type=str, default="reports", help="Output directory for reports")
    parser.add_argument("--prefix", type=str, default="vapt_scan", help="Filename prefix for generated reports")
    parser.add_argument("--module", "-m", type=str, default=None, help="Run single specific module by name")
    parser.add_argument("--baseline", type=str, default=None, help="Baseline JSON report for retesting comparison")
    parser.add_argument("--retest-against", type=str, default=None, help="Directly compare two JSON reports without re-scanning: BASELINE RETEST")

    args = parser.parse_args()

    # Direct report comparison mode
    if args.baseline and args.retest_against:
        print(f"[*] Running Retest Verification Analysis...")
        retest_engine = RetestEngine(output_dir=args.output)
        comparison = retest_engine.compare_scans(args.baseline, args.retest_against)
        m = comparison["metrics"]
        print(f"\n{Fore.GREEN}[+] Retest Comparison Complete:{Style.RESET_ALL}")
        print(f"    |-- Baseline Findings : {m['baseline_total']}")
        print(f"    |-- Retest Findings   : {m['retest_total']}")
        print(f"    |-- Resolved (Fixed)  : {Fore.GREEN}{m['resolved_count']}{Style.RESET_ALL}")
        print(f"    |-- Persistent        : {Fore.RED if m['persistent_count'] > 0 else Fore.GREEN}{m['persistent_count']}{Style.RESET_ALL}")
        print(f"    \\-- Remediation Rate  : {Fore.CYAN}{m['remediation_rate_percent']}%{Style.RESET_ALL}")
        print(f"    \\-- HTML Audit Report : {Fore.CYAN}reports/retest_verification_report.html{Style.RESET_ALL}")
        sys.exit(0)

    try:
        # Initialize engine (Scope guard checked automatically on initialization)
        engine = VaptEngine(
            target_url=args.target,
            config_path=args.config,
            proxy=args.proxy,
            output_dir=args.output
        )

        modules_filter = [args.module] if args.module else None
        engine.run_all(modules_to_run=modules_filter)
        reports = engine.generate_reports(prefix=args.prefix)

        # If baseline report was provided, automatically perform retest comparison
        if args.baseline:
            print(f"\n[*] Comparing current scan findings against baseline: {args.baseline} ...")
            retest_engine = RetestEngine(output_dir=args.output)
            comparison = retest_engine.compare_scans(args.baseline, reports["json"])
            m = comparison["metrics"]
            print(f"{Fore.GREEN}[+] Fix Verification Completed: {m['resolved_count']} Resolved, {m['persistent_count']} Persistent ({m['remediation_rate_percent']}% Resolved){Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Verification Report: reports/retest_verification_report.html{Style.RESET_ALL}")

    except ScopeValidationError as e:
        print(f"\n{Fore.RED}[!] SCOPE GUARD VIOLATION:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{e}{Style.RESET_ALL}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Scan aborted due to unexpected error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

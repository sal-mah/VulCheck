"""
VulnScope Lite - Integrated Security Scanner

Current integration:
    1. Recon
    2. XSS Scanner (SKIPPED until module is added)
    3. SQL Injection Scanner (SKIPPED until module is added)
    4. Security Configuration

Recon is the source of host/service/web context for the later modules.
The terminal report intentionally keeps the detailed output style of the
individual Recon and Security Configuration scanners while presenting both
inside one complete scan.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from recon import run_recon_scan
from security_config import (
    CLASSIFICATION_ORDER,
    SEVERITY_ORDER,
    print_finding,
    run_security_config_scan,
)


SEPARATOR = "=" * 78
SUB_SEPARATOR = "-" * 78


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def skipped_module(module_name: str, target: str, reason: str) -> Dict[str, Any]:
    return {
        "module": module_name,
        "target": target,
        "status": "skipped",
        "findings": [],
        "errors": [],
        "reason": reason,
    }


def aggregate_findings(results: Dict[str, Dict[str, Any]]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    for result in results.values():
        findings.extend(result.get("findings", []))
    return findings


def build_summary(findings: list[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    classifications = {
        "Finding": 0,
        "Hardening": 0,
        "Observation": 0,
    }

    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1

        classification = finding.get("classification", "Finding")
        if classification in classifications:
            classifications[classification] += 1

    return {
        "total_findings": len(findings),
        "severity_counts": counts,
        "classification_counts": classifications,
    }


def print_recon_detail(result: Dict[str, Any]) -> None:
    """Print Recon in the same detailed style as recon.py."""
    print("\n" + SEPARATOR)
    print("RECON MODULE")
    print(SEPARATOR)
    print(f"Status:  {result.get('status', 'unknown')}")
    print(f"Target:  {result.get('target', '')}")

    if result.get("status") == "error":
        print("\n[!] Recon Errors")
        for error in result.get("errors", []):
            print(f"    - {error}")
        return

    print("\n[+] Target is valid")
    print("\n[+] Host is reachable")

    print("\n[+] Open ports:")
    ports = result.get("ports", [])
    if ports:
        for port in ports:
            print(f"    - {port}")
    else:
        print("    No open ports found")

    print("\n[+] Service Detection")
    services = result.get("services", [])
    if services:
        for service in services:
            print(f"\n    Port: {service.get('port')}")
            print(f"    Service: {service.get('service', 'Unknown')}")
            banner = service.get("banner")
            print(f"    Banner: {banner if banner else 'Not available'}")
    else:
        print("    No services detected")

    print("\n[+] Web Services")
    web_services = result.get("web_services", [])
    if web_services:
        for web in web_services:
            print(
                f"    {str(web.get('scheme', '')).upper()} → "
                f"{web.get('url', '')}"
            )
    else:
        print("    No web services found")

    print("\n[+] HTTP Recon")
    http_results = result.get("http_results", [])
    if http_results:
        for http_info in http_results:
            print(f"\n    URL: {http_info.get('url')}")
            print(f"    Status Code: {http_info.get('status_code')}")
            print(f"    Server: {http_info.get('server')}")
            print(f"    X-Powered-By: {http_info.get('powered_by')}")
            print(f"    Content-Type: {http_info.get('content_type')}")
            if http_info.get("error"):
                print(f"    Error: {http_info['error']}")
    else:
        print("    No HTTP information collected")

    print("\n[+] Endpoint Crawling")
    endpoints = result.get("endpoints", [])
    if endpoints:
        for endpoint in endpoints:
            print(f"    - {endpoint}")
    else:
        print("    No endpoints found")

    print("\n[+] OS Clues")
    os_clues = result.get("host", {}).get("os_clues", [])
    if os_clues:
        for clue in os_clues:
            print(f"    OS Family: {clue.get('os_family')}")
            print(f"    OS Clue: {clue.get('os_clue')}")
            print(f"    Confidence: {clue.get('confidence')}")
            print(f"    Source: {clue.get('source')}")
    else:
        print("    No OS clues found")


def print_skipped_module(title: str, result: Dict[str, Any]) -> None:
    print("\n" + SEPARATOR)
    print(title)
    print(SEPARATOR)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Reason: {result.get('reason', 'Not applicable')}")


def print_security_config_detail(result: Dict[str, Any]) -> None:
    """Print the complete Security Config report inside the integrated scan."""
    print("\n" + SEPARATOR)
    print("SECURITY CONFIGURATION MODULE")
    print(SEPARATOR)

    print(f"Version:       {result.get('version', 'unknown')}")
    print(f"Status:        {result.get('status', 'unknown')}")
    print(f"Scan Time UTC: {result.get('scan_started', 'unknown')}")
    print(f"Target:        {result.get('target', '')}")
    print(f"Recon Used:    {result.get('recon_used', False)}")

    web_targets = result.get("web_targets", [])
    if web_targets:
        print("\nWeb Targets:")
        for target in web_targets:
            print(f"  - {target}")

    services_checked = result.get("services_checked", [])
    if services_checked:
        print("\nServices Checked:")
        for service in services_checked:
            version = (
                f" ({service['version']})"
                if service.get("version")
                else ""
            )
            print(
                f"  - {service.get('service', 'Unknown')}"
                f":{service.get('port', '?')}{version}"
            )

    if result.get("errors"):
        print("\nErrors:")
        for error in result["errors"]:
            target = f" [{error['target']}]" if error.get("target") else ""
            print(
                f"  - {error.get('type', 'Error')}"
                f"{target}: {error.get('message', error)}"
            )

    print("\n" + SUB_SEPARATOR)
    print("SECURITY CONFIGURATION RISK SUMMARY")
    print(SUB_SEPARATOR)

    print(f"Risk Score: {result.get('risk_score', 0)}")
    severity_counts = result.get("severity_counts", {})
    print(f"Critical:   {severity_counts.get('Critical', 0)}")
    print(f"High:       {severity_counts.get('High', 0)}")
    print(f"Medium:     {severity_counts.get('Medium', 0)}")
    print(f"Low:        {severity_counts.get('Low', 0)}")
    print(f"Info:       {severity_counts.get('Info', 0)}")

    classification_counts = result.get("classification_counts", {})
    print("")
    print(
        f"Security Findings:          "
        f"{classification_counts.get('Finding', 0)}"
    )
    print(
        f"Hardening Recommendations:  "
        f"{classification_counts.get('Hardening', 0)}"
    )
    print(
        f"Observations:               "
        f"{classification_counts.get('Observation', 0)}"
    )
    print(f"Total:                      {len(result.get('findings', []))}")

    findings = sorted(
        result.get("findings", []),
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity"), 0),
            CLASSIFICATION_ORDER.get(item.get("classification"), 0),
        ),
        reverse=True,
    )

    print("\n" + SEPARATOR)
    print("SECURITY CONFIGURATION FINDINGS")
    print(SEPARATOR)

    if not findings:
        print("No findings detected.")
    else:
        for finding in findings:
            print_finding(finding)


def print_final_report(report: Dict[str, Any]) -> None:
    """Print one clean final summary after all detailed module output."""
    summary = report["summary"]

    print("\n\n" + SEPARATOR)
    print("VULNSCOPE LITE - FINAL INTEGRATED REPORT")
    print(SEPARATOR)
    print(f"Target:          {report['target']}")
    print(f"Scan Started:    {report['scan_started']}")
    print(f"Scan Finished:   {report['scan_finished']}")
    print(f"Overall Status:  {report['status']}")

    print("\n" + SUB_SEPARATOR)
    print("MODULE SUMMARY")
    print(SUB_SEPARATOR)

    for module_name, result in report["modules"].items():
        print(
            f"{module_name:20} "
            f"Status: {result.get('status', 'unknown'):8} "
            f"Findings: {len(result.get('findings', []))}"
        )

    print("\n" + SUB_SEPARATOR)
    print("AGGREGATED RISK SUMMARY")
    print(SUB_SEPARATOR)
    print(
        "Note: XSS and SQLi are currently skipped, so the current aggregate "
        "contains findings from the available integrated modules."
    )
    print(f"Total Findings: {summary['total_findings']}")

    for severity, count in summary["severity_counts"].items():
        print(f"{severity:10}: {count}")

    print("\nClassification:")
    for classification, count in summary["classification_counts"].items():
        print(f"{classification:12}: {count}")

    config_result = report["modules"].get("security_config", {})
    if "risk_score" in config_result:
        print(f"\nCurrent Security Config Risk Score: {config_result['risk_score']}")

    print("\n" + SEPARATOR)
    print("END OF INTEGRATED SCAN")
    print(SEPARATOR)


def run_integrated_scan(target: str) -> Dict[str, Any]:
    started = now_iso()
    results: Dict[str, Dict[str, Any]] = {}

    print(SEPARATOR)
    print("VulnScope Lite - Integrated Security Scan")
    print(SEPARATOR)
    print(f"Target: {target}")
    print("Execution Order: Recon → XSS → SQL Injection → Security Config")

    # 1. Recon MUST run first.
    print("\n[1/4] RECON")
    try:
        recon_data = run_recon_scan(target)
        results["recon"] = recon_data
        print_recon_detail(recon_data)
    except Exception as error:
        recon_data = {
            "module": "recon",
            "target": target,
            "status": "error",
            "findings": [],
            "errors": [{"type": "Scanner Error", "message": str(error)}],
            "host": {"reachable": False, "os_clues": []},
            "ports": [],
            "services": [],
            "web_services": [],
            "http_results": [],
            "endpoints": [],
        }
        results["recon"] = recon_data
        print_recon_detail(recon_data)

    web_available = bool(
        recon_data.get("web_services")
        or recon_data.get("http_results")
    )

    # 2. XSS placeholder.
    print("\n[2/4] XSS SCANNER")
    if web_available:
        xss_result = skipped_module(
            "xss",
            target,
            "XSS scanner module has not been integrated yet.",
        )
    else:
        xss_result = skipped_module(
            "xss",
            target,
            "No HTTP/HTTPS web service was discovered by Recon.",
        )
    results["xss"] = xss_result
    print_skipped_module("XSS SCANNER - CURRENTLY SKIPPED", xss_result)

    # 3. SQLi placeholder.
    print("\n[3/4] SQL INJECTION SCANNER")
    if web_available:
        sqli_result = skipped_module(
            "sqli",
            target,
            "SQLi scanner module has not been integrated yet.",
        )
    else:
        sqli_result = skipped_module(
            "sqli",
            target,
            "No HTTP/HTTPS web service was discovered by Recon.",
        )
    results["sqli"] = sqli_result
    print_skipped_module("SQL INJECTION SCANNER - CURRENTLY SKIPPED", sqli_result)

    # 4. Security Configuration consumes Recon data.
    print("\n[4/4] SECURITY CONFIGURATION")
    try:
        config_result = run_security_config_scan(
            target,
            recon_data=recon_data,
        )
        results["security_config"] = config_result
        print_security_config_detail(config_result)
    except Exception as error:
        config_result = {
            "module": "security_config",
            "target": target,
            "status": "error",
            "findings": [],
            "errors": [{"type": "Scanner Error", "message": str(error)}],
        }
        results["security_config"] = config_result
        print_security_config_detail(config_result)

    findings = aggregate_findings(results)
    summary = build_summary(findings)

    report_status = "success"
    if any(result.get("status") == "error" for result in results.values()):
        report_status = "partial/error"

    report = {
        "tool": "VulnScope Lite",
        "integration_version": "1.1.0",
        "scan_started": started,
        "scan_finished": now_iso(),
        "target": target,
        "status": report_status,
        "execution_order": [
            "recon",
            "xss",
            "sqli",
            "security_config",
        ],
        "modules": results,
        "summary": summary,
        "findings": findings,
    }

    print_final_report(report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VulnScope Lite integrated scanner"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Authorized target IP or hostname",
    )
    parser.add_argument(
        "--json",
        dest="json_file",
        help="Save the complete integrated result as JSON",
    )
    args = parser.parse_args()

    target = args.target
    if not target:
        target = input("Enter target IP or domain: ").strip()

    if not target:
        parser.error("Target cannot be empty.")

    report = run_integrated_scan(target)

    if args.json_file:
        output_path = Path(args.json_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\n[+] Integrated JSON report saved to: {output_path}")


if __name__ == "__main__":
    main()

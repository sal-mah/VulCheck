from __future__ import annotations

from typing import Any

from config.scanner_config import EXECUTION_ORDER


SEPARATOR = "=" * 78
SUB_SEPARATOR = "-" * 78

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}

CLASSIFICATION_ORDER = {
    "Finding": 3,
    "Hardening": 2,
    "Observation": 1,
}


def _format_error(error: Any) -> str:
    if isinstance(error, dict):
        label = error.get("type") or "Error"
        message = error.get("message") or str(error)
        target = f" [{error.get('target')}]" if error.get("target") else ""
        return f"{label}{target}: {message}"

    return str(error)


def _print_errors(result: dict[str, Any]) -> None:
    errors = result.get("errors", [])
    if not errors:
        return

    print("\nErrors:")
    for error in errors:
        print(f"  - {_format_error(error)}")


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity"), 0),
            CLASSIFICATION_ORDER.get(item.get("classification", "Finding"), 0),
        ),
        reverse=True,
    )


def _print_finding(finding: dict[str, Any]) -> None:
    print("\n" + SUB_SEPARATOR)
    print(
        f"[{finding.get('severity', 'Info').upper()}] "
        f"{finding.get('title', finding.get('name', 'Finding'))}"
    )

    if finding.get("type"):
        print(f"Type: {finding['type']}")
    if finding.get("category"):
        print(f"Category: {finding['category']}")
    if finding.get("classification"):
        print(f"Classification: {finding['classification']}")
    if finding.get("confidence"):
        print(f"Confidence: {finding['confidence']}")
    if finding.get("url"):
        print(f"URL: {finding['url']}")
    if finding.get("service"):
        print(f"Service: {finding['service']}:{finding.get('port', 'unknown')}")
    if finding.get("parameter"):
        print(f"Parameter: {finding['parameter']}")
    if finding.get("location"):
        print(f"Location: {finding['location']}")

    if finding.get("description"):
        print("\nFinding:")
        print(finding["description"])

    if finding.get("evidence"):
        print("\nDetected:")
        print(finding["evidence"])

    if finding.get("risk"):
        print("\nRisk:")
        print(finding["risk"])

    if finding.get("recommendation"):
        print("\nRecommendation:")
        print(finding["recommendation"])


def _print_findings(result: dict[str, Any], empty_message: str) -> None:
    findings = result.get("findings", [])

    print("\nFindings:")
    if not findings:
        print(f"  {empty_message}")
        return

    for finding in _sorted_findings(findings):
        _print_finding(finding)


def print_recon_detail(result: dict[str, Any]) -> None:
    print("\n" + SEPARATOR)
    print("RECON MODULE")
    print(SEPARATOR)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Target: {result.get('target', '')}")

    _print_errors(result)

    print("\nTarget Validation:")
    if result.get("status") == "error" and result.get("errors"):
        print("  Target validation or host discovery failed.")
    else:
        print("  Target is valid.")

    print("\nHost Reachability:")
    reachable = result.get("host", {}).get("reachable", False)
    print(f"  Reachable: {reachable}")

    print("\nPort Scan Configuration:")
    print(f"  Source: {result.get('port_source', 'default')}")
    ports_scanned = result.get("ports_scanned", [])
    if ports_scanned:
        print(f"  Total configured entries: {len(ports_scanned)}")
        print("  Ports/Ranges:")
        print(f"    {', '.join(map(str, ports_scanned))}")
    else:
        print("  No configured ports recorded.")

    print("\nOpen Ports:")
    ports = result.get("ports", [])
    if ports:
        for port in ports:
            print(f"  - {port}")
    else:
        print("  No open ports found.")

    print("\nService Detection:")
    services = result.get("services", [])
    if services:
        for service in services:
            print("")
            print(f"  Port: {service.get('port', 'unknown')}")
            print(f"  Service: {service.get('service', 'Unknown')}")
            if service.get("product"):
                print(f"  Product: {service['product']}")
            if service.get("version"):
                print(f"  Version: {service['version']}")
            print(f"  Banner: {service.get('banner') or 'Not available'}")
            if service.get("extra"):
                print(f"  Extra: {service['extra']}")
    else:
        print("  No services detected.")

    print("\nWeb Services:")
    web_services = result.get("web_services", [])
    if web_services:
        for web in web_services:
            if isinstance(web, dict):
                print(
                    f"  - {str(web.get('scheme', '')).upper()} "
                    f"-> {web.get('url', '')}"
                )
            else:
                print(f"  - {web}")
    else:
        print("  No web services found.")

    print("\nHTTP Recon:")
    http_results = result.get("http_results", [])
    if http_results:
        for item in http_results:
            print("")
            print(f"  URL: {item.get('url')}")
            print(f"  Status Code: {item.get('status_code')}")
            print(f"  Server: {item.get('server')}")
            print(f"  X-Powered-By: {item.get('powered_by')}")
            print(f"  Content-Type: {item.get('content_type')}")
            if item.get("error"):
                print(f"  Error: {item['error']}")
    else:
        print("  No HTTP information collected.")

    print("\nEndpoint Crawling:")
    endpoints = result.get("endpoints", [])
    if endpoints:
        for endpoint in endpoints:
            print(f"  - {endpoint}")
    else:
        print("  No endpoints found.")

    print("\nOS Clues:")
    os_clues = result.get("host", {}).get("os_clues", [])
    if os_clues:
        for clue in os_clues:
            print("")
            print(f"  OS Family: {clue.get('os_family')}")
            print(f"  OS Clue: {clue.get('os_clue')}")
            print(f"  Confidence: {clue.get('confidence')}")
            print(f"  Source: {clue.get('source')}")
    else:
        print("  No OS clues found.")

    _print_findings(result, "Recon does not currently emit vulnerability findings.")


def print_xss_detail(result: dict[str, Any]) -> None:
    print("\n" + SEPARATOR)
    print("XSS SCANNER MODULE")
    print(SEPARATOR)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Target: {result.get('target', '')}")
    print(f"Marker: {result.get('marker', 'VulneraptorXSS')}")
    if result.get("max_pages") is not None:
        print(f"Max Pages: {result['max_pages']}")

    if result.get("reason"):
        print(f"Reason: {result['reason']}")

    _print_errors(result)

    print("\nWeb Targets From Recon:")
    web_targets = result.get("web_targets", [])
    if web_targets:
        for url in web_targets:
            print(f"  - {url}")
    else:
        print("  No web targets supplied to XSS scanner.")

    print("\nPages Scanned:")
    scanned_urls = result.get("scanned_urls", [])
    if scanned_urls:
        for url in scanned_urls:
            print(f"  - {url}")
    else:
        print("  No pages scanned.")

    print("\nPer-Page XSS Checks:")
    details = result.get("scan_details", [])
    if details:
        for detail in details:
            print("")
            print(f"  Requested URL: {detail.get('requested_url')}")
            final_urls = detail.get("scanned_urls", [])
            if final_urls:
                print(f"  Final URL: {final_urls[-1]}")

            query_parameters = detail.get("query_parameters", [])
            print(
                "  Query Parameters: "
                + (", ".join(query_parameters) if query_parameters else "None")
            )

            forms = detail.get("forms_discovered", [])
            if forms:
                print("  Forms:")
                for form in forms:
                    fields = ", ".join(form.get("fields", [])) or "None"
                    print(
                        f"    - {form.get('method', 'get').upper()} "
                        f"{form.get('action')} fields=[{fields}]"
                    )
            else:
                print("  Forms: None")

            links = detail.get("links_discovered", [])
            parameterized_links = [url for url in links if "?" in url]
            print(f"  Same-Origin Links Found: {len(links)}")
            print(f"  Parameterized Links Found: {len(parameterized_links)}")
    else:
        print("  No page-level check details recorded.")

    _print_findings(result, "No reflected XSS findings detected.")


def print_sqli_detail(result: dict[str, Any]) -> None:
    print("\n" + SEPARATOR)
    print("SQL INJECTION SCANNER MODULE")
    print(SEPARATOR)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Target: {result.get('target', '')}")

    if result.get("timeout") is not None:
        print(f"Request Timeout: {result['timeout']} seconds")
    if result.get("time_delay_threshold") is not None:
        print(f"Time Delay Threshold: {result['time_delay_threshold']} seconds")
    if result.get("reason"):
        print(f"Reason: {result['reason']}")

    _print_errors(result)

    print("\nCandidate URLs From Recon:")
    candidate_urls = result.get("candidate_urls", [])
    if candidate_urls:
        for url in candidate_urls:
            print(f"  - {url}")
    else:
        print("  No candidate URLs supplied to SQLi scanner.")

    print("\nParameterized URLs Tested:")
    urls_tested = result.get("urls_tested", [])
    if urls_tested:
        for url in urls_tested:
            print(f"  - {url}")
    else:
        print("  No parameterized URLs tested.")

    print("\nPayload Families:")
    payload_groups = result.get("payload_groups", [])
    if payload_groups:
        for group in payload_groups:
            print(f"  - {group}")
    else:
        print("  No payload groups recorded.")

    print("\nBaseline Requests:")
    baselines = result.get("baseline_results", [])
    if baselines:
        for baseline in baselines:
            print(
                f"  - {baseline.get('url')} | "
                f"time={baseline.get('response_time_seconds')}s | "
                f"length={baseline.get('response_length')}"
            )
    else:
        print("  No successful baseline requests recorded.")

    print("\nParameters Tested:")
    parameters = result.get("parameters_tested", [])
    if parameters:
        for item in parameters:
            print(f"  - {item.get('parameter')} on {item.get('url')}")
    else:
        print("  No parameters tested.")

    _print_findings(result, "No SQL injection findings detected.")


def print_security_config_detail(result: dict[str, Any]) -> None:
    print("\n" + SEPARATOR)
    print("SECURITY CONFIGURATION MODULE")
    print(SEPARATOR)

    print(f"Version: {result.get('version', 'unknown')}")
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Scan Time UTC: {result.get('scan_started', 'unknown')}")
    print(f"Target: {result.get('target', '')}")
    print(f"Recon Used: {result.get('recon_used', False)}")

    if result.get("reason"):
        print(f"Reason: {result['reason']}")

    print("\nWeb Targets:")
    web_targets = result.get("web_targets", [])
    if web_targets:
        for target in web_targets:
            print(f"  - {target}")
    else:
        print("  No web targets checked.")

    print("\nServices Checked:")
    services_checked = result.get("services_checked", [])
    if services_checked:
        for service in services_checked:
            version = f" ({service['version']})" if service.get("version") else ""
            print(
                f"  - {service.get('service', 'Unknown')}:"
                f"{service.get('port', '?')}{version}"
            )
    else:
        print("  No service rules applied.")

    _print_errors(result)

    print("\n" + SUB_SEPARATOR)
    print("Security Configuration Risk Summary")
    print(SUB_SEPARATOR)
    print(f"Risk Score: {result.get('risk_score', 0)}")

    severity_counts = result.get("severity_counts", {})
    for severity in ("Critical", "High", "Medium", "Low", "Info"):
        print(f"{severity:10}: {severity_counts.get(severity, 0)}")

    classification_counts = result.get("classification_counts", {})
    print("")
    print(f"Security Findings: {classification_counts.get('Finding', 0)}")
    print(f"Hardening Recommendations: {classification_counts.get('Hardening', 0)}")
    print(f"Observations: {classification_counts.get('Observation', 0)}")
    print(f"Total: {len(result.get('findings', []))}")

    _print_findings(result, "No security configuration findings detected.")


def print_final_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]

    print("\n" + SEPARATOR)
    print("FINAL INTEGRATED SUMMARY")
    print(SEPARATOR)
    print(f"Target: {report['target']}")
    print(f"Overall Status: {report['status']}")
    print(f"Scan Started UTC: {report['scan_started']}")
    print(f"Scan Finished UTC: {report['scan_finished']}")
    print(f"Total Findings: {summary['total_findings']}")

    print("\nSeverity Counts:")
    for severity, count in summary["severity_counts"].items():
        print(f"  {severity:10}: {count}")

    print("\nClassification Counts:")
    for classification, count in summary["classification_counts"].items():
        print(f"  {classification:12}: {count}")

    print("\nModule Status:")
    for module_name in EXECUTION_ORDER:
        result = report["modules"].get(module_name, {})
        print(
            f"  {module_name:16} "
            f"status={result.get('status', 'missing'):12} "
            f"findings={len(result.get('findings', []))}"
        )



def print_ai_detail(report: dict[str, Any]) -> None:
    ai = report.get("ai", {})

    if not ai.get("enabled"):
        return

    print("\n" + SEPARATOR)
    print("OLLAMA LOCAL AI ANALYSIS")
    print(SEPARATOR)
    print(f"Status: {ai.get('status', 'unknown')}")
    print(f"Model: {ai.get('model', 'unknown')}")
    print(f"API: {ai.get('base_url', 'unknown')}")

    if ai.get("error"):
        print("\nError:")
        print(f"  {ai['error']}")
        return

    analysis = ai.get("analysis", "")
    if analysis:
        print("\n" + analysis)
    else:
        print("\nNo AI analysis returned.")



 
def print_integrated_report(report: dict[str, Any]) -> None:
    print("\n" + SEPARATOR)
    print("Vulneraptor LITE - FULL INTEGRATED SCAN OUTPUT")
    print(SEPARATOR)
    print(f"Target: {report['target']}")
    print("Execution Order: Recon -> XSS -> SQL Injection -> Security Config -> Ollama AI")
    print("Execution Order: Recon -> XSS -> SQL Injection -> Security Config")

    modules = report.get("modules", {})

    if "recon" in modules:
        print_recon_detail(modules["recon"])
    if "xss" in modules:
        print_xss_detail(modules["xss"])
    if "sqli" in modules:
        print_sqli_detail(modules["sqli"])
    if "security_config" in modules:
        print_security_config_detail(modules["security_config"])

    print_ai_detail(report)

    print_final_summary(report)

    print("\n" + SEPARATOR)
    print("END OF INTEGRATED SCAN")
    print(SEPARATOR)

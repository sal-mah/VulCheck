"""
modules/sqli_scanner.py

SQL Injection Scanner module for VulnScope Lite.
Owner: Salma

Standard entry point (agreed team interface):
    run_sqli_scanner(target, recon_data=None) -> dict

It only runs against web URLs that Recon (or whoever supplies recon_data)
already found and put in recon_data["urls"] or recon_data["endpoints"]. If
there's no web service, or no URL with parameters, this module reports
"skipped" and does nothing.

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


def _result(target, status, findings=None, errors=None, **extra):
    result = {
        "module": MODULE_NAME,
        "target": target,
        "status": status,
        "findings": findings or [],
        "errors": errors or [],
    }
    result.update(extra)
    return result


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


def _candidate_urls(recon_data):
    if not recon_data:
        return []

    urls = []

    for key in ("urls", "endpoints", "web_services", "http_results"):
        values = recon_data.get(key) or []
        if not isinstance(values, (list, tuple, set)):
            values = [values]

        for item in values:
            if isinstance(item, str):
                url = item
            elif isinstance(item, dict):
                url = item.get("url") or item.get("target") or item.get("endpoint")
            else:
                continue

            if isinstance(url, str) and url.startswith(("http://", "https://")):
                if url not in urls:
                    urls.append(url)

    return urls


def _has_web_service(recon_data):
    return bool(_candidate_urls(recon_data))


def _get_urls_with_params(recon_data):
    urls = _candidate_urls(recon_data)
    return [u for u in urls if "?" in u]


def _test_parameter(base_url, param, baseline_text, baseline_time, session):
    """Runs the three checks for one parameter and returns any findings."""
    findings = []

    # 1. Error-based
    for payload in ERROR_PAYLOADS:
        test_url = _build_url(base_url, param, payload)
        try:
            resp = session.get(test_url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if ERROR_PATTERN.search(resp.text or ""):
            findings.append(_finding(
                param, "Error-Based SQL Injection", "High",
                f"Error-based SQL injection in parameter '{param}'",
                f"Payload {payload!r} caused a database error to appear in the response.",
                f"payload={payload!r} url={test_url}", test_url,
            ))
            break  # one hit is enough evidence for this parameter

    # 2. Boolean-based
    try:
        true_url = _build_url(base_url, param, TRUE_PAYLOAD)
        false_url = _build_url(base_url, param, FALSE_PAYLOAD)
        true_resp = session.get(true_url, timeout=TIMEOUT)
        false_resp = session.get(false_url, timeout=TIMEOUT)

        true_len = len(true_resp.text or "")
        false_len = len(false_resp.text or "")
        baseline_len = len(baseline_text or "")

        # TRUE should look like the normal page; FALSE should look different.
        true_matches_baseline = abs(true_len - baseline_len) <= max(5, baseline_len * 0.02)
        false_differs = abs(false_len - true_len) > max(20, baseline_len * 0.05)

        if true_matches_baseline and false_differs:
            findings.append(_finding(
                param, "Boolean-Based Blind SQL Injection", "High",
                f"Boolean-based SQL injection in parameter '{param}'",
                "A TRUE condition matched the normal page while a FALSE condition changed it.",
                f"true_len={true_len} false_len={false_len} baseline_len={baseline_len}", true_url,
            ))
    except requests.RequestException:
        pass

    # 3. Time-based
    for payload in TIME_PAYLOADS:
        test_url = _build_url(base_url, param, payload)
        try:
            start = time.monotonic()
            session.get(test_url, timeout=TIMEOUT)
            elapsed = time.monotonic() - start
        except requests.RequestException:
            continue
        if elapsed - baseline_time >= TIME_DELAY_THRESHOLD:
            findings.append(_finding(
                param, "Time-Based Blind SQL Injection", "High",
                f"Time-based SQL injection in parameter '{param}'",
                f"Payload {payload!r} made the response take {elapsed:.1f}s vs a normal {baseline_time:.1f}s.",
                f"payload={payload!r} elapsed={elapsed:.2f}s baseline={baseline_time:.2f}s", test_url,
            ))
            break

    return findings


def run_sqli_scanner(target, recon_data=None):
    candidate_urls = _candidate_urls(recon_data)

    if not _has_web_service(recon_data):
        return _result(
            target,
            status="skipped",
            reason="No applicable web service was discovered by Recon.",
            candidate_urls=[],
            urls_tested=[],
            parameters_tested=[],
            baseline_results=[],
            payload_groups=["error-based", "boolean-based", "time-based"],
        )

    urls = _get_urls_with_params(recon_data)
    if not urls:
        return _result(
            target,
            status="skipped",
            reason="No parameterized URLs were discovered by Recon.",
            candidate_urls=candidate_urls,
            urls_tested=[],
            parameters_tested=[],
            baseline_results=[],
            payload_groups=["error-based", "boolean-based", "time-based"],
        )

    findings = []
    errors = []
    session = requests.Session()
    parameters_tested = []
    baseline_results = []

    for base_url in urls:
        params = [k for k, _ in parse_qsl(urlsplit(base_url).query, keep_blank_values=True)]

        try:
            start = time.monotonic()
            baseline_resp = session.get(base_url, timeout=TIMEOUT)
            baseline_time = time.monotonic() - start
            baseline_results.append(
                {
                    "url": base_url,
                    "response_time_seconds": round(baseline_time, 3),
                    "response_length": len(baseline_resp.text or ""),
                }
            )
        except requests.RequestException as exc:
            errors.append(f"Failed to fetch baseline for {base_url}: {exc}")
            continue

        for param in params:
            parameters_tested.append({"url": base_url, "parameter": param})
            try:
                findings.extend(
                    _test_parameter(base_url, param, baseline_resp.text, baseline_time, session)
                )
            except Exception as exc:
                errors.append(f"Error testing parameter '{param}' on {base_url}: {exc}")

    status = "error" if errors and not baseline_results else "success"
    return _result(
        target,
        status=status,
        findings=findings,
        errors=errors,
        candidate_urls=candidate_urls,
        urls_tested=urls,
        parameters_tested=parameters_tested,
        baseline_results=baseline_results,
        payload_groups=["error-based", "boolean-based", "time-based"],
        timeout=TIMEOUT,
        time_delay_threshold=TIME_DELAY_THRESHOLD,
    )

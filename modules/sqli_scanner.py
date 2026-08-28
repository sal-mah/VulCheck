"""
modules/sqli_scanner.py

SQL Injection Scanner for Vulneraptor Lite.

Team interface:
    run_sqli_scanner(target, recon_data=None) -> dict

Designed for authorized security testing and local vulnerable labs.

Supported:
    - Error-based SQL injection
    - Boolean-based SQL injection
    - Time-based SQL injection
    - SQLite-specific detection
    - MySQL detection
    - PostgreSQL detection
    - MSSQL detection
    - URL parameter discovery
    - Basic crawling when Recon provides only a root URL
    - HTML/JSON/plain-text response analysis
    - Response similarity analysis
    - Baseline comparison
    - Redirect handling
    - Parameter-by-parameter testing

IMPORTANT:
    Only use this against systems you own or are explicitly authorized
    to test.
"""

import re
import time
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import (
    urljoin,
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode,
)

import requests


# ============================================================
# CONFIGURATION
# ============================================================

MODULE_NAME = "sqli"

TIMEOUT = 8

# Time delay used by the scanner.
TIME_DELAY = 3

# Minimum additional delay before we consider a response suspicious.
TIME_DELAY_THRESHOLD = 2.2

# Don't crawl endlessly.
MAX_CRAWL_PAGES = 15

# Maximum parameters tested per URL.
MAX_PARAMETERS_PER_URL = 30

# Maximum response body considered for comparison.
MAX_COMPARE_SIZE = 500_000

USER_AGENT = "Vulneraptor-Lite-SQLi-Scanner/1.0"


# ============================================================
# SQL ERROR SIGNATURES
# ============================================================

ERROR_PATTERNS = [

    # SQLite
    r"sqlite3\.operationalerror",
    r"sqlite error",
    r"sqliteexception",
    r"unrecognized token",
    r"near ['\"].{0,80}syntax error",
    r"near \".{0,80}\": syntax error",
    r"near '.{0,80}': syntax error",

    # MySQL
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"mysqli",
    r"pdoexception",
    r"sql syntax.*mysql",

    # PostgreSQL
    r"postgresql.*error",
    r"pg_query",
    r"pg_exec",
    r"psql:",
    r"syntax error at or near",

    # Microsoft SQL Server
    r"microsoft sql server",
    r"odbc sql server driver",
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    r"sqlexception",
    r"system\.data\.sqlclient",

    # Oracle
    r"ora-\d{5}",
    r"oracle.*error",
    r"oracle.*exception",

    # Generic
    r"sqlstate\s*\[",
    r"sql syntax",
    r"database error",
    r"database exception",
    r"query failed",
    r"query error",
    r"invalid query",
    r"unterminated quoted string",
    r"unterminated string",
    r"quoted string not properly terminated",
    r"syntax error",
]

ERROR_PATTERN = re.compile(
    "|".join(ERROR_PATTERNS),
    re.IGNORECASE,
)


# ============================================================
# SQL PAYLOADS
# ============================================================

# These are intentionally simple and are appropriate for a
# scanner test lab.

ERROR_PAYLOADS = [
    "'",
    '"',
    "\\'",
    "';",
    "')",
    '")',
]


BOOLEAN_TRUE_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1-- ",
    "' OR 1=1#",
    "') OR ('1'='1",
    "' AND 1=1--",
]


BOOLEAN_FALSE_PAYLOADS = [
    "' AND '1'='2",
    "' AND 1=2--",
    "' AND 1=2-- ",
    "' AND 1=2#",
    "') AND ('1'='2",
    "' AND 1=2--",
]


# SQLite doesn't provide SLEEP().
#
# SQLite time-based injection can sometimes be detected through
# expensive expressions, but this varies by application/query.
#
# For MySQL/PostgreSQL/MSSQL environments these payloads are useful.

TIME_PAYLOADS = [

    # MySQL
    "' OR SLEEP(3)-- ",
    "' OR IF(1=1,SLEEP(3),0)-- ",

    # PostgreSQL
    "' OR pg_sleep(3)-- ",
    "'; SELECT pg_sleep(3)-- ",

    # MSSQL
    "' WAITFOR DELAY '0:0:3'-- ",
    "'; WAITFOR DELAY '0:0:3'-- ",

]


# ============================================================
# RESULT HELPERS
# ============================================================

def _result(
    target,
    status,
    findings=None,
    errors=None,
    **extra,
):

    result = {
        "module": MODULE_NAME,
        "target": target,
        "status": status,
        "findings": findings or [],
        "errors": errors or [],
    }

    result.update(extra)

    return result


def _finding(
    param,
    name,
    severity,
    title,
    description,
    evidence,
    url,
):

    return {
        "module": MODULE_NAME,
        "type": "SQL Injection",
        "name": name,
        "severity": severity,
        "title": title,
        "description": description,
        "risk": (
            "An attacker could manipulate SQL queries and potentially "
            "read, modify, or delete database information."
        ),
        "recommendation": (
            "Use parameterized queries / prepared statements. "
            "Do not concatenate user-controlled input into SQL queries."
        ),
        "evidence": evidence,
        "url": url,
        "parameter": param,
    }


# ============================================================
# URL HELPERS
# ============================================================

def _build_url(base_url, param, value):

    parts = urlsplit(base_url)

    pairs = parse_qsl(
        parts.query,
        keep_blank_values=True,
    )

    new_pairs = []

    replaced = False

    for key, old_value in pairs:

        if key == param and not replaced:

            new_pairs.append(
                (key, value)
            )

            replaced = True

        else:

            new_pairs.append(
                (key, old_value)
            )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(new_pairs),
            parts.fragment,
        )
    )


def _normalize_url(url):

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url.startswith(
        ("http://", "https://")
    ):
        return None

    parts = urlsplit(url)

    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            parts.query,
            "",
        )
    )


# ============================================================
# RECON DATA
# ============================================================

def _candidate_urls(recon_data):

    if not recon_data:
        return []

    urls = []

    for key in (
        "urls",
        "endpoints",
        "web_services",
        "http_results",
    ):

        values = recon_data.get(key) or []

        if not isinstance(
            values,
            (list, tuple, set),
        ):
            values = [values]

        for item in values:

            if isinstance(item, str):

                url = item

            elif isinstance(item, dict):

                url = (
                    item.get("url")
                    or item.get("target")
                    or item.get("endpoint")
                )

            else:

                continue

            url = _normalize_url(url)

            if url and url not in urls:

                urls.append(url)

    return urls


def _get_urls_with_params(recon_data):

    urls = _candidate_urls(
        recon_data
    )

    return [
        url
        for url in urls
        if parse_qsl(
            urlsplit(url).query,
            keep_blank_values=True,
        )
    ]


# ============================================================
# HTML CRAWLER
# ============================================================

class _LinkParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.links = []

        self.forms = []

    def handle_starttag(
        self,
        tag,
        attrs,
    ):

        attrs = dict(attrs)

        if tag.lower() == "a":

            href = attrs.get(
                "href"
            )

            if href:

                self.links.append(
                    href
                )

        elif tag.lower() == "form":

            self.forms.append(
                {
                    "action": attrs.get(
                        "action",
                        "",
                    ),
                    "method": attrs.get(
                        "method",
                        "GET",
                    ).upper(),
                }
            )


def _crawl_for_urls(
    seed_urls,
    session,
):

    discovered = []

    queue = []

    visited = set()

    for url in seed_urls:

        normalized = _normalize_url(
            url
        )

        if normalized:

            queue.append(
                normalized
            )


    while queue and len(
        visited
    ) < MAX_CRAWL_PAGES:

        current = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)

        try:

            response = session.get(
                current,
                timeout=TIMEOUT,
            )

        except requests.RequestException:

            continue

        content_type = (
            response.headers
            .get(
                "Content-Type",
                "",
            )
            .lower()
        )

        if (
            "text/html" not in
            content_type
        ):

            continue

        parser = _LinkParser()

        try:

            parser.feed(
                response.text
            )

        except Exception:

            continue


        # ----------------------------------------------------
        # Links
        # ----------------------------------------------------

        for href in parser.links:

            absolute = urljoin(
                current,
                href,
            )

            normalized = _normalize_url(
                absolute
            )

            if not normalized:
                continue

            if urlsplit(
                normalized
            ).netloc != urlsplit(
                current
            ).netloc:

                continue

            if normalized not in discovered:

                discovered.append(
                    normalized
                )

            if (
                normalized not in visited
                and normalized not in queue
            ):

                queue.append(
                    normalized
                )


        # ----------------------------------------------------
        # Current URL
        # ----------------------------------------------------

        if current not in discovered:

            discovered.append(
                current
            )


    return discovered


# ============================================================
# RESPONSE ANALYSIS
# ============================================================

def _body(response):

    text = response.text or ""

    if len(text) > MAX_COMPARE_SIZE:

        text = text[
            :MAX_COMPARE_SIZE
        ]

    return text


def _clean_response_text(text):

    text = text or ""

    # Remove obvious dynamic content.
    text = re.sub(
        r"\d{10,}",
        "<NUMBER>",
        text,
    )

    text = re.sub(
        r"[0-9a-f]{16,}",
        "<HEX>",
        text,
        flags=re.IGNORECASE,
    )

    return text


def _similarity(
    first,
    second,
):

    first = _clean_response_text(
        first
    )

    second = _clean_response_text(
        second
    )

    return SequenceMatcher(
        None,
        first,
        second,
    ).ratio()


def _response_signature(response):

    body = _body(
        response
    )

    return {
        "status": response.status_code,
        "length": len(body),
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "error": bool(
            ERROR_PATTERN.search(
                body
            )
        ),
    }


# ============================================================
# REQUEST
# ============================================================

def _request(
    session,
    url,
):

    start = time.monotonic()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        elapsed = (
            time.monotonic()
            - start
        )

        return (
            response,
            elapsed,
            None,
        )

    except requests.RequestException as exc:

        return (
            None,
            time.monotonic() - start,
            exc,
        )


# ============================================================
# ERROR-BASED SQLi
# ============================================================

def _test_error_based(
    base_url,
    param,
    session,
):

    for payload in ERROR_PAYLOADS:

        test_url = _build_url(
            base_url,
            param,
            payload,
        )

        response, elapsed, error = _request(
            session,
            test_url,
        )

        if error:
            continue

        body = _body(
            response
        )

        match = ERROR_PATTERN.search(
            body
        )

        if match:

            evidence = {
                "payload": payload,
                "url": test_url,
                "status": response.status_code,
                "response_time": round(
                    elapsed,
                    3,
                ),
                "matched_error": match.group(
                    0
                )[:150],
            }

            return _finding(
                param,
                "Error-Based SQL Injection",
                "High",
                (
                    f"Error-based SQL injection "
                    f"in parameter '{param}'"
                ),
                (
                    "A malformed SQL payload caused "
                    "a database error to appear in "
                    "the HTTP response."
                ),
                evidence,
                test_url,
            )

    return None


# ============================================================
# BOOLEAN SQLi
# ============================================================

def _test_boolean_based(
    base_url,
    param,
    baseline_response,
    session,
):

    baseline_body = _body(
        baseline_response
    )

    baseline_status = (
        baseline_response.status_code
    )


    for true_payload, false_payload in zip(
        BOOLEAN_TRUE_PAYLOADS,
        BOOLEAN_FALSE_PAYLOADS,
    ):

        true_url = _build_url(
            base_url,
            param,
            true_payload,
        )

        false_url = _build_url(
            base_url,
            param,
            false_payload,
        )


        true_response, true_time, true_error = _request(
            session,
            true_url,
        )

        false_response, false_time, false_error = _request(
            session,
            false_url,
        )


        if true_error or false_error:
            continue

        true_body = _body(
            true_response
        )

        false_body = _body(
            false_response
        )


        true_similarity = _similarity(
            baseline_body,
            true_body,
        )

        false_similarity = _similarity(
            baseline_body,
            false_body,
        )

        true_false_similarity = _similarity(
            true_body,
            false_body,
        )


        # ----------------------------------------------------
        # Detection logic
        # ----------------------------------------------------
        #
        # TRUE should resemble the baseline.
        #
        # FALSE should be substantially different.
        #
        # This is much stronger than simply comparing lengths.
        # ----------------------------------------------------

        true_looks_normal = (
            true_similarity >= 0.90
        )

        false_looks_different = (
            false_similarity <= 0.80
        )

        true_false_different = (
            true_false_similarity <= 0.85
        )


        if (
            true_looks_normal
            and false_looks_different
            and true_false_different
        ):

            evidence = {
                "true_payload": true_payload,
                "false_payload": false_payload,

                "baseline_status": baseline_status,
                "true_status": true_response.status_code,
                "false_status": false_response.status_code,

                "baseline_length": len(
                    baseline_body
                ),

                "true_length": len(
                    true_body
                ),

                "false_length": len(
                    false_body
                ),

                "true_similarity": round(
                    true_similarity,
                    4,
                ),

                "false_similarity": round(
                    false_similarity,
                    4,
                ),

                "true_false_similarity": round(
                    true_false_similarity,
                    4,
                ),

                "true_url": true_url,
                "false_url": false_url,
            }


            return _finding(
                param,
                "Boolean-Based Blind SQL Injection",
                "High",
                (
                    f"Boolean-based SQL injection "
                    f"in parameter '{param}'"
                ),
                (
                    "A TRUE SQL condition produced a "
                    "response similar to the normal request "
                    "while a FALSE condition produced a "
                    "substantially different response."
                ),
                evidence,
                true_url,
            )


    return None


# ============================================================
# TIME-BASED SQLi
# ============================================================

def _test_time_based(
    base_url,
    param,
    baseline_time,
    session,
):

    for payload in TIME_PAYLOADS:

        test_url = _build_url(
            base_url,
            param,
            payload,
        )

        response, elapsed, error = _request(
            session,
            test_url,
        )

        if error:
            continue


        delay = (
            elapsed
            - baseline_time
        )


        if delay >= TIME_DELAY_THRESHOLD:

            evidence = {
                "payload": payload,
                "url": test_url,
                "baseline_seconds": round(
                    baseline_time,
                    3,
                ),
                "response_seconds": round(
                    elapsed,
                    3,
                ),
                "additional_delay_seconds": round(
                    delay,
                    3,
                ),
            }


            return _finding(
                param,
                "Time-Based Blind SQL Injection",
                "High",
                (
                    f"Time-based SQL injection "
                    f"in parameter '{param}'"
                ),
                (
                    "A database delay payload caused "
                    "the HTTP response to take "
                    "significantly longer than the "
                    "baseline request."
                ),
                evidence,
                test_url,
            )


    return None


# ============================================================
# PARAMETER TESTING
# ============================================================

def _test_parameter(
    base_url,
    param,
    baseline_response,
    baseline_time,
    session,
):

    findings = []


    # --------------------------------------------------------
    # Error-based
    # --------------------------------------------------------

    finding = _test_error_based(
        base_url,
        param,
        session,
    )

    if finding:

        findings.append(
            finding
        )


    # --------------------------------------------------------
    # Boolean-based
    # --------------------------------------------------------

    finding = _test_boolean_based(
        base_url,
        param,
        baseline_response,
        session,
    )

    if finding:

        findings.append(
            finding
        )


    # --------------------------------------------------------
    # Time-based
    # --------------------------------------------------------

    finding = _test_time_based(
        base_url,
        param,
        baseline_time,
        session,
    )

    if finding:

        findings.append(
            finding
        )


    return findings


# ============================================================
# MAIN SCANNER
# ============================================================

def run_sqli_scanner(
    target,
    recon_data=None,
):

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT
        }
    )


    candidate_urls = _candidate_urls(
        recon_data
    )


    # --------------------------------------------------------
    # If Recon found nothing, use target itself if it is a URL.
    # --------------------------------------------------------

    if not candidate_urls:

        normalized_target = _normalize_url(
            target
        )

        if normalized_target:

            candidate_urls = [
                normalized_target
            ]


    # --------------------------------------------------------
    # No web service
    # --------------------------------------------------------

    if not candidate_urls:

        return _result(
            target,
            status="skipped",
            reason=(
                "No applicable web service "
                "was discovered."
            ),
            candidate_urls=[],
            urls_tested=[],
            parameters_tested=[],
            baseline_results=[],
            payload_groups=[
                "error-based",
                "boolean-based",
                "time-based",
            ],
        )


    # --------------------------------------------------------
    # Crawl discovered web targets.
    # --------------------------------------------------------

    try:

        crawled_urls = _crawl_for_urls(
            candidate_urls,
            session,
        )

    except Exception:

        crawled_urls = []


    all_urls = []

    for url in (
        candidate_urls
        + crawled_urls
    ):

        if url not in all_urls:

            all_urls.append(
                url
            )


    # --------------------------------------------------------
    # Only URLs containing query parameters are directly
    # injectable by this GET-based module.
    # --------------------------------------------------------

    parameterized_urls = []

    for url in all_urls:

        pairs = parse_qsl(
            urlsplit(url).query,
            keep_blank_values=True,
        )

        if pairs:

            if url not in parameterized_urls:

                parameterized_urls.append(
                    url
                )


    if not parameterized_urls:

        return _result(
            target,
            status="skipped",
            reason=(
                "No parameterized URLs "
                "were discovered."
            ),
            candidate_urls=all_urls,
            urls_tested=[],
            parameters_tested=[],
            baseline_results=[],
            payload_groups=[
                "error-based",
                "boolean-based",
                "time-based",
            ],
        )


    # --------------------------------------------------------
    # Scan
    # --------------------------------------------------------

    findings = []

    errors = []

    parameters_tested = []

    baseline_results = []


    for base_url in parameterized_urls:

        try:

            start = time.monotonic()

            baseline_response = session.get(
                base_url,
                timeout=TIMEOUT,
                allow_redirects=True,
            )

            baseline_time = (
                time.monotonic()
                - start
            )

        except requests.RequestException as exc:

            errors.append(
                (
                    f"Failed baseline request "
                    f"for {base_url}: {exc}"
                )
            )

            continue


        baseline_body = _body(
            baseline_response
        )


        baseline_results.append(
            {
                "url": base_url,

                "status": (
                    baseline_response.status_code
                ),

                "response_time_seconds": round(
                    baseline_time,
                    3,
                ),

                "response_length": len(
                    baseline_body
                ),

                "content_type": (
                    baseline_response.headers.get(
                        "Content-Type",
                        "",
                    )
                ),

                "sql_error": bool(
                    ERROR_PATTERN.search(
                        baseline_body
                    )
                ),
            }
        )


        params = [
            key
            for key, _ in parse_qsl(
                urlsplit(base_url).query,
                keep_blank_values=True,
            )
        ]


        # Remove duplicates while preserving order.

        params = list(
            dict.fromkeys(
                params
            )
        )


        params = params[
            :MAX_PARAMETERS_PER_URL
        ]


        for param in params:

            parameters_tested.append(
                {
                    "url": base_url,
                    "parameter": param,
                }
            )


            try:

                parameter_findings = _test_parameter(
                    base_url,
                    param,
                    baseline_response,
                    baseline_time,
                    session,
                )


                findings.extend(
                    parameter_findings
                )


            except Exception as exc:

                errors.append(
                    (
                        f"Error testing parameter "
                        f"'{param}' on {base_url}: "
                        f"{exc}"
                    )
                )


    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    if errors and not baseline_results:

        status = "error"

    else:

        status = "success"


    # --------------------------------------------------------
    # Deduplicate findings.
    # --------------------------------------------------------

    unique_findings = []

    seen = set()


    for finding in findings:

        key = (
            finding.get("name"),
            finding.get("parameter"),
            finding.get("url"),
        )

        if key in seen:
            continue

        seen.add(key)

        unique_findings.append(
            finding
        )


    return _result(
        target,
        status=status,
        findings=unique_findings,
        errors=errors,

        candidate_urls=all_urls,

        urls_tested=parameterized_urls,

        parameters_tested=parameters_tested,

        baseline_results=baseline_results,

        payload_groups=[
            "error-based",
            "boolean-based",
            "time-based",
        ],

        timeout=TIMEOUT,

        time_delay=TIME_DELAY,

        time_delay_threshold=TIME_DELAY_THRESHOLD,

        scanner_version="2.0",
    )


# ============================================================
# OPTIONAL LOCAL TEST
# ============================================================

if __name__ == "__main__":

    import json
    import sys


    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python modules/sqli_scanner.py "
            "http://127.0.0.1:5000/"
        )

        sys.exit(1)


    target = sys.argv[1]


    result = run_sqli_scanner(
        target,
        recon_data={
            "urls": [
                target
            ]
        },
    )


    print(
        json.dumps(
            result,
            indent=4,
        )
    )
"""
VulnScope Lite - XSS Scanner

Scope:
- Authorized lab/web targets only.
- Performs controlled reflected-XSS checks.
- Discovers forms and query parameters from supplied web URLs.
- Returns the common VulnScope result schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import unescape
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


DEFAULT_TIMEOUT = 8
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_PARAMS = 40
DEFAULT_PAYLOAD = "VulnScopeXSS"


def _result(module: str, target: str, status: str,
            findings: Optional[List[Dict[str, Any]]] = None,
            errors: Optional[List[str]] = None,
            **extra: Any) -> Dict[str, Any]:
    result = {
        "module": module,
        "target": target,
        "status": status,
        "findings": findings or [],
        "errors": errors or [],
    }
    result.update(extra)
    return result


def _finding(target_url: str, parameter: str, evidence: str,
             location: str = "query") -> Dict[str, Any]:
    return {
        "module": "xss",
        "type": "Reflected XSS",
        "name": parameter,
        "severity": "High",
        "title": "Potential reflected XSS",
        "description": (
            "The controlled test marker was reflected in the HTTP response "
            "without sufficient output encoding."
        ),
        "risk": (
            "An attacker may be able to inject script-capable content into "
            "a victim's browser if the application is vulnerable."
        ),
        "recommendation": (
            "Apply context-aware output encoding, validate input where "
            "appropriate, and use a restrictive Content-Security-Policy."
        ),
        "evidence": evidence,
        "url": target_url,
        "parameter": parameter,
        "location": location,
        "confidence": "medium",
    }


def _same_origin(base: str, candidate: str) -> bool:
    a, b = urlparse(base), urlparse(candidate)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def _replace_query_parameter(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    changed = False
    new_pairs = []
    for key, old_value in pairs:
        if key == name and not changed:
            new_pairs.append((key, value))
            changed = True
        else:
            new_pairs.append((key, old_value))
    return urlunparse(parsed._replace(query=urlencode(new_pairs, doseq=True)))


def _discover_query_parameters(url: str) -> List[str]:
    return [key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def _discover_forms(base_url: str, html: str) -> List[Tuple[str, str, List[str]]]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action") or base_url)
        method = (form.get("method") or "get").lower()
        names = []

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if name and name not in names:
                names.append(name)

        if names:
            forms.append((action, method, names))

    return forms


def _discover_links(base_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for tag in soup.find_all("a", href=True):
        candidate = urljoin(base_url, tag["href"])
        parsed = urlparse(candidate)
        clean = urlunparse(parsed._replace(fragment=""))

        if parsed.scheme in ("http", "https") and _same_origin(base_url, clean):
            if clean not in links:
                links.append(clean)

    return links


def _marker_reflected(response_text: str, marker: str) -> bool:
    # We deliberately check the exact marker in the response body.
    # This is evidence of reflection, not proof of exploitability.
    return marker in unescape(response_text)


def _test_query_parameter(session: requests.Session, url: str,
                          parameter: str, timeout: int,
                          marker: str) -> Optional[Dict[str, Any]]:
    test_url = _replace_query_parameter(url, parameter, marker)
    try:
        response = session.get(test_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None

    if _marker_reflected(response.text, marker):
        evidence = (
            f"Marker '{marker}' was reflected in the response body "
            f"for query parameter '{parameter}'."
        )
        return _finding(test_url, parameter, evidence, "query")

    return None


def _test_form(session: requests.Session, action: str, method: str,
               fields: Iterable[str], timeout: int,
               marker: str) -> List[Dict[str, Any]]:
    findings = []

    for field in fields:
        data = {name: "VulnScopeTest" for name in fields}
        data[field] = marker

        try:
            if method == "post":
                response = session.post(
                    action, data=data, timeout=timeout, allow_redirects=True
                )
            else:
                response = session.get(
                    action, params=data, timeout=timeout, allow_redirects=True
                )
        except requests.RequestException:
            continue

        if _marker_reflected(response.text, marker):
            evidence = (
                f"Marker '{marker}' was reflected in the response body "
                f"after testing form field '{field}'."
            )
            findings.append(_finding(
                response.url, field, evidence, "form"
            ))

    return findings


def scan_url(url: str, *, session: Optional[requests.Session] = None,
             timeout: int = DEFAULT_TIMEOUT,
             marker: str = DEFAULT_PAYLOAD) -> Dict[str, Any]:
    """Scan one authorized URL for controlled reflected-XSS behavior."""
    if not url.startswith(("http://", "https://")):
        return _result(
            "xss", url, "error",
            errors=["URL must use HTTP or HTTPS."],
            scanned_urls=[],
            query_parameters=[],
            forms_discovered=[],
            links_discovered=[],
            marker=marker,
        )

    session = session or requests.Session()
    findings: List[Dict[str, Any]] = []

    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return _result(
            "xss", url, "error",
            errors=[str(exc)],
            scanned_urls=[],
            query_parameters=[],
            forms_discovered=[],
            links_discovered=[],
            marker=marker,
        )

    query_parameters = sorted(set(_discover_query_parameters(response.url)))
    forms = _discover_forms(response.url, response.text)
    links = _discover_links(response.url, response.text)

    for parameter in query_parameters:
        result = _test_query_parameter(
            session, response.url, parameter, timeout, marker
        )
        if result:
            findings.append(result)

    for action, method, fields in forms:
        findings.extend(
            _test_form(session, action, method, fields, timeout, marker)
        )

    # De-duplicate by URL + parameter + location.
    unique = {}
    for item in findings:
        key = (item["url"], item["parameter"], item["location"])
        unique[key] = item

    return _result(
        "xss", url, "success", list(unique.values()),
        scanned_urls=[response.url],
        query_parameters=query_parameters,
        forms_discovered=[
            {"action": action, "method": method, "fields": list(fields)}
            for action, method, fields in forms
        ],
        links_discovered=links,
        marker=marker,
    )


def run_xss_scan(target: str, recon_data: Optional[Dict[str, Any]] = None,
                 *, timeout: int = DEFAULT_TIMEOUT,
                 max_pages: int = DEFAULT_MAX_PAGES) -> Dict[str, Any]:
    """
    Standard VulnScope entry point.

    Expected recon_data may contain:
      {"web_services": ["http://target/", "https://target/app"]}
    """
    urls: List[str] = []

    if recon_data:
        for value in recon_data.get("web_services", []) or []:
            if isinstance(value, str):
                urls.append(value)
            elif isinstance(value, dict) and value.get("url"):
                urls.append(value["url"])

    if target.startswith(("http://", "https://")):
        urls.append(target)

    urls = list(dict.fromkeys(urls))
    if not urls:
        return _result(
            "xss", target, "skipped",
            reason="No applicable web service was discovered by Recon.",
            web_targets=[],
            scanned_urls=[],
            scan_details=[],
            marker=DEFAULT_PAYLOAD,
        )

    session = requests.Session()
    findings: List[Dict[str, Any]] = []
    errors: List[str] = []
    visited: Set[str] = set()
    queue = urls[:max_pages]
    scan_details: List[Dict[str, Any]] = []

    while queue and len(visited) < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        result = scan_url(
            current, session=session, timeout=timeout
        )

        if result["status"] == "error":
            errors.extend(result["errors"])
            continue

        findings.extend(result["findings"])
        scan_details.append(
            {
                "requested_url": current,
                "scanned_urls": result.get("scanned_urls", []),
                "query_parameters": result.get("query_parameters", []),
                "forms_discovered": result.get("forms_discovered", []),
                "links_discovered": result.get("links_discovered", []),
            }
        )

        # Lightweight same-origin crawling for additional parameterized pages.
        for link in result.get("links_discovered", []):
            if link not in visited and len(queue) + len(visited) < max_pages:
                if urlparse(link).query:
                    queue.append(link)

    # De-duplicate findings.
    unique = {}
    for item in findings:
        key = (item["url"], item["parameter"], item["location"])
        unique[key] = item

    status = "error" if not visited and errors else "success"
    return _result(
        "xss", target, status, list(unique.values()), errors,
        web_targets=urls,
        scanned_urls=list(visited),
        scan_details=scan_details,
        max_pages=max_pages,
        marker=DEFAULT_PAYLOAD,
    )


__all__ = ["run_xss_scan", "scan_url"]

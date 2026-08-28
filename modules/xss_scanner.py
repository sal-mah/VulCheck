"""
modules/xss_scanner.py

Vulneraptor Lite - XSS Scanner

AUTHORIZED SECURITY TESTING ONLY.

Supported:
    - Reflected XSS detection
    - Stored XSS detection
    - GET query parameters
    - GET forms
    - POST forms
    - Multiple XSS probes
    - HTML body context detection
    - HTML attribute context detection
    - JavaScript context detection
    - HTML comment context detection
    - Encoded reflection detection
    - Same-origin crawling
    - Form discovery
    - Stored-XSS verification
    - Confidence scoring
    - Structured Vulneraptor result schema

Standard entry point:

    run_xss_scan(target, recon_data=None) -> dict

Single URL:

    scan_url(url) -> dict

IMPORTANT:
    This scanner is intended for systems you own or are authorized
    to test. It is designed for local security labs and training
    environments.
"""

from __future__ import annotations

import html
import re
import uuid

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests


# ============================================================
# CONFIGURATION
# ============================================================

MODULE_NAME = "xss"

DEFAULT_TIMEOUT = 8

DEFAULT_MAX_PAGES = 30

DEFAULT_MAX_PARAMS = 50

DEFAULT_MAX_FORMS = 30

DEFAULT_MAX_FIELDS = 30

DEFAULT_MAX_STORED_TESTS = 20

USER_AGENT = "Vulneraptor-Lite-XSS-Scanner/2.0"


# ============================================================
# PAYLOAD / PROBE MARKERS
# ============================================================

# These are deliberately distinctive scanner probes.
#
# The scanner does not attempt to execute arbitrary JavaScript.
# It first determines whether attacker-controlled syntax survives
# into dangerous browser contexts.

PROBES = [
    {
        "name": "html_probe",
        "payload": "<VulneraptorXSS>",
        "marker": "VulneraptorXSS",
    },
    {
        "name": "quote_probe",
        "payload": '"VulneraptorXSS"',
        "marker": "VulneraptorXSS",
    },
    {
        "name": "attribute_probe",
        "payload": "'VulneraptorXSS'",
        "marker": "VulneraptorXSS",
    },
    {
        "name": "tag_probe",
        "payload": "<b>VulneraptorXSS</b>",
        "marker": "VulneraptorXSS",
    },
    {
        "name": "svg_probe",
        "payload": "<svg data-Vulneraptor='VulneraptorXSS'>",
        "marker": "VulneraptorXSS",
    },
]


# Simple harmless markers used to determine whether encoding occurred.

HTML_ENCODED_MARKERS = [
    "&lt;VulneraptorXSS&gt;",
    "&quot;VulneraptorXSS&quot;",
    "&#34;VulneraptorXSS&#34;",
    "&#x22;VulneraptorXSS&#x22;",
    "&#x3c;VulneraptorXSS&#x3e;",
]


# ============================================================
# RESULT HELPERS
# ============================================================

def _result(
    module: str,
    target: str,
    status: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    errors: Optional[List[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:

    result = {
        "module": module,
        "target": target,
        "status": status,
        "findings": findings or [],
        "errors": errors or [],
    }

    result.update(extra)

    return result


def _finding(
    *,
    target_url: str,
    parameter: str,
    location: str,
    xss_type: str,
    severity: str,
    confidence: str,
    title: str,
    description: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:

    return {
        "module": MODULE_NAME,
        "type": xss_type,
        "name": parameter,
        "severity": severity,
        "title": title,
        "description": description,
        "risk": (
            "If attacker-controlled input reaches an executable browser "
            "context without appropriate output encoding, an attacker may "
            "execute script-capable content in a victim's browser context."
        ),
        "recommendation": (
            "Use context-aware output encoding, validate input where "
            "appropriate, avoid unsafe HTML sinks, and deploy a restrictive "
            "Content-Security-Policy."
        ),
        "evidence": evidence,
        "url": target_url,
        "parameter": parameter,
        "location": location,
        "confidence": confidence,
    }


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class Reflection:
    marker: str
    context: str
    encoded: bool
    snippet: str


@dataclass
class FormInfo:
    action: str
    method: str
    fields: List[str]


# ============================================================
# URL HELPERS
# ============================================================

def _normalize_url(url: str) -> Optional[str]:

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return None

    parsed = urlparse(url)

    return urlunparse(
        parsed._replace(
            fragment=""
        )
    )


def _same_origin(
    base: str,
    candidate: str,
) -> bool:

    a = urlparse(base)

    b = urlparse(candidate)

    return (
        a.scheme.lower(),
        a.netloc.lower(),
    ) == (
        b.scheme.lower(),
        b.netloc.lower(),
    )


def _replace_query_parameter(
    url: str,
    name: str,
    value: str,
) -> str:

    parsed = urlparse(url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    changed = False

    new_pairs = []

    for key, old_value in pairs:

        if key == name and not changed:

            new_pairs.append(
                (
                    key,
                    value,
                )
            )

            changed = True

        else:

            new_pairs.append(
                (
                    key,
                    old_value,
                )
            )

    return urlunparse(
        parsed._replace(
            query=urlencode(
                new_pairs,
                doseq=True,
            )
        )
    )


def _discover_query_parameters(
    url: str,
) -> List[str]:

    return list(
        dict.fromkeys(
            key
            for key, _ in parse_qsl(
                urlparse(url).query,
                keep_blank_values=True,
            )
        )
    )


# ============================================================
# HTML PARSER
# ============================================================

class _HTMLParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.links: List[str] = []

        self.forms: List[FormInfo] = []

        self.current_form: Optional[
            Dict[str, Any]
        ] = None


    def handle_starttag(
        self,
        tag: str,
        attrs: List[Tuple[str, Optional[str]]],
    ):

        attrs_dict = dict(
            attrs
        )

        tag_lower = tag.lower()


        # ----------------------------------------------------
        # Links
        # ----------------------------------------------------

        if tag_lower == "a":

            href = attrs_dict.get(
                "href"
            )

            if href:

                self.links.append(
                    href
                )


        # ----------------------------------------------------
        # Forms
        # ----------------------------------------------------

        elif tag_lower == "form":

            self.current_form = {
                "action": attrs_dict.get(
                    "action",
                    "",
                ),
                "method": attrs_dict.get(
                    "method",
                    "get",
                ).lower(),
                "fields": [],
            }


        elif tag_lower in (
            "input",
            "textarea",
            "select",
            "button",
        ):

            if self.current_form is not None:

                name = attrs_dict.get(
                    "name"
                )

                if name and name not in self.current_form[
                    "fields"
                ]:

                    self.current_form[
                        "fields"
                    ].append(
                        name
                    )


    def handle_endtag(
        self,
        tag: str,
    ):

        if (
            tag.lower() == "form"
            and self.current_form is not None
        ):

            self.forms.append(
                FormInfo(
                    action=self.current_form[
                        "action"
                    ],
                    method=self.current_form[
                        "method"
                    ],
                    fields=list(
                        self.current_form[
                            "fields"
                        ]
                    ),
                )
            )

            self.current_form = None


def _parse_html(
    base_url: str,
    html_text: str,
) -> Tuple[
    List[FormInfo],
    List[str],
]:

    parser = _HTMLParser()

    try:

        parser.feed(
            html_text
        )

    except Exception:

        return [], []


    forms = []

    for form in parser.forms:

        action = urljoin(
            base_url,
            form.action or base_url,
        )

        if _same_origin(
            base_url,
            action,
        ):

            forms.append(
                FormInfo(
                    action=action,
                    method=form.method,
                    fields=form.fields,
                )
            )


    links = []

    for href in parser.links:

        candidate = urljoin(
            base_url,
            href,
        )

        candidate = _normalize_url(
            candidate
        )

        if not candidate:
            continue

        if not _same_origin(
            base_url,
            candidate,
        ):
            continue

        if candidate not in links:

            links.append(
                candidate
            )


    return forms, links


# ============================================================
# RESPONSE CONTEXT ANALYSIS
# ============================================================

def _extract_snippet(
    text: str,
    position: int,
    radius: int = 140,
) -> str:

    start = max(
        0,
        position - radius,
    )

    end = min(
        len(text),
        position + radius,
    )

    return text[
        start:end
    ].replace(
        "\n",
        " ",
    )


def _find_marker_context(
    response_text: str,
    marker: str,
) -> List[Reflection]:

    results: List[
        Reflection
    ] = []

    if not response_text:
        return results


    # --------------------------------------------------------
    # Raw marker
    # --------------------------------------------------------

    start = 0

    while True:

        position = response_text.find(
            marker,
            start,
        )

        if position == -1:
            break


        snippet = _extract_snippet(
            response_text,
            position,
        )


        before = response_text[
            max(
                0,
                position - 500,
            ):position
        ]

        after = response_text[
            position + len(marker):
            position + len(marker) + 500
        ]


        # ----------------------------------------------------
        # Script context
        # ----------------------------------------------------

        script_open = (
            before.lower().rfind(
                "<script"
            )
        )

        script_close = (
            before.lower().rfind(
                "</script>"
            )
        )


        if (
            script_open > script_close
        ):

            results.append(
                Reflection(
                    marker=marker,
                    context="javascript",
                    encoded=False,
                    snippet=snippet,
                )
            )

            start = position + len(
                marker
            )

            continue


        # ----------------------------------------------------
        # HTML comment
        # ----------------------------------------------------

        comment_open = before.rfind(
            "<!--"
        )

        comment_close = before.rfind(
            "-->"
        )


        if (
            comment_open > comment_close
        ):

            results.append(
                Reflection(
                    marker=marker,
                    context="html-comment",
                    encoded=False,
                    snippet=snippet,
                )
            )

            start = position + len(
                marker
            )

            continue


        # ----------------------------------------------------
        # Attribute context
        # ----------------------------------------------------

        tag_start = before.rfind(
            "<"
        )

        tag_end = before.rfind(
            ">"
        )


        if tag_start > tag_end:

            # We are inside an HTML tag.

            results.append(
                Reflection(
                    marker=marker,
                    context="html-attribute",
                    encoded=False,
                    snippet=snippet,
                )
            )

            start = position + len(
                marker
            )

            continue


        # ----------------------------------------------------
        # HTML body
        # ----------------------------------------------------

        results.append(
            Reflection(
                marker=marker,
                context="html-body",
                encoded=False,
                snippet=snippet,
            )
        )


        start = position + len(
            marker
        )


    # --------------------------------------------------------
    # Encoded marker detection
    # --------------------------------------------------------

    decoded = html.unescape(
        response_text
    )

    if decoded != response_text:

        if marker in decoded:

            position = decoded.find(
                marker
            )

            results.append(
                Reflection(
                    marker=marker,
                    context="encoded-html",
                    encoded=True,
                    snippet=_extract_snippet(
                        decoded,
                        position,
                    ),
                )
            )


    return results


# ============================================================
# REFLECTION TEST
# ============================================================

def _test_probe(
    session: requests.Session,
    url: str,
    parameter: str,
    timeout: int,
    probe: Dict[str, str],
) -> Optional[Dict[str, Any]]:

    test_url = _replace_query_parameter(
        url,
        parameter,
        probe["payload"],
    )


    try:

        response = session.get(
            test_url,
            timeout=timeout,
            allow_redirects=True,
        )

    except requests.RequestException:

        return None


    reflections = _find_marker_context(
        response.text,
        probe["marker"],
    )


    if not reflections:

        return None


    best = reflections[0]


    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    if best.context in (
        "javascript",
        "html-attribute",
    ) and not best.encoded:

        confidence = "high"

    elif (
        best.context == "html-body"
        and "<" in probe["payload"]
        and not best.encoded
    ):

        confidence = "high"

    elif best.context == "encoded-html":

        confidence = "low"

    else:

        confidence = "medium"


    severity = (
        "High"
        if confidence == "high"
        else "Medium"
    )


    title = (
        f"Potential reflected XSS "
        f"in parameter '{parameter}'"
    )


    description = (
        f"Controlled XSS probe was reflected in "
        f"{best.context} context without evidence "
        f"of complete output encoding."
    )


    return _finding(
        target_url=test_url,
        parameter=parameter,
        location=best.context,
        xss_type="Reflected XSS",
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence={
            "probe": probe["name"],
            "payload": probe["payload"],
            "marker": probe["marker"],
            "context": best.context,
            "encoded": best.encoded,
            "snippet": best.snippet,
            "status_code": response.status_code,
            "final_url": response.url,
        },
    )


# ============================================================
# FORM TESTING
# ============================================================

def _test_form_field(
    session: requests.Session,
    form: FormInfo,
    field: str,
    timeout: int,
    probe: Dict[str, str],
) -> Optional[Dict[str, Any]]:

    data = {}

    for name in form.fields:

        data[name] = "VulneraptorTest"


    data[field] = probe["payload"]


    try:

        if form.method == "post":

            response = session.post(
                form.action,
                data=data,
                timeout=timeout,
                allow_redirects=True,
            )

        else:

            response = session.get(
                form.action,
                params=data,
                timeout=timeout,
                allow_redirects=True,
            )

    except requests.RequestException:

        return None


    reflections = _find_marker_context(
        response.text,
        probe["marker"],
    )


    if not reflections:

        return None


    best = reflections[0]


    if best.context in (
        "javascript",
        "html-attribute",
    ):

        confidence = "high"

    elif (
        best.context == "html-body"
        and not best.encoded
    ):

        confidence = "high"

    else:

        confidence = "medium"


    severity = (
        "High"
        if confidence == "high"
        else "Medium"
    )


    return _finding(
        target_url=response.url,
        parameter=field,
        location=f"form:{best.context}",
        xss_type="Reflected XSS",
        severity=severity,
        confidence=confidence,
        title=(
            f"Potential reflected XSS "
            f"in form field '{field}'"
        ),
        description=(
            "A controlled XSS probe submitted through a web form "
            "was reflected in the resulting response."
        ),
        evidence={
            "form_action": form.action,
            "form_method": form.method,
            "field": field,
            "probe": probe["name"],
            "payload": probe["payload"],
            "context": best.context,
            "encoded": best.encoded,
            "snippet": best.snippet,
            "status_code": response.status_code,
            "final_url": response.url,
        },
    )


# ============================================================
# STORED XSS
# ============================================================

def _test_stored_form(
    session: requests.Session,
    form: FormInfo,
    field: str,
    timeout: int,
    marker: str,
) -> Optional[Dict[str, Any]]:

    """
    Submit a harmless unique marker through a POST/GET form,
    then check the application's same-origin pages for persistence.

    This detects persistence of attacker-controlled content without
    executing arbitrary JavaScript.
    """

    unique_marker = (
        f"VulneraptorStoredXSS_"
        f"{uuid.uuid4().hex[:12]}"
    )


    payload = (
        f"<VulneraptorStoredXSS "
        f"data-marker='{unique_marker}'>"
        f"</VulneraptorStoredXSS>"
    )


    data = {}

    for name in form.fields:

        data[name] = "VulneraptorStoredTest"


    data[field] = payload


    try:

        if form.method == "post":

            response = session.post(
                form.action,
                data=data,
                timeout=timeout,
                allow_redirects=True,
            )

        else:

            response = session.get(
                form.action,
                params=data,
                timeout=timeout,
                allow_redirects=True,
            )

    except requests.RequestException:

        return None


    # --------------------------------------------------------
    # Check immediate response.
    # --------------------------------------------------------

    pages_to_check = [
        response.url
    ]


    # Common post-submit location.
    parsed = urlparse(
        response.url
    )

    root = urlunparse(
        parsed._replace(
            query="",
            fragment="",
        )
    )


    if root not in pages_to_check:

        pages_to_check.append(
            root
        )


    # --------------------------------------------------------
    # Search returned page.
    # --------------------------------------------------------

    for check_url in pages_to_check:

        try:

            check_response = session.get(
                check_url,
                timeout=timeout,
                allow_redirects=True,
            )

        except requests.RequestException:

            continue


        if unique_marker not in html.unescape(
            check_response.text
        ):

            continue


        reflections = _find_marker_context(
            check_response.text,
            unique_marker,
        )


        context = (
            reflections[0].context
            if reflections
            else "unknown"
        )


        confidence = (
            "high"
            if context in (
                "html-body",
                "html-attribute",
                "javascript",
            )
            else "medium"
        )


        return _finding(
            target_url=check_response.url,
            parameter=field,
            location=f"stored:{context}",
            xss_type="Stored XSS",
            severity="High",
            confidence=confidence,
            title=(
                f"Potential stored XSS "
                f"in form field '{field}'"
            ),
            description=(
                "A unique controlled marker submitted through "
                "the form persisted and was subsequently returned "
                "by the application."
            ),
            evidence={
                "submission_endpoint": form.action,
                "submission_method": form.method,
                "field": field,
                "unique_marker": unique_marker,
                "display_url": check_response.url,
                "context": context,
                "payload": payload,
                "status_code": check_response.status_code,
            },
        )


    return None


# ============================================================
# URL SCANNER
# ============================================================

def scan_url(
    url: str,
    *,
    session: Optional[requests.Session] = None,
    timeout: int = DEFAULT_TIMEOUT,
    marker: str = "VulneraptorXSS",
    test_stored: bool = True,
) -> Dict[str, Any]:

    """
    Scan one authorized URL.

    Tests:
        - Query parameters
        - GET forms
        - POST forms
        - Stored XSS where applicable
    """

    normalized = _normalize_url(
        url
    )


    if not normalized:

        return _result(
            MODULE_NAME,
            url,
            "error",
            errors=[
                "URL must use HTTP or HTTPS."
            ],
            scanned_urls=[],
            query_parameters=[],
            forms_discovered=[],
            links_discovered=[],
            marker=marker,
        )


    if session is None:

        session = requests.Session()

        session.headers.update(
            {
                "User-Agent": USER_AGENT
            }
        )


    findings: List[
        Dict[str, Any]
    ] = []


    try:

        response = session.get(
            normalized,
            timeout=timeout,
            allow_redirects=True,
        )

    except requests.RequestException as exc:

        return _result(
            MODULE_NAME,
            normalized,
            "error",
            errors=[str(exc)],
            scanned_urls=[],
            query_parameters=[],
            forms_discovered=[],
            links_discovered=[],
            marker=marker,
        )


    final_url = response.url

    forms, links = _parse_html(
        final_url,
        response.text,
    )


    query_parameters = (
        _discover_query_parameters(
            final_url
        )
    )


    # ========================================================
    # QUERY PARAMETERS
    # ========================================================

    parameter_limit = 0


    for parameter in query_parameters:

        if parameter_limit >= DEFAULT_MAX_PARAMS:

            break


        parameter_limit += 1


        for probe in PROBES:

            result = _test_probe(
                session,
                final_url,
                parameter,
                timeout,
                probe,
            )

            if result:

                findings.append(
                    result
                )


                # One strong result is enough for this parameter.
                if result[
                    "confidence"
                ] == "high":

                    break


    # ========================================================
    # FORMS
    # ========================================================

    forms = forms[
        :DEFAULT_MAX_FORMS
    ]


    for form in forms:

        fields = form.fields[
            :DEFAULT_MAX_FIELDS
        ]


        for field in fields:

            # ------------------------------------------------
            # Reflected XSS
            # ------------------------------------------------

            for probe in PROBES:

                result = _test_form_field(
                    session,
                    form,
                    field,
                    timeout,
                    probe,
                )

                if result:

                    findings.append(
                        result
                    )

                    if result[
                        "confidence"
                    ] == "high":

                        break


            # ------------------------------------------------
            # Stored XSS
            # ------------------------------------------------

            if (
                test_stored
                and form.method == "post"
            ):

                stored_result = _test_stored_form(
                    session,
                    form,
                    field,
                    timeout,
                    marker,
                )

                if stored_result:

                    findings.append(
                        stored_result
                    )


    # ========================================================
    # DEDUPLICATION
    # ========================================================

    unique: Dict[
        Tuple[str, str, str, str],
        Dict[str, Any]
    ] = {}


    for item in findings:

        key = (
            item.get("type", ""),
            item.get("url", ""),
            item.get("parameter", ""),
            item.get("location", ""),
        )

        unique[key] = item


    return _result(
        MODULE_NAME,
        normalized,
        "success",
        list(
            unique.values()
        ),
        scanned_urls=[
            final_url
        ],
        query_parameters=query_parameters,
        forms_discovered=[
            {
                "action": form.action,
                "method": form.method,
                "fields": form.fields,
            }
            for form in forms
        ],
        links_discovered=links,
        marker=marker,
        probes=[
            probe["name"]
            for probe in PROBES
        ],
    )


# ============================================================
# RECON URL EXTRACTION
# ============================================================

def _extract_recon_urls(
    target: str,
    recon_data: Optional[
        Dict[str, Any]
    ],
) -> List[str]:

    urls: List[str] = []


    if recon_data:

        for key in (
            "urls",
            "web_services",
            "endpoints",
            "http_results",
        ):

            values = recon_data.get(
                key,
                []
            ) or []


            if not isinstance(
                values,
                (
                    list,
                    tuple,
                    set,
                ),
            ):

                values = [
                    values
                ]


            for item in values:

                if isinstance(
                    item,
                    str,
                ):

                    url = item

                elif isinstance(
                    item,
                    dict,
                ):

                    url = (
                        item.get("url")
                        or item.get("target")
                        or item.get("endpoint")
                    )

                else:

                    continue


                normalized = _normalize_url(
                    url
                )


                if normalized:

                    urls.append(
                        normalized
                    )


    target_normalized = _normalize_url(
        target
    )


    if target_normalized:

        urls.append(
            target_normalized
        )


    return list(
        dict.fromkeys(
            urls
        )
    )


# ============================================================
# MAIN Vulneraptor ENTRY POINT
# ============================================================

def run_xss_scan(
    target: str,
    recon_data: Optional[
        Dict[str, Any]
    ] = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> Dict[str, Any]:

    """
    Standard Vulneraptor XSS scanner entry point.

    Example:

        result = run_xss_scan(
            "http://127.0.0.1:5000/",
            recon_data={
                "web_services": [
                    "http://127.0.0.1:5000/"
                ]
            }
        )
    """

    urls = _extract_recon_urls(
        target,
        recon_data,
    )


    if not urls:

        return _result(
            MODULE_NAME,
            target,
            "skipped",
            reason=(
                "No applicable web service "
                "was discovered by Recon."
            ),
            web_targets=[],
            scanned_urls=[],
            scan_details=[],
            marker="VulneraptorXSS",
        )


    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT
        }
    )


    findings: List[
        Dict[str, Any]
    ] = []


    errors: List[
        str
    ] = []


    visited: Set[
        str
    ] = set()


    queue: List[
        str
    ] = list(
        urls
    )


    scan_details: List[
        Dict[str, Any]
    ] = []


    # ========================================================
    # CRAWL / SCAN LOOP
    # ========================================================

    while (
        queue
        and len(visited) < max_pages
    ):

        current = queue.pop(
            0
        )


        normalized = _normalize_url(
            current
        )


        if not normalized:

            continue


        if normalized in visited:

            continue


        visited.add(
            normalized
        )


        result = scan_url(
            normalized,
            session=session,
            timeout=timeout,
            marker="VulneraptorXSS",
            test_stored=True,
        )


        if result[
            "status"
        ] == "error":

            errors.extend(
                result.get(
                    "errors",
                    [],
                )
            )

            continue


        findings.extend(
            result.get(
                "findings",
                [],
            )
        )


        scan_details.append(
            {
                "requested_url": normalized,
                "scanned_urls": result.get(
                    "scanned_urls",
                    [],
                ),
                "query_parameters": result.get(
                    "query_parameters",
                    [],
                ),
                "forms_discovered": result.get(
                    "forms_discovered",
                    [],
                ),
                "links_discovered": result.get(
                    "links_discovered",
                    [],
                ),
                "findings_count": len(
                    result.get(
                        "findings",
                        [],
                    )
                ),
            }
        )


        # ====================================================
        # SAME-ORIGIN CRAWLING
        # ====================================================

        for link in result.get(
            "links_discovered",
            [],
        ):

            if len(
                queue
            ) + len(
                visited
            ) >= max_pages:

                break


            if link in visited:

                continue


            # Only follow same-origin URLs.

            if not _same_origin(
                normalized,
                link,
            ):

                continue


            # Prioritize parameterized pages because they provide
            # additional XSS testing surfaces.

            if (
                urlparse(link).query
            ):

                queue.insert(
                    0,
                    link,
                )

            else:

                queue.append(
                    link
                )


    # ========================================================
    # GLOBAL DEDUPLICATION
    # ========================================================

    unique: Dict[
        Tuple[str, str, str, str],
        Dict[str, Any]
    ] = {}


    for item in findings:

        key = (
            item.get(
                "type",
                "",
            ),
            item.get(
                "url",
                "",
            ),
            item.get(
                "parameter",
                "",
            ),
            item.get(
                "location",
                "",
            ),
        )


        existing = unique.get(
            key
        )


        if existing is None:

            unique[key] = item

            continue


        # Keep the higher-confidence finding.

        confidence_rank = {
            "low": 1,
            "medium": 2,
            "high": 3,
        }


        old_rank = confidence_rank.get(
            existing.get(
                "confidence",
                "low",
            ),
            0,
        )


        new_rank = confidence_rank.get(
            item.get(
                "confidence",
                "low",
            ),
            0,
        )


        if new_rank > old_rank:

            unique[key] = item


    # ========================================================
    # STATUS
    # ========================================================

    if (
        not visited
        and errors
    ):

        status = "error"

    else:

        status = "success"


    # ========================================================
    # SUMMARY
    # ========================================================

    final_findings = list(
        unique.values()
    )


    reflected_count = sum(
        1
        for item in final_findings
        if item.get(
            "type"
        ) == "Reflected XSS"
    )


    stored_count = sum(
        1
        for item in final_findings
        if item.get(
            "type"
        ) == "Stored XSS"
    )


    high_confidence = sum(
        1
        for item in final_findings
        if item.get(
            "confidence"
        ) == "high"
    )


    return _result(
        MODULE_NAME,
        target,
        status,
        final_findings,
        errors,

        web_targets=urls,

        scanned_urls=list(
            visited
        ),

        scan_details=scan_details,

        max_pages=max_pages,

        timeout=timeout,

        scanner_version="2.0",

        detection_summary={
            "total_findings": len(
                final_findings
            ),
            "reflected_xss": reflected_count,
            "stored_xss": stored_count,
            "high_confidence": high_confidence,
        },

        capabilities=[
            "reflected-xss",
            "stored-xss",
            "query-parameter-testing",
            "GET-form-testing",
            "POST-form-testing",
            "html-context-analysis",
            "javascript-context-analysis",
            "html-attribute-analysis",
            "html-comment-analysis",
            "encoded-reflection-analysis",
            "same-origin-crawling",
        ],
    )


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    import json
    import sys


    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python modules/xss_scanner.py "
            "http://127.0.0.1:5000/"
        )

        raise SystemExit(
            1
        )


    target = sys.argv[1]


    result = run_xss_scan(
        target,
        recon_data={
            "web_services": [
                target
            ]
        },
    )


    print(
        json.dumps(
            result,
            indent=4,
            ensure_ascii=False,
        )
    )


__all__ = [
    "run_xss_scan",
    "scan_url",
]


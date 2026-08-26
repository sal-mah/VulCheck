
from __future__ import annotations
import argparse
import csv
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, RequestException, SSLError, Timeout

try:
    from config.security_rules import (
        SECURITY_HEADERS,
        SEVERITY_ORDER,
        SEVERITY_WEIGHTS,
        SERVICE_RULES,
        SCANNER_DEFAULTS,
    )
except ImportError:
    from security_rules import (
        SECURITY_HEADERS,
        SEVERITY_ORDER,
        SEVERITY_WEIGHTS,
        SERVICE_RULES,
        SCANNER_DEFAULTS,
    )


TOOL_NAME = "VulnScope Lite"
TOOL_VERSION = "2.1.0"

REQUEST_TIMEOUT = SCANNER_DEFAULTS["request_timeout"]
MAX_RETRIES = SCANNER_DEFAULTS["max_retries"]
RETRY_DELAY = SCANNER_DEFAULTS["retry_delay"]

USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (Security Configuration Scanner)"

CONFIDENCE_MULTIPLIERS = {
    "High": 1.0,
    "Medium": 0.75,
    "Low": 0.5,
}

CLASSIFICATION_ORDER = {
    "Finding": 3,
    "Hardening": 2,
    "Observation": 1,
}

COOKIE_SEVERITY_MATRIX = {
    "Session/Auth": {
        "secure": "High",
        "httponly": "High",
        "samesite": "Medium",
    },
    "Functional": {
        "secure": "Medium",
        "httponly": "Medium",
        "samesite": "Low",
    },
    "Analytics/Tracking": {
        "secure": "Low",
        "httponly": "Info",
        "samesite": "Info",
    },
    "Unknown": {
        "secure": "Low",
        "httponly": "Low",
        "samesite": "Low",
    },
}

SESSION_COOKIE_KEYWORDS = (
    "session",
    "sess",
    "sid",
    "auth",
    "login",
    "access_token",
    "refresh_token",
    "id_token",
    "jwt",
    "sso",
    "remember",
    "identity",
)

FUNCTIONAL_COOKIE_KEYWORDS = (
    "csrf",
    "xsrf",
    "pref",
    "preference",
    "locale",
    "language",
    "lang",
    "theme",
    "currency",
    "timezone",
    "tz",
    "consent",
    "settings",
    "feature",
    "flag",
    "region",
    "country",
    "device",
    "viewport",
    "cf_bm",
    "cf_clearance",
)

ANALYTICS_COOKIE_KEYWORDS = (
    "analytics",
    "attribution",
    "bucket",
    "bucketing",
    "experiment",
    "abtest",
    "ab_test",
    "tracking",
    "track",
    "utm",
    "optimizely",
    "amplitude",
    "mixpanel",
    "segment",
    "ajs_",
    "_ga",
    "_gid",
    "_gat",
    "_gcl",
    "_fbp",
    "_fbc",
)


# ============================================================
# General utilities
# ============================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_target(target: str) -> str:
    """Normalize an IP/hostname or HTTP(S) URL into an HTTP(S) URL."""
    if not isinstance(target, str):
        raise ValueError("Target must be a string.")

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    parsed = urlparse(target)

    if parsed.scheme:
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Unsupported URL scheme: {parsed.scheme}. "
                "Only http:// and https:// are supported."
            )
        if not parsed.hostname:
            raise ValueError("Target does not contain a valid hostname.")
        return target

    return f"http://{target}"


def validate_url(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// are supported.")

    if not parsed.hostname:
        raise ValueError("Target does not contain a valid hostname.")

    return True


def make_finding(
    finding_type: str,
    name: str,
    severity: str,
    title: str,
    description: str,
    risk: str,
    recommendation: str,
    evidence: str,
    url: Optional[str] = None,
    *,
    service: Optional[str] = None,
    port: Optional[int] = None,
    confidence: str = "High",
    category: Optional[str] = None,
    classification: str = "Finding",
    risk_contribution: Optional[float] = None,
    applicability: float = 1.0,
    cookie_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Create the common VulnScope finding schema."""
    finding = {
        "module": "security_config",
        "type": finding_type,
        "name": name,
        "severity": severity,
        "confidence": confidence,
        "category": category or finding_type,
        "classification": classification,
        "title": title,
        "description": description,
        "risk": risk,
        "recommendation": recommendation,
        "evidence": evidence,
        "url": url,
    }

    if risk_contribution is not None:
        finding["risk_contribution"] = risk_contribution

    if applicability != 1.0:
        finding["applicability"] = applicability

    if cookie_type is not None:
        finding["cookie_type"] = cookie_type

    if service is not None:
        finding["service"] = service

    if port is not None:
        finding["port"] = port

    return finding


def empty_result(
    target: str,
    *,
    status: str = "success",
    recon_used: bool = False,
) -> Dict[str, Any]:
    return {
        "module": "security_config",
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target,
        "scan_started": now_iso(),
        "status": status,
        "recon_used": recon_used,
        "web_targets": [],
        "services_checked": [],
        "findings": [],
        "errors": [],
        "risk_score": 0,
        "severity_counts": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        },
        "classification_counts": {
            "Finding": 0,
            "Hardening": 0,
            "Observation": 0,
        },
    }


# ============================================================
# Error classification / DNS
# ============================================================

def classify_request_error(error: BaseException) -> str:
    if isinstance(error, Timeout):
        return "Connection timeout"

    if isinstance(error, SSLError):
        return "TLS/SSL error"

    if isinstance(error, ConnectionError):
        message = str(error).lower()

        dns_terms = (
            "name or service not known",
            "nodename nor servname",
            "temporary failure in name resolution",
            "getaddrinfo failed",
            "failed to resolve",
        )

        if any(term in message for term in dns_terms):
            return "DNS resolution failure"

        if "connection refused" in message:
            return "Connection refused"

        if "max retries exceeded" in message:
            return "Connection failed"

        return "Network connection error"

    return "Request error"


def resolve_hostname(hostname: str) -> tuple[bool, Optional[str]]:
    try:
        socket.getaddrinfo(hostname, None)
        return True, None
    except socket.gaierror as error:
        return False, str(error)


# ============================================================
# HTTP request layer
# ============================================================

def request_with_retry(url: str) -> Dict[str, Any]:
    """
    Perform one normal GET request with a small retry budget.

    Redirects are followed so the scanner can inspect the final
    response and preserve the redirect chain.
    """
    validate_url(url)

    parsed = urlparse(url)
    dns_ok, dns_error = resolve_hostname(parsed.hostname)

    if not dns_ok:
        return {
            "success": False,
            "response": None,
            "error_type": "DNS resolution failure",
            "error_message": dns_error,
        }

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    last_error: Optional[BaseException] = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )

            return {
                "success": True,
                "response": response,
                "error_type": None,
                "error_message": None,
            }

        except RequestException as error:
            last_error = error

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    return {
        "success": False,
        "response": None,
        "error_type": classify_request_error(last_error or RequestException()),
        "error_message": str(last_error),
    }


# ============================================================
# Recon normalization
# ============================================================

def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return list(value)

    return [value]


def _service_name(service: Any) -> Optional[str]:
    if isinstance(service, str):
        return service.strip().lower() or None

    if isinstance(service, dict):
        value = (
            service.get("service")
            or service.get("name")
            or service.get("service_name")
            or service.get("protocol")
        )

        if value:
            return str(value).strip().lower()

    return None


def _service_port(service: Any) -> Optional[int]:
    if isinstance(service, dict):
        value = service.get("port")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    return None


def normalize_recon_data(
    target: str,
    recon_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Normalize common Recon schemas without requiring the Recon module
    to use one exact internal representation.

    Supported examples:
      open_ports: [22, 80]
      services: [{"port": 22, "service": "ssh"}]
      web_services: ["http://10.0.0.1"]
    """
    normalized = {
        "host": target,
        "reachable": None,
        "open_ports": [],
        "services": [],
        "web_services": [],
    }

    if not isinstance(recon_data, dict):
        return normalized

    normalized["host"] = (
        recon_data.get("host")
        or recon_data.get("target")
        or recon_data.get("ip")
        or target
    )

    if "reachable" in recon_data:
        normalized["reachable"] = bool(recon_data["reachable"])
    elif "host_status" in recon_data:
        normalized["reachable"] = str(
            recon_data["host_status"]
        ).lower() in {"reachable", "up", "online", "true"}

    # Ports
    for value in _as_list(
        recon_data.get("open_ports")
        or recon_data.get("ports")
        or recon_data.get("open_ports_list")
    ):
        try:
            port = int(value.get("port") if isinstance(value, dict) else value)
            if port not in normalized["open_ports"]:
                normalized["open_ports"].append(port)
        except (TypeError, ValueError):
            continue

    # Services
    raw_services = _as_list(
        recon_data.get("services")
        or recon_data.get("service_map")
        or recon_data.get("detected_services")
    )

    for item in raw_services:
        name = _service_name(item)
        port = _service_port(item)

        if name:
            normalized["services"].append(
                {
                    "service": name,
                    "port": port,
                    "version": (
                        item.get("version")
                        if isinstance(item, dict)
                        else None
                    ),
                }
            )

            if port is not None and port not in normalized["open_ports"]:
                normalized["open_ports"].append(port)

    # If Recon provides only ports, infer service names from standard ports.
    standard_ports = {
        20: "ftp",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        139: "smb",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        5432: "postgresql",
        1433: "mssql",
        1521: "oracle",
        6379: "redis",
        27017: "mongodb",
    }

    existing = {(item["service"], item["port"]) for item in normalized["services"]}

    for port in normalized["open_ports"]:
        service = standard_ports.get(port)

        if service and (service, port) not in existing:
            normalized["services"].append(
                {
                    "service": service,
                    "port": port,
                    "version": None,
                }
            )

    # Web targets
    raw_web = _as_list(
        recon_data.get("web_services")
        or recon_data.get("web_targets")
        or recon_data.get("http_services")
        or recon_data.get("urls")
    )

    for item in raw_web:
        if isinstance(item, str):
            value = item.strip()
        elif isinstance(item, dict):
            value = (
                item.get("url")
                or item.get("target")
                or item.get("endpoint")
                or ""
            ).strip()
        else:
            value = ""

        if value:
            try:
                value = normalize_target(value)
            except ValueError:
                continue

            if value not in normalized["web_services"]:
                normalized["web_services"].append(value)

    # Infer web targets from service information when Recon identifies
    # standard HTTP/HTTPS services but did not explicitly provide URLs.
    if not normalized["web_services"]:
        host = str(normalized["host"])

        for item in normalized["services"]:
            service = item["service"]
            port = item["port"]

            if service == "https":
                normalized["web_services"].append(
                    f"https://{host}:{port}" if port and port != 443
                    else f"https://{host}"
                )

            elif service == "http":
                normalized["web_services"].append(
                    f"http://{host}:{port}" if port and port != 80
                    else f"http://{host}"
                )

    return normalized


# ============================================================
# Redirect analysis
# ============================================================

def get_redirect_chain(requested_url: str, response: requests.Response) -> List[str]:
    chain = [requested_url]

    for item in response.history:
        chain.append(item.url)

    if not chain or chain[-1] != response.url:
        chain.append(response.url)

    cleaned: List[str] = []

    for url in chain:
        if not cleaned or cleaned[-1] != url:
            cleaned.append(url)

    return cleaned


def check_http_to_https_redirect(
    requested_url: str,
    response: requests.Response,
) -> List[Dict[str, Any]]:
    if urlparse(requested_url).scheme != "http":
        return []

    if response.url.lower().startswith("https://"):
        return []

    return [
        make_finding(
            finding_type="Transport Security",
            name="HTTP to HTTPS Redirect",
            severity="Medium",
            title="No HTTP-to-HTTPS Redirect",
            description="The requested HTTP endpoint did not redirect to HTTPS.",
            risk=(
                "Users may continue communicating over unencrypted HTTP, "
                "which can expose traffic to interception or manipulation."
            ),
            recommendation=(
                "Redirect HTTP traffic to HTTPS and configure HSTS after "
                "HTTPS is correctly deployed."
            ),
            evidence=(
                f"Requested: {requested_url}\n"
                f"Final URL: {response.url}\n"
                f"Redirects observed: {len(response.history)}"
            ),
            url=response.url,
        )
    ]


# ============================================================
# Web security checks
# ============================================================

def check_security_headers(response: requests.Response) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    headers = response.headers

    for header_name, rule in SECURITY_HEADERS.items():
        if rule.get("report_when_missing") is False:
            continue

        value = headers.get(header_name)

        if not value:
            findings.append(
                make_finding(
                    finding_type="Security Header",
                    name=header_name,
                    severity=rule["missing_severity"],
                    confidence=rule.get("confidence", "High"),
                    category=rule.get("category", "Security Headers"),
                    classification=rule.get("classification", "Finding"),
                    risk_contribution=rule.get("risk_contribution"),
                    title=f"Missing {header_name}",
                    description=rule["description"],
                    risk=(
                        f"The {header_name} security control is not "
                        "explicitly configured."
                    ),
                    recommendation=rule["recommendation"],
                    evidence=f"{header_name} header is missing.",
                    url=response.url,
                )
            )

    return findings


def check_cors(response: requests.Response) -> List[Dict[str, Any]]:
    cors = response.headers.get("Access-Control-Allow-Origin")

    if not cors or cors.strip() != "*":
        return []

    return [
        make_finding(
            finding_type="Cross-Origin Configuration",
            name="Access-Control-Allow-Origin",
            severity="Medium",
            title="Wildcard CORS Policy",
            description="The server allows cross-origin requests from any origin.",
            risk=(
                "A wildcard CORS policy can expose resources to arbitrary "
                "web origins depending on what the application makes accessible."
            ),
            recommendation=(
                "Restrict Access-Control-Allow-Origin to trusted origins "
                "when cross-origin access is actually required."
            ),
            evidence="Access-Control-Allow-Origin: *",
            url=response.url,
        )
    ]


def check_csp_quality(response: requests.Response) -> List[Dict[str, Any]]:
    csp = response.headers.get("Content-Security-Policy")

    if not csp:
        return []

    csp_lower = csp.lower()
    weak_reasons: List[str] = []

    if re.search(r"(^|[\s;])default-src\s+\*", csp_lower):
        weak_reasons.append("default-src *")

    if "'unsafe-inline'" in csp_lower:
        weak_reasons.append("'unsafe-inline'")

    if "'unsafe-eval'" in csp_lower:
        weak_reasons.append("'unsafe-eval'")

    if not weak_reasons:
        return []

    return [
        make_finding(
            finding_type="Security Header Quality",
            name="Content-Security-Policy",
            severity="Medium",
            title="Weak Content-Security-Policy",
            description=(
                "The target has a CSP, but it contains permissive "
                "directives that reduce its protective value."
            ),
            risk=(
                "Overly broad CSP directives can reduce the protection "
                "CSP provides against injected or untrusted content."
            ),
            recommendation=(
                "Replace broad directives with a restrictive policy. "
                "Avoid unsafe-inline/unsafe-eval where possible and "
                "avoid wildcard sources unless strictly required."
            ),
            evidence=(
                f"Detected weak directives: {', '.join(weak_reasons)}\n"
                f"CSP: {csp}"
            ),
            url=response.url,
        )
    ]


def check_hsts_quality(response: requests.Response) -> List[Dict[str, Any]]:
    if not response.url.lower().startswith("https://"):
        return []

    hsts = response.headers.get("Strict-Transport-Security")

    if not hsts:
        return [
            make_finding(
                finding_type="Security Header",
                name="Strict-Transport-Security",
                severity="Medium",
                title="Missing Strict-Transport-Security",
                description="The HTTPS response does not define HSTS.",
                risk=(
                    "Browsers are not instructed to enforce HTTPS for "
                    "future connections to the host."
                ),
                recommendation=(
                    "Configure HSTS with an appropriate max-age after "
                    "confirming all relevant HTTPS endpoints are ready."
                ),
                evidence="Strict-Transport-Security header is missing.",
                url=response.url,
            )
        ]

    lower = hsts.lower()
    findings: List[Dict[str, Any]] = []

    max_age_match = re.search(r"max-age\s*=\s*(\d+)", lower)

    if not max_age_match:
        return [
            make_finding(
                finding_type="Security Header Quality",
                name="Strict-Transport-Security",
                severity="Medium",
                title="Invalid HSTS max-age",
                description=(
                    "The HSTS header exists but does not specify a valid max-age."
                ),
                risk="HSTS enforcement may not work as intended.",
                recommendation="Set a valid HSTS max-age value.",
                evidence=f"Strict-Transport-Security: {hsts}",
                url=response.url,
            )
        ]

    max_age = int(max_age_match.group(1))

    if max_age < 15768000:
        findings.append(
            make_finding(
                finding_type="Security Header Quality",
                name="Strict-Transport-Security",
                severity="Low",
                category="Security Headers",
                classification="Hardening",
                risk_contribution=0,
                title="Short HSTS max-age",
                description=f"HSTS max-age is only {max_age} seconds.",
                risk="A short HSTS lifetime provides less persistent HTTPS enforcement.",
                recommendation="Use a longer max-age appropriate for the deployment.",
                evidence=f"Strict-Transport-Security: {hsts}",
                url=response.url,
            )
        )

    if "includesubdomains" not in lower:
        findings.append(
            make_finding(
                finding_type="Security Header Quality",
                name="Strict-Transport-Security",
                severity="Low",
                category="Security Headers",
                classification="Hardening",
                risk_contribution=0,
                title="HSTS missing includeSubDomains",
                description="The HSTS policy does not include subdomains.",
                risk="Subdomains may not receive the same HSTS enforcement.",
                recommendation=(
                    "Consider includeSubDomains when all relevant "
                    "subdomains are HTTPS-ready."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
                url=response.url,
            )
        )

    # preload is deliberately informational/optional and is not reported
    # as a finding when absent.

    return findings


# ============================================================
# Cookie checks
# ============================================================

def get_set_cookie_headers(response: requests.Response) -> List[str]:
    raw_headers = getattr(response.raw, "headers", None)

    if raw_headers is not None:
        try:
            values = raw_headers.get_all("Set-Cookie")
            if values:
                return list(values)
        except (AttributeError, TypeError):
            pass

        try:
            values = raw_headers.getlist("Set-Cookie")
            if values:
                return list(values)
        except (AttributeError, TypeError):
            pass

    fallback = response.headers.get("Set-Cookie")

    if fallback:
        return [fallback]

    return []


def parse_cookie(cookie_header: str) -> Optional[tuple[str, Dict[str, Any]]]:
    parts = [part.strip() for part in cookie_header.split(";")]

    if not parts or "=" not in parts[0]:
        return None

    cookie_name = parts[0].split("=", 1)[0].strip()

    if not cookie_name:
        return None

    attributes: Dict[str, Any] = {}

    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[part.strip().lower()] = True

    return cookie_name, attributes


def classify_cookie(cookie_name: str) -> tuple[str, str]:
    """
    Classify cookie purpose from its name using conservative heuristics.

    The scanner cannot know server-side meaning from headers alone, so
    matched classifications get high confidence and unmatched cookies
    remain unknown with medium confidence.
    """
    normalized = cookie_name.strip().lower()

    if any(keyword in normalized for keyword in SESSION_COOKIE_KEYWORDS):
        return "Session/Auth", "High"

    if any(keyword in normalized for keyword in FUNCTIONAL_COOKIE_KEYWORDS):
        return "Functional", "High"

    if any(keyword in normalized for keyword in ANALYTICS_COOKIE_KEYWORDS):
        return "Analytics/Tracking", "High"

    return "Unknown", "Medium"


def cookie_flag_severity(cookie_type: str, flag: str) -> str:
    return COOKIE_SEVERITY_MATRIX.get(
        cookie_type,
        COOKIE_SEVERITY_MATRIX["Unknown"],
    )[flag]


def cookie_flag_classification(
    cookie_type: str,
    severity: str,
) -> str:
    if severity == "Info":
        return "Observation"

    if cookie_type == "Analytics/Tracking":
        return "Hardening"

    return "Finding"


def check_cookie_security(response: requests.Response) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cookies = get_set_cookie_headers(response)

    for raw_cookie in cookies:
        parsed = parse_cookie(raw_cookie)

        if not parsed:
            continue

        cookie_name, attributes = parsed
        cookie_type, confidence = classify_cookie(cookie_name)

        secure = "secure" in attributes
        httponly = "httponly" in attributes
        samesite = attributes.get("samesite")
        samesite_none_without_secure = (
            samesite is not None
            and str(samesite).lower() == "none"
            and not secure
        )

        if not secure and not samesite_none_without_secure:
            severity = cookie_flag_severity(cookie_type, "secure")
            findings.append(
                make_finding(
                    finding_type="Cookie Security",
                    name=cookie_name,
                    severity=severity,
                    confidence=confidence,
                    category="Cookie Security",
                    classification=cookie_flag_classification(
                        cookie_type,
                        severity,
                    ),
                    cookie_type=cookie_type,
                    title=f"{cookie_type} Cookie Missing Secure Flag",
                    description=(
                        f"The {cookie_type.lower()} cookie '{cookie_name}' "
                        "does not use Secure."
                    ),
                    risk=(
                        "The cookie may be sent over an unencrypted connection "
                        "when HTTP is reachable. Applicability depends on "
                        "the cookie purpose."
                    ),
                    recommendation=(
                        "Set Secure for cookies that should only be sent over HTTPS."
                    ),
                    evidence=f"Cookie '{cookie_name}': Secure flag missing.",
                    url=response.url,
                )
            )

        if not httponly:
            severity = cookie_flag_severity(cookie_type, "httponly")
            findings.append(
                make_finding(
                    finding_type="Cookie Security",
                    name=cookie_name,
                    severity=severity,
                    confidence=confidence,
                    category="Cookie Security",
                    classification=cookie_flag_classification(
                        cookie_type,
                        severity,
                    ),
                    cookie_type=cookie_type,
                    title=f"{cookie_type} Cookie Missing HttpOnly Flag",
                    description=(
                        f"The {cookie_type.lower()} cookie '{cookie_name}' "
                        "does not use HttpOnly."
                    ),
                    risk=(
                        "Client-side JavaScript may be able to access the cookie. "
                        "This is most sensitive for authentication or session "
                        "cookies and less applicable to analytics cookies."
                    ),
                    recommendation=(
                        "Use HttpOnly for cookies that do not need to be "
                        "accessible to client-side JavaScript."
                    ),
                    evidence=f"Cookie '{cookie_name}': HttpOnly flag missing.",
                    url=response.url,
                )
            )

        if samesite is None:
            severity = cookie_flag_severity(cookie_type, "samesite")
            findings.append(
                make_finding(
                    finding_type="Cookie Security",
                    name=cookie_name,
                    severity=severity,
                    confidence=confidence,
                    category="Cookie Security",
                    classification=cookie_flag_classification(
                        cookie_type,
                        severity,
                    ),
                    cookie_type=cookie_type,
                    title=f"{cookie_type} Cookie Missing SameSite",
                    description=(
                        f"The {cookie_type.lower()} cookie '{cookie_name}' "
                        "does not explicitly define SameSite."
                    ),
                    risk=(
                        "Cross-site cookie behavior is not explicitly "
                        "configured by the application. Applicability depends "
                        "on the cookie purpose."
                    ),
                    recommendation=(
                        "Set an appropriate SameSite value such as Lax or Strict."
                    ),
                    evidence=f"Cookie '{cookie_name}': SameSite missing.",
                    url=response.url,
                )
            )

        elif samesite_none_without_secure:
            findings.append(
                make_finding(
                    finding_type="Cookie Security",
                    name=cookie_name,
                    severity="High",
                    confidence="High",
                    category="Cookie Security",
                    classification="Finding",
                    cookie_type=cookie_type,
                    title="SameSite=None Without Secure",
                    description=(
                        f"The cookie '{cookie_name}' specifies SameSite=None "
                        "without Secure."
                    ),
                    risk=(
                        "SameSite=None is intended for cross-site contexts and "
                        "requires Secure in modern browser cookie handling."
                    ),
                    recommendation=(
                        "Use SameSite=None only when cross-site use is required "
                        "and add the Secure attribute."
                    ),
                    evidence=(
                        f"Cookie '{cookie_name}': SameSite=None, Secure missing."
                    ),
                    url=response.url,
                )
            )

    return findings


# ============================================================
# Information disclosure
# ============================================================

def has_version_disclosure(value: str) -> bool:
    return bool(re.search(r"/\d+(?:\.\d+)+", value))


def version_disclosure_severity(value: str) -> str:
    return "Medium" if has_version_disclosure(value) else "Info"


def technology_fingerprint_finding(
    *,
    header_name: str,
    value: str,
    url: str,
    version_title: str,
    generic_title: str,
) -> Dict[str, Any]:
    severity = version_disclosure_severity(value)
    versioned = severity == "Medium"

    return make_finding(
        finding_type="Information Disclosure",
        name=header_name,
        severity=severity,
        confidence="High",
        category="Technology Fingerprinting",
        classification="Finding" if versioned else "Observation",
        title=version_title if versioned else generic_title,
        description=(
            "The HTTP response reveals versioned technology information."
            if versioned
            else "The HTTP response reveals non-versioned technology information."
        ),
        risk=(
            "Versioned technology information can help attackers identify "
            "specific software flaws and target the application stack."
            if versioned
            else "This is useful for technology fingerprinting, but no "
            "specific software version is exposed."
        ),
        recommendation=(
            "Minimize unnecessary server software and version information."
            if versioned
            else "Treat this as an observation. Remove or minimize the header "
            "only when it is not required operationally."
        ),
        evidence=f"{header_name}: {value}",
        url=url,
    )


def check_information_disclosure(
    response: requests.Response,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    server = response.headers.get("Server")

    if server:
        findings.append(
            technology_fingerprint_finding(
                header_name="Server",
                value=server,
                url=response.url,
                version_title="Server Version Disclosure",
                generic_title="Server Technology Fingerprinting Observed",
            )
        )

    powered_by = response.headers.get("X-Powered-By")

    if powered_by:
        findings.append(
            technology_fingerprint_finding(
                header_name="X-Powered-By",
                value=powered_by,
                url=response.url,
                version_title="Technology Version Disclosure",
                generic_title="Technology Fingerprinting Observed",
            )
        )

    for header in (
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
    ):
        value = response.headers.get(header)

        if value:
            severity = version_disclosure_severity(value)
            versioned = severity == "Medium"
            findings.append(
                make_finding(
                    finding_type="Information Disclosure",
                    name=header,
                    severity=severity,
                    confidence="High",
                    category="Technology Fingerprinting",
                    classification="Finding" if versioned else "Observation",
                    title=(
                        f"{header} Version Disclosure"
                        if versioned
                        else f"{header} Technology Fingerprinting Observed"
                    ),
                    description=(
                        f"The response exposes technology information through {header}."
                    ),
                    risk=(
                        "Versioned technology information can help attackers "
                        "identify specific software flaws."
                        if versioned
                        else "This supports technology fingerprinting, but no "
                        "specific software version is exposed."
                    ),
                    recommendation=f"Remove or minimize {header} when not required.",
                    evidence=f"{header}: {value}",
                    url=response.url,
                )
            )

    return findings


# ============================================================
# Service configuration checks
# ============================================================

def check_service_security(
    recon: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Evaluate service exposure/configuration based on Recon results.

    This function intentionally does not perform its own port scan.
    """
    findings: List[Dict[str, Any]] = []

    for service_info in recon.get("services", []):
        service = service_info.get("service")
        port = service_info.get("port")
        version = service_info.get("version")

        if not service:
            continue

        rule = SERVICE_RULES.get(service)

        if not rule:
            continue

        severity = rule["severity"]

        evidence = f"Recon detected service: {service}"
        if port is not None:
            evidence += f" on port {port}"
        if version:
            evidence += f" (version: {version})"

        findings.append(
            make_finding(
                finding_type="Service Configuration",
                name=service.upper(),
                severity=severity,
                title=rule["title"],
                description=rule["description"],
                risk=rule["risk"],
                recommendation=rule["recommendation"],
                evidence=evidence,
                url=None,
                service=service,
                port=port,
            )
        )

    return findings


# ============================================================
# Web target selection
# ============================================================

def get_web_targets(
    target: str,
    recon: Dict[str, Any],
    recon_data_supplied: bool,
) -> List[str]:
    targets = list(recon.get("web_services", []))

    # If Recon explicitly exists and says there are no web services,
    # do not invent a web target from the main host.
    if recon_data_supplied:
        return targets

    # Standalone operation: treat target as a web target.
    return [normalize_target(target)]


# ============================================================
# Scan orchestration
# ============================================================

def scan_web_target(url: str) -> Dict[str, Any]:
    """
    Scan one HTTP(S) endpoint.

    Returns a sub-result so the parent module can continue if one
    web endpoint fails.
    """
    requested_url = normalize_target(url)

    request_result = request_with_retry(requested_url)

    sub_result = {
        "requested_url": requested_url,
        "final_url": None,
        "status_code": None,
        "redirect_chain": [],
        "findings": [],
        "errors": [],
    }

    if not request_result["success"]:
        sub_result["errors"].append(
            {
                "type": request_result["error_type"],
                "message": request_result["error_message"],
            }
        )
        return sub_result

    response = request_result["response"]

    sub_result["final_url"] = response.url
    sub_result["status_code"] = response.status_code
    sub_result["redirect_chain"] = get_redirect_chain(
        requested_url,
        response,
    )

    findings: List[Dict[str, Any]] = []

    findings.extend(check_http_to_https_redirect(requested_url, response))
    findings.extend(check_security_headers(response))
    findings.extend(check_csp_quality(response))
    findings.extend(check_hsts_quality(response))
    findings.extend(check_cookie_security(response))
    findings.extend(check_cors(response))
    findings.extend(check_information_disclosure(response))

    sub_result["findings"] = findings

    return sub_result


def calculate_risk_score(findings: Iterable[Dict[str, Any]]) -> int:
    score = 0.0

    for finding in findings:
        explicit_contribution = finding.get("risk_contribution")

        if explicit_contribution is not None:
            try:
                score += float(explicit_contribution)
            except (TypeError, ValueError):
                pass
            continue

        severity_weight = SEVERITY_WEIGHTS.get(finding.get("severity"), 0)
        confidence = finding.get("confidence", "High")
        confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(confidence, 1.0)

        try:
            applicability = float(finding.get("applicability", 1.0))
        except (TypeError, ValueError):
            applicability = 1.0

        score += severity_weight * confidence_multiplier * applicability

    return int(round(score))


def severity_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for finding in findings:
        severity = finding.get("severity")

        if severity in counts:
            counts[severity] += 1

    return counts


def classification_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "Finding": 0,
        "Hardening": 0,
        "Observation": 0,
    }

    for finding in findings:
        classification = finding.get("classification", "Finding")

        if classification in counts:
            counts[classification] += 1

    return counts


def deduplicate_findings(
    findings: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    deduplicated: List[Dict[str, Any]] = []
    seen = set()

    for finding in findings:
        key = (
            finding.get("module"),
            finding.get("type"),
            finding.get("name"),
            finding.get("title"),
            finding.get("severity"),
            finding.get("url"),
            finding.get("service"),
            finding.get("port"),
            finding.get("evidence"),
        )

        if key in seen:
            continue

        seen.add(key)
        deduplicated.append(finding)

    return deduplicated


def run_security_config_scan(
    target: str,
    recon_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Standard VulnScope integration entry point.

    Parameters
    ----------
    target:
        Target IP, hostname, or HTTP(S) URL.

    recon_data:
        Optional output from the Recon module. When supplied, Security
        Config uses it to select applicable service and web checks.

    Returns
    -------
    dict
        Standardized module result.
    """
    result = empty_result(
        target,
        recon_used=recon_data is not None,
    )

    try:
        recon = normalize_recon_data(target, recon_data)
    except Exception as error:
        result["status"] = "error"
        result["errors"].append(
            {
                "type": "Recon Data Error",
                "message": str(error),
            }
        )
        return result

    findings: List[Dict[str, Any]] = []

    # Service checks always use Recon context.
    if recon_data is not None:
        findings.extend(check_service_security(recon))

    result["services_checked"] = [
        {
            "service": item["service"],
            "port": item["port"],
            "version": item["version"],
        }
        for item in recon["services"]
        if item["service"] in SERVICE_RULES
    ]

    web_targets = get_web_targets(
        target,
        recon,
        recon_data is not None,
    )

    result["web_targets"] = web_targets

    # Web checks.
    for web_target in web_targets:
        try:
            web_result = scan_web_target(web_target)
        except Exception as error:
            web_result = {
                "requested_url": web_target,
                "final_url": None,
                "status_code": None,
                "redirect_chain": [],
                "findings": [],
                "errors": [
                    {
                        "type": "Web Scanner Error",
                        "message": str(error),
                    }
                ],
            }

        findings.extend(web_result["findings"])

        if web_result["errors"]:
            for error in web_result["errors"]:
                result["errors"].append(
                    {
                        "target": web_target,
                        **error,
                    }
                )

    findings = deduplicate_findings(findings)

    result["findings"] = findings
    result["risk_score"] = calculate_risk_score(findings)
    result["severity_counts"] = severity_counts(findings)
    result["classification_counts"] = classification_counts(findings)

    # No applicable check is a successful skip, not a scanner error.
    if not web_targets and not result["services_checked"]:
        result["status"] = "skipped"
    elif result["errors"] and not findings:
        result["status"] = "error"
    else:
        result["status"] = "success"

    return result


# Backward-compatible alias for standalone use.
def scan_target(target: str) -> Dict[str, Any]:
    return run_security_config_scan(target)


# ============================================================
# Reporting
# ============================================================

def print_redirect_chain(chain: List[str]) -> None:
    if not chain:
        return

    print("\nRedirect Chain:")

    for index, url in enumerate(chain):
        prefix = "  " if index == 0 else "  -> "
        print(f"{prefix}{url}")


def print_finding(finding: Dict[str, Any]) -> None:
    print("\n" + "-" * 78)
    print(
        f"[{finding['severity'].upper()}] "
        f"{finding['title']}"
    )

    if finding.get("service"):
        print(
            f"Service: {finding['service']} "
            f"Port: {finding.get('port', 'unknown')}"
        )

    print(f"Category: {finding.get('category', finding.get('type', ''))}")
    print(f"Classification: {finding.get('classification', 'Finding')}")
    print(f"Confidence: {finding.get('confidence', 'High')}")

    if finding.get("cookie_type"):
        print(f"Cookie Type: {finding['cookie_type']}")

    print("\nFinding:")
    print(finding["description"])

    print("\nDetected:")
    print(finding["evidence"])

    print("\nRisk:")
    print(finding["risk"])

    print("\nRecommendation:")
    print(finding["recommendation"])


def print_single_report(result: Dict[str, Any]) -> None:
    print("\n" + "=" * 78)
    print(f"{TOOL_NAME}")
    print("SECURITY CONFIGURATION MODULE")
    print("=" * 78)

    print(f"Version:       {result['version']}")
    print(f"Status:        {result['status']}")
    print(f"Scan Time UTC: {result['scan_started']}")
    print(f"Target:        {result['target']}")
    print(f"Recon Used:    {result['recon_used']}")

    if result["web_targets"]:
        print("\nWeb Targets:")
        for target in result["web_targets"]:
            print(f"  - {target}")

    if result["services_checked"]:
        print("\nServices Checked:")
        for service in result["services_checked"]:
            version = (
                f" ({service['version']})"
                if service.get("version")
                else ""
            )
            print(
                f"  - {service['service']}:{service.get('port', '?')}"
                f"{version}"
            )

    if result["errors"]:
        print("\nErrors:")
        for error in result["errors"]:
            target = (
                f" [{error['target']}]"
                if error.get("target")
                else ""
            )
            print(f"  - {error['type']}{target}: {error['message']}")

    print("\n" + "-" * 78)
    print("RISK SUMMARY")
    print("-" * 78)

    print(f"Risk Score: {result['risk_score']}")
    print(f"Critical:   {result['severity_counts']['Critical']}")
    print(f"High:       {result['severity_counts']['High']}")
    print(f"Medium:     {result['severity_counts']['Medium']}")
    print(f"Low:        {result['severity_counts']['Low']}")
    print(f"Info:       {result['severity_counts']['Info']}")
    print("")
    classification_summary = result.get(
        "classification_counts",
        classification_counts(result["findings"]),
    )
    print(f"Security Findings:          {classification_summary['Finding']}")
    print(f"Hardening Recommendations:  {classification_summary['Hardening']}")
    print(f"Observations:               {classification_summary['Observation']}")
    print(f"Total:                      {len(result['findings'])}")

    if not result["findings"]:
        print("\nNo findings detected.")
        print("=" * 78)
        return

    print("\n" + "=" * 78)
    print("FINDINGS")
    print("=" * 78)

    findings = sorted(
        result["findings"],
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity"), 0),
            CLASSIFICATION_ORDER.get(item.get("classification"), 0),
        ),
        reverse=True,
    )

    for finding in findings:
        print_finding(finding)

    print("\n" + "=" * 78)
    print("END OF REPORT")
    print("=" * 78)


# ============================================================
# JSON / CSV export
# ============================================================

def export_json(results: Any, filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)


def export_csv(results: List[Dict[str, Any]], filename: str) -> None:
    rows: List[Dict[str, Any]] = []

    fieldnames = [
        "module",
        "tool",
        "version",
        "status",
        "target",
        "scan_started",
        "risk_score",
        "finding_type",
        "name",
        "severity",
        "confidence",
        "category",
        "classification",
        "risk_contribution",
        "cookie_type",
        "title",
        "description",
        "risk",
        "recommendation",
        "evidence",
        "service",
        "port",
        "url",
    ]

    for result in results:
        if not result["findings"]:
            rows.append(
                {
                    "module": result["module"],
                    "tool": result["tool"],
                    "version": result["version"],
                    "status": result["status"],
                    "target": result["target"],
                    "scan_started": result["scan_started"],
                    "risk_score": result["risk_score"],
                    "finding_type": "",
                    "name": "",
                    "severity": "",
                    "confidence": "",
                    "category": "",
                    "classification": "",
                    "risk_contribution": "",
                    "cookie_type": "",
                    "title": "No findings",
                    "description": "",
                    "risk": "",
                    "recommendation": "",
                    "evidence": "",
                    "service": "",
                    "port": "",
                    "url": "",
                }
            )

        for finding in result["findings"]:
            rows.append(
                {
                    "module": result["module"],
                    "tool": result["tool"],
                    "version": result["version"],
                    "status": result["status"],
                    "target": result["target"],
                    "scan_started": result["scan_started"],
                    "risk_score": result["risk_score"],
                    "finding_type": finding.get("type", ""),
                    "name": finding.get("name", ""),
                    "severity": finding.get("severity", ""),
                    "confidence": finding.get("confidence", ""),
                    "category": finding.get("category", ""),
                    "classification": finding.get("classification", ""),
                    "risk_contribution": finding.get("risk_contribution", ""),
                    "cookie_type": finding.get("cookie_type", ""),
                    "title": finding.get("title", ""),
                    "description": finding.get("description", ""),
                    "risk": finding.get("risk", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "evidence": finding.get("evidence", ""),
                    "service": finding.get("service", ""),
                    "port": finding.get("port", ""),
                    "url": finding.get("url", ""),
                }
            )

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# Batch mode
# ============================================================

def load_targets(filename: str) -> List[str]:
    targets: List[str] = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            targets.append(line)

    return targets


def scan_batch(targets: Iterable[str]) -> List[Dict[str, Any]]:
    target_list = list(targets)
    results: List[Dict[str, Any]] = []

    for index, target in enumerate(target_list, start=1):
        print(f"\n[{index}/{len(target_list)}] Scanning: {target}")

        try:
            result = run_security_config_scan(target)
        except Exception as error:
            result = empty_result(target, status="error")
            result["errors"].append(
                {
                    "type": "Scanner Error",
                    "message": str(error),
                }
            )

        results.append(result)

        print(
            f"    Status: {result['status']} | "
            f"Risk Score: {result['risk_score']} | "
            f"Findings: {len(result['findings'])}"
        )

    return results


# ============================================================
# CLI
# ============================================================

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VulnScope Lite Security Configuration Scanner"
    )

    parser.add_argument(
        "--target",
        help="Single target URL, IP, or hostname.",
    )

    parser.add_argument(
        "--target-file",
        help="File containing one target per line.",
    )

    parser.add_argument(
        "--json",
        dest="json_file",
        help="Export results to JSON.",
    )

    parser.add_argument(
        "--csv",
        dest="csv_file",
        help="Export results to CSV.",
    )

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if not args.target and not args.target_file:
        parser.error("Specify either --target or --target-file.")

    requests.packages.urllib3.disable_warnings()

    results: List[Dict[str, Any]]

    if args.target_file:
        try:
            targets = load_targets(args.target_file)
        except OSError as error:
            print(f"[ERROR] Cannot read target file: {error}")
            sys.exit(1)

        if not targets:
            print("[ERROR] Target file contains no targets.")
            sys.exit(1)

        results = scan_batch(targets)

        print("\n" + "=" * 78)
        print("BATCH SUMMARY")
        print("=" * 78)

        for result in results:
            print(
                f"Target: {result['target']} | "
                f"Status: {result['status']} | "
                f"Risk: {result['risk_score']} | "
                f"Findings: {len(result['findings'])}"
            )

    else:
        try:
            results = [run_security_config_scan(args.target)]
        except ValueError as error:
            print(f"[ERROR] {error}")
            sys.exit(1)

        print_single_report(results[0])

    if args.json_file:
        export_json(results, args.json_file)
        print(f"\n[+] JSON report saved to: {args.json_file}")

    if args.csv_file:
        export_csv(results, args.csv_file)
        print(f"[+] CSV report saved to: {args.csv_file}")


if __name__ == "__main__":
    main()

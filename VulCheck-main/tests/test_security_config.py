import json

import modules.security_config as sc


class FakeRawHeaders:
    def __init__(self, values):
        self.values = values

    def get_all(self, name):
        if name.lower() == "set-cookie":
            return self.values
        return None


class FakeResponse:
    def __init__(self, headers=None, url="https://example.test"):
        self.headers = headers or {}
        self.url = url
        self.history = []
        self.raw = type("Raw", (), {"headers": FakeRawHeaders([])})()


def response_with_cookies(cookies):
    response = FakeResponse()
    response.raw = type(
        "Raw",
        (),
        {"headers": FakeRawHeaders(cookies)},
    )()
    return response


def test_standard_finding_contains_module():
    finding = sc.make_finding(
        "Test",
        "Example",
        "Low",
        "Example finding",
        "Description",
        "Risk",
        "Recommendation",
        "Evidence",
    )

    assert finding["module"] == "security_config"
    assert finding["severity"] == "Low"
    assert finding["confidence"] == "High"
    assert finding["classification"] == "Finding"


def test_missing_security_headers():
    response = FakeResponse()

    findings = sc.check_security_headers(response)

    names = {item["name"] for item in findings}

    assert "Content-Security-Policy" in names
    assert "X-Content-Type-Options" in names
    assert "X-Frame-Options" in names
    assert "X-XSS-Protection" not in names


def test_missing_permissions_policy_is_hardening_with_no_risk_contribution():
    response = FakeResponse(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
    )

    findings = sc.check_security_headers(response)

    assert len(findings) == 1
    assert findings[0]["name"] == "Permissions-Policy"
    assert findings[0]["classification"] == "Hardening"
    assert findings[0]["risk_contribution"] == 0
    assert sc.calculate_risk_score(findings) == 0


def test_weak_csp():
    response = FakeResponse(
        {
            "Content-Security-Policy": "default-src *; script-src 'unsafe-inline'"
        }
    )

    findings = sc.check_csp_quality(response)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert "unsafe-inline" in findings[0]["evidence"]


def test_hsts_quality():
    response = FakeResponse(
        {
            "Strict-Transport-Security": "max-age=1000"
        }
    )

    findings = sc.check_hsts_quality(response)

    titles = {item["title"] for item in findings}

    assert "Short HSTS max-age" in titles
    assert "HSTS missing includeSubDomains" in titles


def test_cookie_samesite_none_without_secure():
    response = response_with_cookies(
        ["session=abc; SameSite=None; HttpOnly"]
    )

    findings = sc.check_cookie_security(response)

    high = [
        item
        for item in findings
        if item["title"] == "SameSite=None Without Secure"
    ]

    assert len(high) == 1
    assert high[0]["severity"] == "High"


def test_cookie_classification_reduces_analytics_cookie_severity():
    response = response_with_cookies(["ATTRIBUTION_V1=abc"])

    findings = sc.check_cookie_security(response)

    by_title = {item["title"]: item for item in findings}

    assert by_title[
        "Analytics/Tracking Cookie Missing Secure Flag"
    ]["severity"] == "Low"
    assert by_title[
        "Analytics/Tracking Cookie Missing HttpOnly Flag"
    ]["severity"] == "Info"
    assert by_title[
        "Analytics/Tracking Cookie Missing SameSite"
    ]["severity"] == "Info"
    assert all(
        item["cookie_type"] == "Analytics/Tracking"
        for item in findings
    )


def test_cookie_classification_preserves_session_cookie_severity():
    response = response_with_cookies(["session=abc"])

    findings = sc.check_cookie_security(response)

    severities = {
        item["title"]: item["severity"]
        for item in findings
    }

    assert severities["Session/Auth Cookie Missing Secure Flag"] == "High"
    assert severities["Session/Auth Cookie Missing HttpOnly Flag"] == "High"
    assert severities["Session/Auth Cookie Missing SameSite"] == "Medium"


def test_wildcard_cors():
    response = FakeResponse(
        {
            "Access-Control-Allow-Origin": "*"
        }
    )

    findings = sc.check_cors(response)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"


def test_server_cloudflare_is_observation():
    response = FakeResponse({"Server": "cloudflare"})

    findings = sc.check_information_disclosure(response)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Info"
    assert findings[0]["classification"] == "Observation"
    assert findings[0]["title"] == "Server Technology Fingerprinting Observed"
    assert sc.calculate_risk_score(findings) == 0


def test_server_version_disclosure_stays_medium_finding():
    response = FakeResponse({"Server": "Apache/2.4.49"})

    findings = sc.check_information_disclosure(response)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["classification"] == "Finding"
    assert findings[0]["title"] == "Server Version Disclosure"


def test_recon_normalization():
    recon = {
        "host": "192.168.64.129",
        "open_ports": [21, 22, 23, 80, 445],
        "services": [
            {"port": 21, "service": "ftp"},
            {"port": 22, "service": "ssh"},
            {"port": 23, "service": "telnet"},
            {"port": 80, "service": "http"},
            {"port": 445, "service": "smb"},
        ],
        "web_services": ["http://192.168.64.129"],
    }

    normalized = sc.normalize_recon_data(
        "192.168.64.129",
        recon,
    )

    services = {
        item["service"]
        for item in normalized["services"]
    }

    assert "ftp" in services
    assert "ssh" in services
    assert "telnet" in services
    assert "smb" in services
    assert normalized["web_services"] == ["http://192.168.64.129"]


def test_service_checks():
    recon = sc.normalize_recon_data(
        "192.168.64.129",
        {
            "open_ports": [21, 23, 22, 445],
            "services": [
                {"port": 21, "service": "ftp"},
                {"port": 23, "service": "telnet"},
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "smb"},
            ],
        },
    )

    findings = sc.check_service_security(recon)

    names = {item["name"] for item in findings}

    assert "FTP" in names
    assert "TELNET" in names
    assert "SSH" in names
    assert "SMB" in names


def test_no_web_service_from_recon_means_web_checks_are_not_invented(monkeypatch):
    def fail_if_called(url):
        raise AssertionError("Web scan should not run")

    monkeypatch.setattr(sc, "scan_web_target", fail_if_called)

    result = sc.run_security_config_scan(
        "192.168.64.129",
        {
            "host": "192.168.64.129",
            "open_ports": [22],
            "services": [{"port": 22, "service": "ssh"}],
            "web_services": [],
        },
    )

    assert result["recon_used"] is True
    assert result["web_targets"] == []
    assert result["status"] == "success"
    assert any(
        finding["name"] == "SSH"
        for finding in result["findings"]
    )


def test_recon_without_applicable_checks_is_skipped():
    result = sc.run_security_config_scan(
        "192.168.64.129",
        {
            "host": "192.168.64.129",
            "open_ports": [9999],
            "services": [{"port": 9999, "service": "unknown"}],
            "web_services": [],
        },
    )

    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_risk_score():
    findings = [
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Info"},
    ]

    assert sc.calculate_risk_score(findings) == 12


def test_severity_counts():
    findings = [
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
    ]

    counts = sc.severity_counts(findings)

    assert counts["High"] == 2
    assert counts["Medium"] == 1
    assert counts["Low"] == 1

import unittest
from unittest.mock import Mock, patch

from modules.xss_scanner import run_xss_scan, scan_url


class FakeResponse:
    def __init__(self, text, url="http://lab.local/"):
        self.text = text
        self.url = url
        self.status_code = 200


class FakeSession:
    def get(self, url, **kwargs):
        if "q=VulnScopeXSS" in url:
            return FakeResponse(
                "<html><body>VulnScopeXSS</body></html>", url
            )
        return FakeResponse(
            '<html><form action="/search" method="get">'
            '<input name="q"></form></html>', url
        )

    def post(self, url, **kwargs):
        return FakeResponse(
            "<html><body>VulnScopeXSS</body></html>", url
        )


class TestXSSScanner(unittest.TestCase):

    def test_reflected_query_parameter(self):
        result = scan_url(
            "http://lab.local/?q=test",
            session=FakeSession()
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["module"], "xss")
        self.assertEqual(result["findings"][0]["location"], "query")

    def test_skipped_without_web_target(self):
        result = run_xss_scan(
            "192.168.64.129",
            recon_data={"web_services": []}
        )
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["findings"], [])

    def test_standard_schema(self):
        result = scan_url(
            "http://lab.local/",
            session=FakeSession()
        )
        for key in ("module", "target", "status", "findings", "errors"):
            self.assertIn(key, result)

    @patch("modules.xss_scanner.requests.Session")
    def test_recon_web_service_is_used(self, session_factory):
        session_factory.return_value = FakeSession()
        result = run_xss_scan(
            "192.168.64.129",
            recon_data={"web_services": ["http://lab.local/?q=test"]}
        )
        self.assertEqual(result["status"], "success")


if __name__ == "__main__":
    unittest.main()

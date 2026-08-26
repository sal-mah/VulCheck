"""
tests/test_sqli.py

Unit tests for modules/sqli_scanner.py using mocked HTTP responses
(no live target / no network needed).

Run with:
    python -m unittest tests/test_sqli.py -v
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.sqli_scanner import run_sqli_scanner, _has_web_service, _get_urls_with_params, _build_url


def fake_response(text="OK"):
    resp = MagicMock()
    resp.text = text
    return resp


class TestHelpers(unittest.TestCase):
    def test_has_web_service_false_without_recon_data(self):
        self.assertFalse(_has_web_service(None))
        self.assertFalse(_has_web_service({}))

    def test_has_web_service_true_with_urls(self):
        self.assertTrue(_has_web_service({"urls": ["http://x/page.php?id=1"]}))

    def test_get_urls_with_params_skips_urls_without_query(self):
        recon = {"urls": ["http://x/page.php?id=1", "http://x/no-params"]}
        self.assertEqual(_get_urls_with_params(recon), ["http://x/page.php?id=1"])

    def test_build_url_only_changes_target_param(self):
        url = _build_url("http://x/page.php?id=1&Submit=Submit", "id", "' OR '1'='1")
        self.assertIn("Submit=Submit", url)


class TestRunSqliScanner(unittest.TestCase):
    def test_skips_when_no_web_service(self):
        result = run_sqli_scanner("192.168.64.129", recon_data=None)
        self.assertEqual(result["module"], "sqli")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["findings"], [])

    def test_skips_when_no_parameterized_urls(self):
        recon = {"urls": ["http://192.168.64.129/index.html"]}
        result = run_sqli_scanner("192.168.64.129", recon_data=recon)
        self.assertEqual(result["status"], "skipped")

    @patch("modules.sqli_scanner.requests.Session.get")
    def test_detects_error_based_sqli(self, mock_get):
        def side_effect(url, timeout):
            if "%27" in url or "'" in url:
                return fake_response("You have an error in your SQL syntax near ...")
            return fake_response("Welcome to the site")

        mock_get.side_effect = side_effect
        recon = {"urls": ["http://192.168.64.129/page.php?id=1"]}
        result = run_sqli_scanner("192.168.64.129", recon_data=recon)

        self.assertEqual(result["status"], "success")
        names = [f["name"] for f in result["findings"]]
        self.assertIn("Error-Based SQL Injection", names)

    @patch("modules.sqli_scanner.requests.Session.get")
    def test_no_false_positive_on_clean_target(self, mock_get):
        mock_get.return_value = fake_response("Nothing interesting here")
        recon = {"urls": ["http://192.168.64.129/page.php?id=1"]}
        result = run_sqli_scanner("192.168.64.129", recon_data=recon)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["findings"], [])

    @patch("modules.sqli_scanner.requests.Session.get")
    def test_module_error_does_not_crash_scan(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")
        recon = {"urls": ["http://192.168.64.129/page.php?id=1"]}
        result = run_sqli_scanner("192.168.64.129", recon_data=recon)

        self.assertEqual(result["module"], "sqli")
        self.assertTrue(len(result["errors"]) >= 1)
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()

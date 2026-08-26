from core import scanner


def test_integrated_scan_runs_all_modules(monkeypatch):
    calls = []

    def fake_recon(target):
        calls.append("recon")
        return {
            "module": "recon",
            "target": target,
            "status": "success",
            "host": {"reachable": True, "os_clues": []},
            "ports": [80],
            "services": [{"port": 80, "service": "http"}],
            "web_services": [{"scheme": "http", "url": f"http://{target}"}],
            "http_results": [],
            "endpoints": [f"http://{target}/item.php?id=1"],
            "findings": [],
            "errors": [],
        }

    def fake_xss(target, recon_data=None):
        calls.append("xss")
        return {
            "module": "xss",
            "target": target,
            "status": "success",
            "findings": [],
            "errors": [],
        }

    def fake_sqli(target, recon_data=None):
        calls.append("sqli")
        assert recon_data["urls"] == [f"http://{target}/item.php?id=1", f"http://{target}"]
        return {
            "module": "sqli",
            "target": target,
            "status": "success",
            "findings": [
                {
                    "module": "sqli",
                    "type": "SQL Injection",
                    "name": "Error-Based SQL Injection",
                    "severity": "High",
                    "title": "SQLi",
                    "evidence": "mock",
                }
            ],
            "errors": [],
        }

    def fake_security_config(target, recon_data=None):
        calls.append("security_config")
        return {
            "module": "security_config",
            "target": target,
            "status": "success",
            "findings": [],
            "errors": [],
        }

    monkeypatch.setattr(scanner, "run_recon_scan", fake_recon)
    monkeypatch.setattr(scanner, "run_xss_scan", fake_xss)
    monkeypatch.setattr(scanner, "run_sqli_scanner", fake_sqli)
    monkeypatch.setattr(scanner, "run_security_config_scan", fake_security_config)

    report = scanner.run_integrated_scan("lab.local")

    assert calls == ["recon", "xss", "sqli", "security_config"]
    assert report["status"] == "success"
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["severity_counts"]["High"] == 1

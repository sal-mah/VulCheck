from pathlib import Path

from main import (
    _csv_rows,
    batch_report_output_path,
    report_output_path,
    target_report_name,
)


def test_target_report_name_uses_registered_domain_label():
    assert target_report_name("https://www.hackerone.com/") == "hackerone"
    assert target_report_name("https://api.hackerone.com/path") == "hackerone"


def test_report_output_path_uses_reports_directory():
    assert (
        report_output_path("https://www.hackerone.com/", "pdf")
        == Path("reports") / "hackerone_report.pdf"
    )


def test_batch_report_output_path_uses_target_file_name():
    assert (
        batch_report_output_path("targets.txt", "json")
        == Path("reports") / "targets_report.json"
    )


def test_csv_rows_maps_integrated_finding_type():
    report = {
        "tool": "Vulneraptor Lite",
        "integration_version": "2.1.0",
        "target": "https://www.hackerone.com/",
        "scan_started": "start",
        "scan_finished": "finish",
        "status": "success",
        "summary": {"total_findings": 1},
        "findings": [
            {
                "module": "xss",
                "type": "XSS",
                "name": "returnUrl",
                "severity": "High",
            }
        ],
        "ai": {
            "enabled": True,
            "status": "success",
            "model": "qwen3.5:4b",
        },
    }

    rows = _csv_rows(report)

    assert rows[0]["target"] == "https://www.hackerone.com/"
    assert rows[0]["module"] == "xss"
    assert rows[0]["finding_type"] == "XSS"
    assert rows[0]["severity"] == "High"

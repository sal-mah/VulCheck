from modules import recon


def test_detect_http_from_open_ports():
    services = recon.detect_http("lab.local", [80, 443])

    assert services == [
        {"scheme": "http", "url": "http://lab.local"},
        {"scheme": "https", "url": "https://lab.local"},
    ]


def test_invalid_target_returns_error(monkeypatch):
    monkeypatch.setattr(recon, "validate_target", lambda target: False)

    result = recon.run_recon_scan("not-a-target")

    assert result["module"] == "recon"
    assert result["status"] == "error"
    assert "Invalid target" in result["errors"]

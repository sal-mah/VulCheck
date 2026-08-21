# XSS Scanner README

## Purpose

Detect controlled reflected-XSS indicators in applicable authorized web
applications discovered by Recon.

## Installation

```bash
python -m pip install -r requirements.txt
```

## Run the module

```python
from modules.xss_scanner import run_xss_scan

result = run_xss_scan(
    "192.168.64.129",
    recon_data={
        "web_services": ["http://192.168.64.129/"]
    }
)

print(result)
```

## Test

```bash
python -m unittest discover -s tests -v
```

## Expected result shape

```json
{
  "module": "xss",
  "target": "http://example.local/",
  "status": "success",
  "findings": [],
  "errors": []
}
```

## Authorized lab use

Only scan systems you own or have explicit permission to assess.
Metasploitable 2 is an appropriate isolated lab target according to the
VulnScope Lite integration guide.

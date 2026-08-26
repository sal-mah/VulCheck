# XSS Module Interface

## Entry point

```python
run_xss_scan(target, recon_data=None)
```

## Status values

- `success`: module completed normally.
- `skipped`: no applicable web service was available.
- `error`: the module failed but the integration scan can continue.

## Finding fields

The XSS module returns the common VulnScope finding fields:

- module
- type
- name
- severity
- title
- description
- risk
- recommendation
- evidence
- url

It also adds:

- parameter
- location
- confidence

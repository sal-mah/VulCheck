# Vulneraptor Lite — XSS Scanner

## Scope

This module is Member 2's web-application scanner. It is intended for systems
owned by the team or explicitly authorized for security assessment.

## Input

The standard entry point is:

```python
run_xss_scan(target, recon_data=None)
```

`recon_data["web_services"]` should contain HTTP/HTTPS URLs discovered by Recon.
If no applicable web service is available, the module returns `status="skipped"`.

## Methodology

1. Receive web targets from Recon.
2. Request the target page.
3. Discover query-string parameters.
4. Discover HTML forms and their named fields.
5. Submit a controlled marker (`VulneraptorXSS`) to one input at a time.
6. Check whether the exact marker is reflected in the response body.
7. Return standardized evidence, severity, confidence and remediation fields.

The scanner does not attempt persistence, authentication bypass, data theft, or
destructive actions.

## Limitations

- Reflection alone is not a complete proof of exploitability.
- JavaScript execution is not performed by this module.
- Complex client-side DOM XSS is outside the current scope.
- Authentication/session workflows are not implemented.
- WAF behavior and context-specific encoding can require manual verification.
- Crawling is intentionally lightweight and same-origin only.

## Evidence

A finding records the tested URL, input name, input location, and a concise
description of where the controlled marker was reflected.

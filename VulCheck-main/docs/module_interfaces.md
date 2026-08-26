# Module Interfaces

Every scanner module returns the shared result shape:

```python
{
    "module": "module_name",
    "target": "authorized-target",
    "status": "success | skipped | error",
    "findings": [],
    "errors": [],
}
```

Current module entry points:

```python
modules.recon.run_recon_scan(target)
modules.xss_scanner.run_xss_scan(target, recon_data=None)
modules.sqli_scanner.run_sqli_scanner(target, recon_data=None)
modules.security_config.run_security_config_scan(target, recon_data=None)
```

Findings should include `module`, `type`, `name`, `severity`, `title`,
`description`, `risk`, `recommendation`, `evidence`, and optional context such
as `url`, `service`, `port`, or `parameter`.

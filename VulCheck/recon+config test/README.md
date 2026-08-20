# VulnScope Lite - Current Integration

Current execution order:

1. Recon
2. XSS (skipped until xss_scanner.py is added)
3. SQLi (skipped until sqli_scanner.py is added)
4. Security Configuration

Security Configuration receives the complete Recon result through:
`run_security_config_scan(target, recon_data=recon_data)`.

Run:
`python main.py 192.168.64.129`

JSON:
`python main.py 192.168.64.129 --json reports/scan.json`

Only scan systems you own or are explicitly authorized to assess.

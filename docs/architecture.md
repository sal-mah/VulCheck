# Architecture

Vulneraptor Lite is organized as a small package-based scanner.

```text
main.py                 CLI entry point
core/scanner.py         Integration orchestration
core/results.py         Shared result schema helpers
core/reporter.py        Terminal reporting
core/validators.py      Input validation helpers
modules/                Scanner implementations
config/                 Rules and scanner constants
tests/                  Unit and integration tests
reports/                Generated report output
```

The integration order is:

1. Recon
2. XSS
3. SQLi
4. Security Configuration

Recon runs first and supplies host, web-service, and endpoint context to the
web-focused scanners. The integration layer preserves Recon output and adds a
normalized `urls` list so SQLi can consume crawled parameterized endpoints.

"""
main.py (SQL-only snippet)

This is NOT the full team main.py — that's a shared/integration file your
team builds together (Recon runs first, then it decides which modules to
call, etc.). This is just the piece that shows how YOUR module plugs in,
so you can test it standalone or hand this snippet to whoever wires the
real main.py.

Usage:
    python main.py <target>
"""

import sys
from modules.sqli_scanner import run_sqli_scanner


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    # In the real pipeline, this recon_data comes from Recon's output.
    # For standalone testing of your module, fill in a URL you're
    # authorized to test against (must include a '?' with parameters).
    recon_data = {
        "urls": [f"http://{target}/page.php?id=1"],
    }

    result = run_sqli_scanner(target, recon_data)

    print(f"Module: {result['module']}")
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['findings'])}")
    for finding in result["findings"]:
        print(f"  [{finding['severity']}] {finding['title']}")
    for err in result["errors"]:
        print(f"  ! {err}")


if __name__ == "__main__":
    main()

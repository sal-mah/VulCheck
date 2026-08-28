from __future__ import annotations

import argparse
import csv
from contextlib import redirect_stdout
import ipaddress
from io import StringIO
import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from config.scanner_config import DEFAULT_REPORT_DIR
from core.reporter import print_integrated_report
from core.validators import require_target


# ============================================================
# Configuration
# ============================================================

DEPENDENCY_HINTS = {
    "nmap": "python-nmap",
    "bs4": "beautifulsoup4",
    "requests": "requests",
}

REPORT_FILENAME_TEMPLATE = "<target>_report"
DEFAULT_JSON_FILE = str(
    Path(DEFAULT_REPORT_DIR)
    / f"{REPORT_FILENAME_TEMPLATE}.json"
)
DEFAULT_CSV_FILE = str(
    Path(DEFAULT_REPORT_DIR)
    / f"{REPORT_FILENAME_TEMPLATE}.csv"
)
DEFAULT_PDF_FILE = str(
    Path(DEFAULT_REPORT_DIR)
    / f"{REPORT_FILENAME_TEMPLATE}.pdf"
)

COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "net",
    "org",
}


# ============================================================
# Target loading
# ============================================================

def load_targets(filename: str) -> list[str]:
    """Load targets from a text file.

    Empty lines and lines beginning with # are ignored.
    """
    targets: list[str] = []

    with open(filename, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            target = line.strip()

            if not target:
                continue

            if target.startswith("#"):
                continue

            targets.append(target)

    return targets


# ============================================================
# Report output paths
# ============================================================

def _target_hostname(target: str) -> str:
    """Return the host-like part of a target string."""

    candidate = target.strip()

    parsed = urlparse(candidate)

    if not parsed.netloc and "://" not in candidate:
        parsed = urlparse(
            f"//{candidate}",
            scheme="http",
        )

    if parsed.hostname:
        return parsed.hostname.lower()

    fallback = (
        candidate
        .split("/", 1)[0]
        .split("?", 1)[0]
        .split("#", 1)[0]
    )

    return fallback.lower()


def target_report_name(target: str) -> str:
    """Build a filesystem-safe report name from the target."""

    host = _target_hostname(target)

    if host.startswith("www."):
        host = host[4:]

    name = host

    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = [
            label
            for label in host.split(".")
            if label
        ]

        if len(labels) >= 2:
            name = labels[-2]

            if (
                len(labels) >= 3
                and name in COMMON_SECOND_LEVEL_SUFFIXES
            ):
                name = labels[-3]

        elif labels:
            name = labels[0]

    safe_name = re.sub(
        r"[^a-z0-9]+",
        "_",
        name.lower(),
    ).strip("_")

    return safe_name or "target"


def report_output_path(target: str, extension: str) -> Path:
    """Return reports/<target>_report.<extension>."""

    clean_extension = extension.lower().lstrip(".")

    return (
        Path(DEFAULT_REPORT_DIR)
        / f"{target_report_name(target)}_report.{clean_extension}"
    )


def batch_report_output_path(target_file: str, extension: str) -> Path:
    """Return a stable report path for --target-file exports."""

    stem = Path(target_file).stem or "batch"

    safe_stem = re.sub(
        r"[^a-z0-9]+",
        "_",
        stem.lower(),
    ).strip("_")

    clean_extension = extension.lower().lstrip(".")

    return (
        Path(DEFAULT_REPORT_DIR)
        / f"{safe_stem or 'batch'}_report.{clean_extension}"
    )


# ============================================================
# JSON export
# ============================================================

def save_json(data: Any, filename: str) -> Path:
    """Save scan results as JSON."""
    output_path = Path(filename)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    return output_path


# ============================================================
# CSV export
# ============================================================

CSV_FIELDNAMES = [
    "tool",
    "integration_version",
    "target",
    "scan_started",
    "scan_finished",
    "report_status",
    "total_findings",
    "module",
    "finding_type",
    "name",
    "title",
    "severity",
    "confidence",
    "category",
    "classification",
    "risk_contribution",
    "cookie_type",
    "parameter",
    "payload",
    "service",
    "port",
    "url",
    "description",
    "risk",
    "recommendation",
    "evidence",
    "ai_enabled",
    "ai_status",
    "ai_model",
]


def _csv_value(value: Any) -> str:
    """Convert CSV cell values without losing nested evidence."""

    if value is None:
        return ""

    if isinstance(value, (str, int, float, bool)):
        return str(value)

    return json.dumps(
        value,
        ensure_ascii=False,
        default=str,
    )


def _csv_rows(data: Any) -> list[dict[str, str]]:
    reports = data if isinstance(data, list) else [data]
    rows: list[dict[str, str]] = []

    for report in reports:
        if not isinstance(report, dict):
            continue

        summary = report.get("summary", {})
        ai = report.get("ai", {})
        findings = report.get("findings", [])

        base_row = {
            "tool": report.get("tool", ""),
            "integration_version": report.get(
                "integration_version",
                "",
            ),
            "target": report.get("target", ""),
            "scan_started": report.get(
                "scan_started",
                "",
            ),
            "scan_finished": report.get(
                "scan_finished",
                "",
            ),
            "report_status": report.get("status", ""),
            "total_findings": summary.get(
                "total_findings",
                len(findings),
            ),
            "ai_enabled": ai.get("enabled", ""),
            "ai_status": ai.get("status", ""),
            "ai_model": ai.get("model", ""),
        }

        if not findings:
            row = {
                fieldname: ""
                for fieldname in CSV_FIELDNAMES
            }
            row.update(
                {
                    key: _csv_value(value)
                    for key, value in base_row.items()
                }
            )
            row["title"] = "No findings"
            rows.append(row)
            continue

        for finding in findings:
            row = {
                fieldname: ""
                for fieldname in CSV_FIELDNAMES
            }

            row.update(
                {
                    key: _csv_value(value)
                    for key, value in base_row.items()
                }
            )

            if isinstance(finding, dict):
                for fieldname in CSV_FIELDNAMES:
                    if fieldname in row and fieldname in finding:
                        row[fieldname] = _csv_value(
                            finding[fieldname]
                        )

                row["finding_type"] = _csv_value(
                    finding.get(
                        "type",
                        finding.get("finding_type", ""),
                    )
                )

            rows.append(row)

    return rows


def save_csv(data: Any, filename: str) -> Path:
    """Save scan findings as CSV."""

    output_path = Path(filename)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDNAMES,
        )
        writer.writeheader()
        writer.writerows(
            _csv_rows(data)
        )

    return output_path


# ============================================================
# Text report rendering
# ============================================================

def render_report_text(data: Any) -> str:
    """Convert integrated scan results into printable report text."""

    reports = data if isinstance(data, list) else [data]

    sections: list[str] = []

    for index, report in enumerate(reports, start=1):
        buffer = StringIO()

        with redirect_stdout(buffer):
            if len(reports) > 1:
                print()
                print("=" * 78)
                print(
                    f"BATCH REPORT {index}/{len(reports)}"
                )
                print("=" * 78)

            print_integrated_report(report)

        sections.append(
            buffer.getvalue().strip()
        )

    if not sections:
        return "No report content.\n"

    return "\n\n".join(sections) + "\n"


# ============================================================
# PDF helpers
# ============================================================

def _escape_pdf_text(value: str) -> str:
    """Escape characters that have special meaning in PDF text."""

    return (
        value
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _pdf_safe_text(value: str) -> str:
    """Convert text to PDF-safe Latin-1 representation.

    Unsupported Unicode characters are replaced.
    """
    return (
        value
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


def _paginate_text(
    text: str,
    line_width: int,
    lines_per_page: int,
) -> list[list[str]]:
    """Wrap report text and split it into PDF pages."""

    wrapper = textwrap.TextWrapper(
        width=line_width,
        replace_whitespace=False,
        drop_whitespace=False,
        break_long_words=True,
        break_on_hyphens=False,
    )

    lines: list[str] = []

    for raw_line in text.splitlines():
        expanded = raw_line.expandtabs(4)

        if not expanded:
            lines.append("")
            continue

        wrapped = wrapper.wrap(expanded)

        if wrapped:
            lines.extend(wrapped)
        else:
            lines.append("")

    if not lines:
        lines = ["No report content."]

    return [
        lines[index:index + lines_per_page]
        for index in range(
            0,
            len(lines),
            lines_per_page,
        )
    ]


def _build_pdf_bytes(text: str) -> bytes:
    """Build a minimal text-based PDF."""

    page_width = 612
    page_height = 792

    margin = 36

    font_size = 9
    line_height = 12

    line_width = int(
        (page_width - (2 * margin))
        / (font_size * 0.6)
    )

    lines_per_page = int(
        (page_height - (2 * margin))
        / line_height
    )

    pages = _paginate_text(
        text,
        line_width,
        lines_per_page,
    )

    objects: list[bytes] = []

    # PDF object numbers:
    #
    # 1 = Catalog
    # 2 = Pages
    # 3 = Font
    # 4+ = Page/content pairs

    page_object_numbers = [
        4 + (page_index * 2)
        for page_index in range(len(pages))
    ]

    kids = " ".join(
        f"{number} 0 R"
        for number in page_object_numbers
    )

    # Catalog
    objects.append(
        b"<< /Type /Catalog /Pages 2 0 R >>"
    )

    # Pages
    objects.append(
        (
            f"<< /Type /Pages "
            f"/Kids [{kids}] "
            f"/Count {len(pages)} >>"
        ).encode("ascii")
    )

    # Font
    objects.append(
        b"<< /Type /Font "
        b"/Subtype /Type1 "
        b"/BaseFont /Courier >>"
    )

    # Pages + content streams
    for page_index, lines in enumerate(pages):
        page_object_number = 4 + (page_index * 2)
        content_object_number = page_object_number + 1

        page_object = (
            f"<< /Type /Page "
            f"/Parent 2 0 R "
            f"/MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << "
            f"/Font << /F1 3 0 R >> "
            f">> "
            f"/Contents {content_object_number} 0 R >>"
        )

        objects.append(
            page_object.encode("ascii")
        )

        commands = [
            "BT",
            f"/F1 {font_size} Tf",
            f"{line_height} TL",
            f"{margin} {page_height - margin} Td",
        ]

        for line in lines:
            safe_line = _escape_pdf_text(
                _pdf_safe_text(line)
            )

            commands.append(
                f"({safe_line}) Tj"
            )

            commands.append("T*")

        commands.append("ET")

        stream = "\n".join(commands).encode(
            "latin-1",
            "replace",
        )

        stream_object = (
            f"<< /Length {len(stream)} >>\n"
            .encode("ascii")
            + b"stream\n"
            + stream
            + b"\nendstream"
        )

        objects.append(stream_object)

    # Build PDF
    pdf = bytearray(
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    )

    offsets = [0]

    for index, obj in enumerate(
        objects,
        start=1,
    ):
        offsets.append(len(pdf))

        pdf.extend(
            f"{index} 0 obj\n".encode("ascii")
        )

        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    startxref = len(pdf)

    pdf.extend(
        f"xref\n0 {len(objects) + 1}\n"
        .encode("ascii")
    )

    pdf.extend(
        b"0000000000 65535 f \n"
    )

    for offset in offsets[1:]:
        pdf.extend(
            f"{offset:010d} 00000 n \n"
            .encode("ascii")
        )

    pdf.extend(
        (
            f"trailer\n"
            f"<< /Size {len(objects) + 1} "
            f"/Root 1 0 R >>\n"
            f"startxref\n"
            f"{startxref}\n"
            f"%%EOF\n"
        ).encode("ascii")
    )

    return bytes(pdf)


def save_pdf(data: Any, filename: str) -> Path:
    """Save scan report as PDF."""

    output_path = Path(filename)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_text = render_report_text(data)

    output_path.write_bytes(
        _build_pdf_bytes(report_text)
    )

    return output_path


# ============================================================
# Argument parser
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Vulneraptor Lite integrated "
            "vulnerability scanner"
        )
    )

    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Authorized target IP, hostname, "
            "or HTTP(S) URL."
        ),
    )

    parser.add_argument(
        "--target-file",
        help=(
            "File containing one authorized "
            "target per line."
        ),
    )

    parser.add_argument(
        "--json",
        dest="json_file",
        nargs="?",
        const=DEFAULT_JSON_FILE,
        metavar="JSON_FILE",
        help=(
            "Save report JSON as "
            f"{DEFAULT_JSON_FILE}. "
            "Legacy filename arguments are accepted."
        ),
    )

    parser.add_argument(
        "--csv",
        dest="csv_file",
        nargs="?",
        const=DEFAULT_CSV_FILE,
        metavar="CSV_FILE",
        help=(
            "Save report CSV as "
            f"{DEFAULT_CSV_FILE}. "
            "Legacy filename arguments are accepted."
        ),
    )

    parser.add_argument(
        "--pdf",
        dest="pdf_file",
        nargs="?",
        const=DEFAULT_PDF_FILE,
        metavar="PDF_FILE",
        help=(
            "Save report PDF as "
            f"{DEFAULT_PDF_FILE}. "
            "Legacy filename arguments are accepted."
        ),
    )

    parser.add_argument(
        "--ai",
        action="store_true",
        help=(
            "Analyze the completed scan "
            "locally with Ollama."
        ),
    )

    parser.add_argument(
        "--ai-model",
        default="qwen3.5:4b",
        help=(
            "Local Ollama model to use "
            "(default: qwen3.5:4b)."
        ),
    )

    parser.add_argument(
        "--ai-url",
        default="http://127.0.0.1:11434",
        help=(
            "Ollama API base URL "
            "(default: http://127.0.0.1:11434)."
        ),
    )

    return parser


# ============================================================
# Scanner loading
# ============================================================

def load_integrated_scanner():
    """Import the integrated scanner and provide useful errors."""

    try:
        from core.scanner import run_integrated_scan

    except ModuleNotFoundError as error:
        missing_module = error.name or "unknown"

        package_name = DEPENDENCY_HINTS.get(
            missing_module,
            missing_module,
        )

        print(
            "[ERROR] Missing required Python package: "
            f"{package_name}",
            file=sys.stderr,
        )

        print(
            "Install project dependencies with:",
            file=sys.stderr,
        )

        print(
            "python -m pip install -r requirements.txt",
            file=sys.stderr,
        )

        if missing_module == "nmap":
            print(
                "Recon also requires the Nmap application "
                "to be installed and available in PATH.",
                file=sys.stderr,
            )

        raise SystemExit(1)

    except ImportError as error:
        print(
            "[ERROR] Failed to import the integrated scanner:",
            file=sys.stderr,
        )

        print(
            str(error),
            file=sys.stderr,
        )

        raise SystemExit(1)

    return run_integrated_scan


# ============================================================
# Requests warnings
# ============================================================

def disable_request_warnings() -> None:
    """Disable urllib3 certificate warnings.

    The scanner currently uses verify=False for HTTPS requests.
    """

    try:
        import requests
    except ModuleNotFoundError:
        return

    requests.packages.urllib3.disable_warnings()


# ============================================================
# Scanner wrapper
# ============================================================

def run_scan(
    run_integrated_scan,
    target: str,
    *,
    ai_enabled: bool,
    ai_model: str,
    ai_url: str,
) -> dict[str, Any]:
    """Validate and execute one scan safely."""

    try:
        validated_target = require_target(
            target.strip()
        )

        return run_integrated_scan(
            validated_target,
            ai_enabled=ai_enabled,
            ai_model=ai_model,
            ai_url=ai_url,
        )

    except Exception as error:
        print(
            f"[ERROR] Scan failed for {target}: {error}",
            file=sys.stderr,
        )

        return {
            "target": target,
            "status": "error",
            "error": str(error),
            "findings": [],
        }


# ============================================================
# Main
# ============================================================

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # --------------------------------------------------------
    # Validate argument combinations
    # --------------------------------------------------------

    if args.target and args.target_file:
        parser.error(
            "Use either TARGET or --target-file, not both."
        )

    # --------------------------------------------------------
    # Setup
    # --------------------------------------------------------

    disable_request_warnings()

    run_integrated_scan = load_integrated_scanner()

    # --------------------------------------------------------
    # Batch scan
    # --------------------------------------------------------

    if args.target_file:

        try:
            targets = load_targets(
                args.target_file
            )

        except OSError as error:
            print(
                f"[ERROR] Cannot read target file: {error}",
                file=sys.stderr,
            )
            raise SystemExit(1)

        if not targets:
            print(
                "[ERROR] Target file contains no targets.",
                file=sys.stderr,
            )
            raise SystemExit(1)

        reports: list[dict[str, Any]] = []

        total = len(targets)

        for index, target in enumerate(
            targets,
            start=1,
        ):
            print()
            print(
                f"[{index}/{total}] Scanning: {target}"
            )

            report = run_scan(
                run_integrated_scan,
                target,
                ai_enabled=args.ai,
                ai_model=args.ai_model,
                ai_url=args.ai_url,
            )

            print_integrated_report(report)

            reports.append(report)

        # ----------------------------------------------------
        # Batch exports
        # ----------------------------------------------------

        if args.json_file:
            output_path = save_json(
                reports,
                batch_report_output_path(
                    args.target_file,
                    "json",
                ),
            )

            print(
                f"\n[+] JSON reports saved to: "
                f"{output_path}"
            )

        if args.csv_file:
            output_path = save_csv(
                reports,
                batch_report_output_path(
                    args.target_file,
                    "csv",
                ),
            )

            print(
                f"\n[+] CSV reports saved to: "
                f"{output_path}"
            )

        if args.pdf_file:
            output_path = save_pdf(
                reports,
                batch_report_output_path(
                    args.target_file,
                    "pdf",
                ),
            )

            print(
                f"\n[+] PDF reports saved to: "
                f"{output_path}"
            )

        return

    # --------------------------------------------------------
    # Single target
    # --------------------------------------------------------

    target = args.target

    if not target:
        if not sys.stdin.isatty():
            parser.error(
                "Specify TARGET or --target-file."
            )

        try:
            target = input(
                "Enter target IP, domain, or URL: "
            ).strip()

        except (EOFError, KeyboardInterrupt):
            print(
                "\n[ERROR] No target supplied.",
                file=sys.stderr,
            )
            raise SystemExit(1)

    if not target:
        parser.error(
            "Target cannot be empty."
        )

    report = run_scan(
        run_integrated_scan,
        target,
        ai_enabled=args.ai,
        ai_model=args.ai_model,
        ai_url=args.ai_url,
    )

    print_integrated_report(report)

    # --------------------------------------------------------
    # Single-target exports
    # --------------------------------------------------------

    if args.json_file:
        output_path = save_json(
            report,
            report_output_path(
                report.get("target", target),
                "json",
            ),
        )

        print(
            f"\n[+] JSON report saved to: "
            f"{output_path}"
        )

    if args.csv_file:
        output_path = save_csv(
            report,
            report_output_path(
                report.get("target", target),
                "csv",
            ),
        )

        print(
            f"\n[+] CSV report saved to: "
            f"{output_path}"
        )

    if args.pdf_file:
        output_path = save_pdf(
            report,
            report_output_path(
                report.get("target", target),
                "pdf",
            ),
        )

        print(
            f"\n[+] PDF report saved to: "
            f"{output_path}"
        )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()

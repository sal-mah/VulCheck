from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
CLASSIFICATIONS = ("Finding", "Hardening", "Observation")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def skipped_module(module_name: str, target: str, reason: str) -> dict[str, Any]:
    return {
        "module": module_name,
        "target": target,
        "status": "skipped",
        "findings": [],
        "errors": [],
        "reason": reason,
    }


def scanner_error(module_name: str, target: str, error: BaseException) -> dict[str, Any]:
    return {
        "module": module_name,
        "target": target,
        "status": "error",
        "findings": [],
        "errors": [
            {
                "type": "Scanner Error",
                "message": str(error),
            }
        ],
    }


def ensure_module_result(
    module_name: str,
    target: str,
    result: Any,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        return scanner_error(
            module_name,
            target,
            TypeError(f"{module_name} returned {type(result).__name__}"),
        )

    result.setdefault("module", module_name)
    result.setdefault("target", target)
    result.setdefault("status", "success")
    result.setdefault("findings", [])
    result.setdefault("errors", [])
    return result


def aggregate_findings(
    module_results: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for result in module_results.values():
        for finding in result.get("findings", []):
            if isinstance(finding, dict):
                findings.append(finding)

    return findings


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in SEVERITIES}
    classification_counts = {
        classification: 0 for classification in CLASSIFICATIONS
    }

    for finding in findings:
        severity = finding.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

        classification = finding.get("classification", "Finding")
        if classification in classification_counts:
            classification_counts[classification] += 1

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "classification_counts": classification_counts,
    }


def _url_from_item(item: Any) -> str | None:
    if isinstance(item, str):
        value = item.strip()
    elif isinstance(item, dict):
        value = str(
            item.get("url")
            or item.get("target")
            or item.get("endpoint")
            or ""
        ).strip()
    else:
        return None

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value

    return None


def _extend_urls(urls: list[str], values: Any) -> None:
    if not values:
        return

    if not isinstance(values, (list, tuple, set)):
        values = [values]

    for item in values:
        url = _url_from_item(item)
        if url and url not in urls:
            urls.append(url)


def enrich_recon_for_web_scanners(
    recon_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Give web scanners one normalized URL list while preserving Recon data.

    Recon stores discovered links in ``endpoints``. The SQLi scanner expects
    parameterized candidates in ``urls``, so the integration layer bridges the
    two schemas here instead of making Recon know about every consumer.
    """
    enriched = deepcopy(recon_data)
    urls: list[str] = []

    _extend_urls(urls, enriched.get("urls"))
    _extend_urls(urls, enriched.get("endpoints"))
    _extend_urls(urls, enriched.get("web_services"))
    _extend_urls(urls, enriched.get("http_results"))

    enriched["urls"] = urls
    return enriched

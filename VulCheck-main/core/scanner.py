from __future__ import annotations

from typing import Any, Callable

from config.scanner_config import (
    EXECUTION_ORDER,
    INTEGRATION_VERSION,
    TOOL_NAME,
)

from core.results import (
    aggregate_findings,
    build_summary,
    enrich_recon_for_web_scanners,
    ensure_module_result,
    now_iso,
    scanner_error,
)

from modules.recon import run_recon_scan
from modules.security_config import run_security_config_scan
from modules.sqli_scanner import run_sqli_scanner
from modules.xss_scanner import run_xss_scan

from modules.ollama_analyzer import (
    analyze_results,
    check_ollama,
)


ScannerCallable = Callable[..., dict[str, Any]]


def _run_safely(
    module_name: str,
    target: str,
    scanner: ScannerCallable,
    *args: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run one scanner module without crashing the entire scan."""

    try:
        return ensure_module_result(
            module_name,
            target,
            scanner(*args, **kwargs),
        )

    except Exception as error:
        return scanner_error(
            module_name,
            target,
            error,
        )


def run_integrated_scan(
    target: str,
    ai_enabled: bool = False,
    ai_model: str = "qwen3.5:4b",
    ai_url: str = "http://127.0.0.1:11434",
) -> dict[str, Any]:

    # ========================================================
    # 1. Start scan
    # ========================================================

    started = now_iso()

    modules: dict[str, dict[str, Any]] = {}

    # ========================================================
    # 2. Recon
    # ========================================================

    recon_result = _run_safely(
        "recon",
        target,
        run_recon_scan,
        target,
    )

    modules["recon"] = recon_result

    # ========================================================
    # 3. Prepare Recon data for web scanners
    # ========================================================

    web_recon = enrich_recon_for_web_scanners(
        recon_result
    )

    # ========================================================
    # 4. XSS Scanner
    # ========================================================

    modules["xss"] = _run_safely(
        "xss",
        target,
        run_xss_scan,
        target,
        recon_data=web_recon,
    )

    # ========================================================
    # 5. SQL Injection Scanner
    # ========================================================

    modules["sqli"] = _run_safely(
        "sqli",
        target,
        run_sqli_scanner,
        target,
        recon_data=web_recon,
    )

    # ========================================================
    # 6. Security Configuration Scanner
    # ========================================================

    modules["security_config"] = _run_safely(
        "security_config",
        target,
        run_security_config_scan,
        target,
        recon_data=recon_result,
    )

    # ========================================================
    # 7. Aggregate findings
    # ========================================================

    findings = aggregate_findings(
        modules
    )

    summary = build_summary(
        findings
    )

    # ========================================================
    # 8. Determine overall scan status
    # ========================================================

    status = "success"

    if any(
        result.get("status") == "error"
        for result in modules.values()
    ):
        status = "partial/error"

    # ========================================================
    # 9. Build report BEFORE AI
    # ========================================================

    report: dict[str, Any] = {
        "tool": TOOL_NAME,
        "integration_version": INTEGRATION_VERSION,
        "target": target,
        "scan_started": started,
        "scan_finished": now_iso(),
        "status": status,
        "execution_order": EXECUTION_ORDER,
        "modules": modules,
        "summary": summary,
        "findings": findings,

        "ai": {
            "enabled": ai_enabled,
            "status": (
                "requested"
                if ai_enabled
                else "not_requested"
            ),
            "model": ai_model,
            "base_url": ai_url,
            "analysis": "",
            "error": None,
        },
    }

    # ========================================================
    # 10. Ollama AI Analysis
    # ========================================================

    if ai_enabled:

        print()
        print("=" * 78)
        print("OLLAMA LOCAL AI ANALYSIS")
        print("=" * 78)
        print(f"Model: {ai_model}")
        print(f"API:   {ai_url}")
        print()

        # ----------------------------------------------------
        # Check whether Ollama is reachable
        # ----------------------------------------------------

        try:
            ollama_available = check_ollama(
                ai_url
            )

        except Exception as error:
            ollama_available = False

            report["ai"]["error"] = (
                f"Failed to check Ollama: {error}"
            )

        # ----------------------------------------------------
        # Ollama unavailable
        # ----------------------------------------------------

        if not ollama_available:

            report["ai"]["status"] = "error"

            if not report["ai"]["error"]:
                report["ai"]["error"] = (
                    "Ollama is not reachable at "
                    f"{ai_url}. "
                    "Start Ollama and try again."
                )

            print(
                "[ERROR] "
                + report["ai"]["error"]
            )

        # ----------------------------------------------------
        # Ollama available
        # ----------------------------------------------------

        else:

            print(
                "[+] Ollama is reachable."
            )

            print(
                f"[+] Sending scan results to "
                f"{ai_model}..."
            )

            try:

                ai_result = analyze_results(
                    report,
                    model=ai_model,
                    base_url=ai_url,
                )

                report["ai"] = {
                    "enabled": True,
                    **ai_result,
                }

                print(
                    f"[+] AI analysis status: "
                    f"{report['ai'].get('status', 'unknown')}"
                )

            except Exception as error:

                report["ai"]["status"] = "error"

                report["ai"]["error"] = (
                    f"AI analysis failed: {error}"
                )

                print(
                    f"[ERROR] "
                    f"{report['ai']['error']}"
                )

    # ========================================================
    # 11. Return final report
    # ========================================================

    return report
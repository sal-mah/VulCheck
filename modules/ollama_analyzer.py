from __future__ import annotations

import json
from typing import Any

import requests


DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3.5:4b"


def check_ollama(base_url: str = DEFAULT_OLLAMA_URL, timeout: int = 10) -> bool:
    """Return True when the local Ollama API is reachable."""
    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/api/tags",
            timeout=timeout,
        )
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False


def list_models(
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout: int = 10,
) -> list[str]:
    """Return locally available Ollama model names."""
    response = requests.get(
        f"{base_url.rstrip('/')}/api/tags",
        timeout=timeout,
    )
    response.raise_for_status()

    data = response.json()
    models = data.get("models", [])

    return [
        str(item.get("name"))
        for item in models
        if isinstance(item, dict) and item.get("name")
    ]


def analyze_results(
    scan_report: dict[str, Any],
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout: int = 180,
) -> dict[str, Any]:
    """
    Analyze an already completed Vulneraptor report.

    Ollama is deliberately kept outside the scanning logic:
    it receives evidence produced by the deterministic modules and
    does not perform network scanning or vulnerability testing.
    """

    prompt = f"""
 You are the local AI security analyst for Vulneraptor Lite.
 
 Analyze ONLY the security evidence contained in the JSON below.
 
 Rules:
 - Do not invent vulnerabilities, ports, services, endpoints, or evidence.
 - Do not treat a skipped or failed module as a clean result.
 - Clearly distinguish confirmed findings, hardening recommendations,
   observations, and areas that were not assessed.
 - Explain why important findings matter.
 - Prioritize remediation by severity and practical impact.
 - Keep the report technically accurate and concise.
 - Do not perform or recommend unauthorized testing.
 
 Return a professional report with these sections:
 
 1. Executive Summary
 2. Target and Reconnaissance Analysis
 3. XSS Analysis
 4. SQL Injection Analysis
 5. Security Configuration Analysis
 6. Risk Assessment
 7. Prioritized Remediation
 8. ways to hack the system
 9.tools to use to hack the system 
 10.if it is possible to hack the system or not
 11.if it contani cve or not if it contain cve then mention the cve number and the description of the cve
 12. Coverage and Limitations
 13. Overall Conclusion
 14. References
 15. Appendices
 16. Additional Notes
 17. Additional Recommendations
 18. Additional Observations
 19. Additional Findings
 
 Vulneraptor REPORT:
 {json.dumps(scan_report, indent=2, ensure_ascii=False, default=str)}
"""

    payload = {
        "model": model,
        "system": (
            "You are a defensive security report analyst. "
            "Use only supplied scanner evidence."
        ),
        "prompt": prompt,
        "stream": False,
        # Qwen3.5 supports thinking; disabling it here makes the
        # integration return the actual report in the response field.
        "think": True,
        "options": {
            "temperature": 0.1,
            "num_ctx": 18384,
        },
    }

    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/generate",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()

        data = response.json()

        # /api/generate normally returns "response". Some Ollama
        # configurations/models can expose content through a message
        # object instead, so support both forms.
        analysis = data.get("response") or ""

        if not analysis:
            message = data.get("message") or {}
            if isinstance(message, dict):
                analysis = message.get("content") or ""

        # If thinking was returned separately and no final content
        # exists, keep the diagnostic text instead of reporting a
        # misleading empty result.
        if not analysis:
            analysis = data.get("thinking") or ""

        if not analysis:
            return {
                "status": "error",
                "model": model,
                "base_url": base_url,
                "analysis": "",
                "error": (
                    "Ollama returned HTTP 200 but no text in "
                    "'response', 'message.content', or 'thinking'. "
                    f"Raw keys: {list(data.keys())}"
                ),
            }

        return {
            "status": "success",
            "model": model,
            "base_url": base_url,
            "analysis": analysis,
            "error": None,
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "model": model,
            "base_url": base_url,
            "analysis": "",
            "error": str(error),
        }

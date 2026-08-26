from __future__ import annotations


def require_target(target: str | None) -> str:
    if target is None:
        raise ValueError("Target cannot be empty.")

    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty.")

    return cleaned

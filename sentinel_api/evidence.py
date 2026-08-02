"""Evidence helpers."""
from __future__ import annotations


def normalize_confidence(value: str) -> str:
    value = (value or "").strip().lower()
    if value in {"low", "medium", "high"}:
        return value
    return "medium"

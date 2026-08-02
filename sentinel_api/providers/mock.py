"""Deterministic provider for testing without a real LLM.

The basic analyzer is heuristic-driven, so the mock only needs to return a
short natural-language endpoint summary. It echoes the method/path it sees.
"""
import re

from sentinel_api.providers.base import LLMProvider


class MockProvider(LLMProvider):
    def complete(self, prompt: str) -> str:
        method = _find(prompt, r"method:\s*(\S+)")
        path = _find(prompt, r"path:\s*(\S+)")
        if method and path:
            return f"This endpoint appears to handle a {method} request to {path}."
        return "This endpoint could not be summarized (mock provider)."

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        question = user_prompt.strip().splitlines()
        if question:
            q = question[-1].strip()
            if q:
                return f"[mock] Sentinel chat is enabled. Question received: {q}"
        return "[mock] Sentinel chat is enabled, but no question text was provided."


def _find(text: str, pattern: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else ""

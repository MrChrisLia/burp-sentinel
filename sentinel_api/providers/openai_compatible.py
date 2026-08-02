"""OpenAI-compatible chat completions provider.

Works with any backend exposing a /chat/completions-style API, including many
local model gateways and agent runtimes.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from sentinel_api.config import settings
from sentinel_api.providers.base import LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self) -> None:
        self.base_url = (settings.base_url or "").strip().rstrip("/")
        self.model = (settings.model or "").strip()
        self.api_key = (settings.api_key or "").strip()
        self.timeout = 75.0

    def complete(self, prompt: str) -> str:
        return self.chat(
            "You summarize web security endpoint behavior in one concise sentence.",
            prompt,
        )

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        if not self.base_url or not self.model:
            return (
                "LLM summary unavailable: configure SENTINEL_BASE_URL and SENTINEL_MODEL "
                "for openai_compatible provider."
            )
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        errors: list[str] = []
        for url in self._chat_urls():
            try:
                response = self._post_json(url, payload)
                text = _extract_message_text(response)
                if text:
                    return text.strip()
                return "LLM summary unavailable: empty response content from provider."
            except Exception as exc:
                errors.append(f"{url}: {exc}")
        return "LLM summary unavailable: provider call failed (" + " | ".join(errors) + ")."

    def _chat_urls(self) -> list[str]:
        # Accept either a full endpoint or a base URL and probe common variants.
        if self.base_url.endswith("/chat/completions"):
            return [self.base_url]

        normalized = self.base_url.rstrip("/")
        candidates = [f"{normalized}/chat/completions"]
        if normalized.endswith("/v1"):
            candidates.append(f"{normalized[:-3]}/chat/completions")
        else:
            candidates.append(f"{normalized}/v1/chat/completions")
        return list(dict.fromkeys(candidates))

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(url, headers=headers, content=json.dumps(payload))
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}: {truncate(r.text)}")
            return r.json()


def truncate(s: str, limit: int = 320) -> str:
    if s is None:
        return ""
    text = s.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _extract_message_text(body: dict[str, Any]) -> str:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Some providers return multi-part content blocks.
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                t = item.get("text")
                if isinstance(t, str):
                    parts.append(t)
        return "\n".join(parts)
    return ""

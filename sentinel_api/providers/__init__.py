"""LLM provider abstraction. Selected via SENTINEL_PROVIDER env var."""
from sentinel_api.config import settings
from sentinel_api.providers.base import LLMProvider
from sentinel_api.providers.mock import MockProvider
from sentinel_api.providers.openai_compatible import OpenAICompatibleProvider


def get_provider() -> LLMProvider:
    name = settings.provider.lower()
    if name in {"openai_compatible", "openai-compatible", "sentinel_agent", "sentinel-agent"}:
        return OpenAICompatibleProvider()
    if name == "mock":
        return MockProvider()
    # Unknown providers fall back to mock so the service always starts.
    return MockProvider()

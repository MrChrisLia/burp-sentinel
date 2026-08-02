"""Provider interface. The rest of Sentinel only depends on this."""


class LLMProvider:
    def complete(self, prompt: str) -> str:
        raise NotImplementedError

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """Optional richer chat-style call.

        Default implementation falls back to single-prompt completion so
        existing providers remain compatible.
        """
        combined = f"{system_prompt}\n\n{user_prompt}".strip()
        return self.complete(combined)

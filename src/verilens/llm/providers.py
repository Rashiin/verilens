"""Concrete LLM providers.

* ``gemini``  - Google Gemini REST API (has a free tier; set ``GEMINI_API_KEY``).
* ``openai``  - any OpenAI-compatible ``/chat/completions`` endpoint: OpenAI,
  OpenRouter, Groq, or a fully local model served by Ollama / vLLM / LM Studio.
"""

from __future__ import annotations

import os

from .base import LLMClient, LLMError

DEFAULT_GEMINI_MODEL = "gemini-flash-latest"
DEFAULT_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_OPENAI_BASE = "http://localhost:11434/v1"  # Ollama


class GeminiClient(LLMClient):
    provider = "gemini"

    def __init__(self, model: str | None = None, api_key: str | None = None, base_url: str | None = None, **kw):
        super().__init__(model=model or os.getenv("VERILENS_MODEL") or DEFAULT_GEMINI_MODEL, **kw)
        self.base_url = (base_url or os.getenv("GEMINI_BASE_URL") or DEFAULT_GEMINI_BASE).rstrip("/")
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise LLMError("Set GEMINI_API_KEY (free key: https://aistudio.google.com/apikey)")

    def _complete(self, system: str, prompt: str) -> str:
        url = f"{self.base_url}/models/{self.model}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
        }
        data = self._post_json(url, payload, {"x-goog-api-key": self.api_key})
        try:
            parts = data["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"Unexpected Gemini response: {str(data)[:300]}") from e
        return "".join(p.get("text", "") for p in parts)


class OpenAICompatibleClient(LLMClient):
    provider = "openai"

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        **kw,
    ):
        model = model or os.getenv("VERILENS_MODEL")
        if not model:
            raise LLMError("Pass --model (e.g. qwen2.5-coder:7b for Ollama)")
        super().__init__(model=model, **kw)
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL") or DEFAULT_OPENAI_BASE).rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or "not-needed"

    def _complete(self, system: str, prompt: str) -> str:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        data = self._post_json(
            f"{self.base_url}/chat/completions", payload, {"Authorization": f"Bearer {self.api_key}"}
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"Unexpected response: {str(data)[:300]}") from e


def make_client(provider: str, model: str | None = None, **kw) -> LLMClient:
    if provider == "gemini":
        return GeminiClient(model=model, **kw)
    if provider in ("openai", "ollama"):
        return OpenAICompatibleClient(model=model, **kw)
    raise LLMError(f"Unknown provider {provider!r} (use gemini or openai)")

"""Unified AI provider abstraction.

Supports: OpenAI, Groq, Anthropic, OpenRouter, Ollama, XAI, NVIDIA NIM.
Normalizes all providers behind a single `generate` interface.
"""

from __future__ import annotations

from typing import Any

from stryx.utils.logging import get_logger

logger = get_logger("ai.providers")


class AIProvider:
    """Base class for AI providers."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key
        self.model = model

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate a response from the AI model."""
        raise NotImplementedError


class OpenAIProvider(AIProvider):
    """OpenAI API provider."""

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(api_key=self.api_key)
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await client.chat.completions.create(
                model=self.model or "gpt-4",
                messages=messages,
                temperature=0.1,
                max_tokens=4096,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"OpenAI provider error: {e}")
            return ""


class GroqProvider(AIProvider):
    """Groq API provider."""

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            from groq import AsyncGroq

            client = AsyncGroq(api_key=self.api_key)
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await client.chat.completions.create(
                model=self.model or "llama-3.3-70b-versatile",
                messages=messages,
                temperature=0.1,
                max_tokens=4096,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"Groq provider error: {e}")
            return ""


class AnthropicProvider(AIProvider):
    """Anthropic API provider."""

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic(api_key=self.api_key)
            response = await client.messages.create(
                model=self.model or "claude-3-5-sonnet-20241022",
                max_tokens=4096,
                system=system_prompt if system_prompt else "You are a security expert.",
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else ""
        except Exception as e:
            logger.error(f"Anthropic provider error: {e}")
            return ""


class OpenRouterProvider(AIProvider):
    """OpenRouter API provider (routes to multiple models)."""

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                response = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model or "meta-llama/llama-3.3-70b-instruct:free",
                        "messages": messages,
                        "temperature": 0.1,
                        "max_tokens": 4096,
                    },
                    timeout=60,
                )
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenRouter provider error: {e}")
            return ""


class OllamaProvider(AIProvider):
    """Ollama local model provider."""

    def __init__(self, api_key: str | None = None, model: str | None = None, base_url: str = "http://localhost:11434"):
        super().__init__(api_key, model)
        self.base_url = base_url

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model or "llama3.1",
                        "messages": messages,
                        "stream": False,
                    },
                    timeout=120,
                )
                data = response.json()
                return data.get("message", {}).get("content", "")
        except Exception as e:
            logger.error(f"Ollama provider error: {e}")
            return ""


class XAIProvider(AIProvider):
    """XAI (Grok) API provider."""

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                response = await client.post(
                    "https://api.x.ai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model or "grok-2",
                        "messages": messages,
                        "temperature": 0.1,
                        "max_tokens": 4096,
                    },
                    timeout=60,
                )
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"XAI provider error: {e}")
            return ""


class NVIDIANimProvider(AIProvider):
    """NVIDIA NIM API provider."""

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                response = await client.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model or "meta/llama-3.1-8b-instruct",
                        "messages": messages,
                        "temperature": 0.1,
                        "max_tokens": 4096,
                    },
                    timeout=60,
                )
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"NVIDIA NIM provider error: {e}")
            return ""


def get_provider(name: str, api_key: str | None = None, model: str | None = None, **kwargs: Any) -> AIProvider:
    """Factory function to get an AI provider by name."""
    providers = {
        "openai": OpenAIProvider,
        "groq": GroqProvider,
        "anthropic": AnthropicProvider,
        "openrouter": OpenRouterProvider,
        "ollama": OllamaProvider,
        "xai": XAIProvider,
        "nvidia_nim": NVIDIANimProvider,
        "nvidia": NVIDIANimProvider,
    }

    provider_class = providers.get(name.lower())
    if not provider_class:
        logger.warning(f"Unknown provider '{name}', falling back to Groq")
        provider_class = GroqProvider

    if name.lower() == "ollama":
        return OllamaProvider(api_key=api_key, model=model, **kwargs)

    return provider_class(api_key=api_key, model=model)

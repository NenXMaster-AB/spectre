"""
LLM Interface Abstraction

Model-agnostic interface for LLM providers (Claude, OpenAI, Ollama).
Supports async streaming, token tracking, and structured output extraction.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

import httpx
import structlog

logger = structlog.get_logger(__name__)


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    CLAUDE = "claude"
    OPENAI = "openai"
    OLLAMA = "ollama"


@dataclass
class LLMConfig:
    """Configuration for LLM provider."""

    provider: LLMProvider
    model: str
    api_key: str | None = None
    api_url: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096
    timeout_seconds: int = 60

    @classmethod
    def claude(
        cls,
        api_key: str,
        model: str = "claude-sonnet-4-5-20250929",
        **kwargs: Any,
    ) -> "LLMConfig":
        """Create Claude configuration."""
        return cls(
            provider=LLMProvider.CLAUDE,
            model=model,
            api_key=api_key,
            api_url="https://api.anthropic.com/v1/messages",
            **kwargs,
        )

    @classmethod
    def openai(
        cls,
        api_key: str,
        model: str = "gpt-4o",
        **kwargs: Any,
    ) -> "LLMConfig":
        """Create OpenAI configuration."""
        return cls(
            provider=LLMProvider.OPENAI,
            model=model,
            api_key=api_key,
            api_url="https://api.openai.com/v1/chat/completions",
            **kwargs,
        )

    @classmethod
    def ollama(
        cls,
        model: str = "llama2",
        api_url: str = "http://localhost:11434/api/generate",
        **kwargs: Any,
    ) -> "LLMConfig":
        """Create Ollama configuration (local, no API key needed)."""
        return cls(
            provider=LLMProvider.OLLAMA,
            model=model,
            api_key=None,
            api_url=api_url,
            **kwargs,
        )


@dataclass
class LLMMessage:
    """A message in a conversation."""

    role: str  # "user", "assistant", "system"
    content: str


@dataclass
class LLMResponse:
    """Response from an LLM."""

    content: str
    model: str
    provider: LLMProvider
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)

    @property
    def cost_estimate(self) -> float:
        """Estimate cost in USD (rough approximation)."""
        # Approximate costs per 1M tokens
        costs = {
            LLMProvider.CLAUDE: {"input": 3.0, "output": 15.0},
            LLMProvider.OPENAI: {"input": 5.0, "output": 15.0},
            LLMProvider.OLLAMA: {"input": 0.0, "output": 0.0},
        }
        rates = costs.get(self.provider, {"input": 0.0, "output": 0.0})
        return (self.input_tokens * rates["input"] + self.output_tokens * rates["output"]) / 1_000_000


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the client with configuration."""
        self.config = config
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.config.timeout_seconds)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @abstractmethod
    async def generate(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Generate a response from the LLM."""
        ...

    @abstractmethod
    async def generate_stream(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> AsyncIterator[str]:
        """Generate a streaming response from the LLM."""
        ...

    async def generate_json(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Generate a response and parse it as JSON."""
        response = await self.generate(messages, system_prompt)
        content = response.content.strip()

        # Try to extract JSON from markdown code blocks
        if "```json" in content:
            start = content.find("```json") + 7
            end = content.find("```", start)
            content = content[start:end].strip()
        elif "```" in content:
            start = content.find("```") + 3
            end = content.find("```", start)
            content = content[start:end].strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON from LLM response", error=str(e), content=content[:200])
            raise ValueError(f"Failed to parse JSON from LLM response: {e}") from e


class ClaudeClient(BaseLLMClient):
    """Anthropic Claude API client."""

    async def generate(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Generate a response from Claude."""
        client = await self._get_client()

        # Build request
        api_messages = [{"role": m.role, "content": m.content} for m in messages]

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": api_messages,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if self.config.temperature > 0:
            payload["temperature"] = self.config.temperature

        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        logger.debug("Sending request to Claude", model=self.config.model)

        response = await client.post(
            self.config.api_url,
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()

        # Extract content
        content = ""
        if data.get("content"):
            content = "".join(
                block.get("text", "") for block in data["content"] if block.get("type") == "text"
            )

        usage = data.get("usage", {})

        return LLMResponse(
            content=content,
            model=self.config.model,
            provider=LLMProvider.CLAUDE,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            finish_reason=data.get("stop_reason"),
            raw_response=data,
        )

    async def generate_stream(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> AsyncIterator[str]:
        """Generate a streaming response from Claude."""
        client = await self._get_client()

        api_messages = [{"role": m.role, "content": m.content} for m in messages]

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": api_messages,
            "stream": True,
        }

        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        async with client.stream(
            "POST",
            self.config.api_url,
            json=payload,
            headers=headers,
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    try:
                        data = json.loads(line[6:])
                        if data.get("type") == "content_block_delta":
                            delta = data.get("delta", {})
                            if delta.get("type") == "text_delta":
                                yield delta.get("text", "")
                    except json.JSONDecodeError:
                        continue


class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""

    async def generate(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Generate a response from OpenAI."""
        client = await self._get_client()

        # Build messages with system prompt
        api_messages = []
        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})
        api_messages.extend([{"role": m.role, "content": m.content} for m in messages])

        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": api_messages,
            "temperature": self.config.temperature,
        }

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        logger.debug("Sending request to OpenAI", model=self.config.model)

        response = await client.post(
            self.config.api_url,
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()

        # Extract content
        content = ""
        if data.get("choices"):
            content = data["choices"][0].get("message", {}).get("content", "")

        usage = data.get("usage", {})

        return LLMResponse(
            content=content,
            model=self.config.model,
            provider=LLMProvider.OPENAI,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            finish_reason=data.get("choices", [{}])[0].get("finish_reason"),
            raw_response=data,
        )

    async def generate_stream(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> AsyncIterator[str]:
        """Generate a streaming response from OpenAI."""
        client = await self._get_client()

        api_messages = []
        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})
        api_messages.extend([{"role": m.role, "content": m.content} for m in messages])

        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": api_messages,
            "temperature": self.config.temperature,
            "stream": True,
        }

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        async with client.stream(
            "POST",
            self.config.api_url,
            json=payload,
            headers=headers,
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        data = json.loads(line[6:])
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        if "content" in delta:
                            yield delta["content"]
                    except json.JSONDecodeError:
                        continue


class OllamaClient(BaseLLMClient):
    """Ollama local LLM client."""

    async def generate(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Generate a response from Ollama."""
        client = await self._get_client()

        # Ollama uses a simpler prompt format
        prompt_parts = []
        if system_prompt:
            prompt_parts.append(f"System: {system_prompt}\n")
        for msg in messages:
            role = msg.role.capitalize()
            prompt_parts.append(f"{role}: {msg.content}\n")
        prompt_parts.append("Assistant: ")

        payload = {
            "model": self.config.model,
            "prompt": "".join(prompt_parts),
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        logger.debug("Sending request to Ollama", model=self.config.model)

        response = await client.post(
            self.config.api_url,
            json=payload,
        )
        response.raise_for_status()
        data = response.json()

        return LLMResponse(
            content=data.get("response", ""),
            model=self.config.model,
            provider=LLMProvider.OLLAMA,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
            finish_reason="stop" if data.get("done") else None,
            raw_response=data,
        )

    async def generate_stream(
        self,
        messages: list[LLMMessage],
        system_prompt: str | None = None,
    ) -> AsyncIterator[str]:
        """Generate a streaming response from Ollama."""
        client = await self._get_client()

        prompt_parts = []
        if system_prompt:
            prompt_parts.append(f"System: {system_prompt}\n")
        for msg in messages:
            role = msg.role.capitalize()
            prompt_parts.append(f"{role}: {msg.content}\n")
        prompt_parts.append("Assistant: ")

        payload = {
            "model": self.config.model,
            "prompt": "".join(prompt_parts),
            "stream": True,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        async with client.stream(
            "POST",
            self.config.api_url,
            json=payload,
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "response" in data:
                            yield data["response"]
                    except json.JSONDecodeError:
                        continue


def create_llm_client(config: LLMConfig) -> BaseLLMClient:
    """Factory function to create the appropriate LLM client."""
    clients = {
        LLMProvider.CLAUDE: ClaudeClient,
        LLMProvider.OPENAI: OpenAIClient,
        LLMProvider.OLLAMA: OllamaClient,
    }

    client_class = clients.get(config.provider)
    if client_class is None:
        raise ValueError(f"Unsupported LLM provider: {config.provider}")

    return client_class(config)

"""Model provider seam. build_adapter() is the one place that decides which
ModelAdapter backs an agent -- callers never construct a provider client
directly. Adding a second provider is a new adapter file + one more branch
here, not a rewrite of agent_core.py or any agent loop -- "openrouter" below
is exactly that: no new logic, just OpenAICompatibleAdapter pointed at a
specific base_url/API-key env var.

"openrouter" is one provider name, not one per model family: OpenRouter is a
single account/key/endpoint fronting many different models (GLM, Qwen,
DeepSeek, ...), so which model you get is entirely the --model flag
(e.g. "z-ai/glm-5.2", "qwen/qwen3.6-plus") -- not a new provider entry per
model. A genuinely different endpoint (GLM/Zhipu direct, rather than via
OpenRouter) would be its own _build_* factory with a different
base_url/api_key_env, same adapter class.
"""

from __future__ import annotations

from .anthropic_adapter import AnthropicAdapter
from .base import ModelAdapter, ModelResponse, ToolCall, ToolResult, Turn, Usage
from .openai_compatible_adapter import OpenAICompatibleAdapter
from .pricing import estimate_cost_usd, sum_usage


def _build_openrouter_adapter(model: str) -> ModelAdapter:
    return OpenAICompatibleAdapter(model, base_url="https://openrouter.ai/api/v1", api_key_env="OPENROUTER_API_KEY")


_PROVIDERS = {
    "anthropic": AnthropicAdapter,
    "openrouter": _build_openrouter_adapter,
}


def build_adapter(provider: str, model: str) -> ModelAdapter:
    try:
        adapter_cls = _PROVIDERS[provider]
    except KeyError:
        raise ValueError(
            f"Unknown model provider {provider!r}. Available providers: {sorted(_PROVIDERS)}"
        ) from None
    return adapter_cls(model)


__all__ = [
    "ModelAdapter",
    "ModelResponse",
    "OpenAICompatibleAdapter",
    "ToolCall",
    "ToolResult",
    "Turn",
    "Usage",
    "build_adapter",
    "estimate_cost_usd",
    "sum_usage",
]

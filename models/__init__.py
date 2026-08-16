"""Model provider seam. build_adapter() is the one place that decides which
ModelAdapter backs an agent -- callers never construct a provider client
directly. Only "anthropic" is registered today; adding a second provider is
a new adapter file + one more branch here, not a rewrite of agent_core.py or
any agent loop.
"""

from __future__ import annotations

from .anthropic_adapter import AnthropicAdapter
from .base import ModelAdapter, ModelResponse, ToolCall, ToolResult, Turn, Usage
from .pricing import estimate_cost_usd, sum_usage

_PROVIDERS = {
    "anthropic": AnthropicAdapter,
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
    "ToolCall",
    "ToolResult",
    "Turn",
    "Usage",
    "build_adapter",
    "estimate_cost_usd",
    "sum_usage",
]

"""Provider-agnostic model interface. agent_core.py's tool-calling loop talks
only to a ModelAdapter and the neutral dataclasses below -- it never touches
a provider's native message/content-block shapes. Each adapter is
responsible for translating the *entire* Turn history to and from its
provider's wire format on every call, not just the latest response; that's
what keeps agent_core.py genuinely provider-agnostic rather than merely
wrapping one provider's response shape.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ToolResult:
    tool_call_id: str
    content: str  # JSON-serialized tool output
    is_error: bool = False


@dataclass
class Turn:
    role: str  # "user" | "assistant"
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)


@dataclass
class ModelResponse:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str


class ModelAdapter(ABC):
    @abstractmethod
    async def send_messages(
        self, system: str, messages: list[Turn], tools: list[dict], max_tokens: int
    ) -> ModelResponse:
        """Send the full conversation so far and return the model's next turn,
        normalized into a ModelResponse. `messages` is the complete Turn
        history built by agent_core.py; implementations translate it to their
        provider's native format on every call.
        """
        raise NotImplementedError

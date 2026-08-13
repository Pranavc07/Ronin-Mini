"""The only real ModelAdapter implementation today -- wraps anthropic's
AsyncAnthropic client. Auth is still the SDK's implicit env-based
ANTHROPIC_API_KEY read, unchanged from before this adapter layer existed.
"""

from __future__ import annotations

import anthropic

from .base import ModelAdapter, ModelResponse, ToolCall, Turn


class AnthropicAdapter(ModelAdapter):
    def __init__(self, model: str):
        self._client = anthropic.AsyncAnthropic()
        self._model = model

    def _to_anthropic_messages(self, messages: list[Turn]) -> list[dict]:
        anthropic_messages = []
        for turn in messages:
            if turn.tool_results:
                anthropic_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": r.tool_call_id,
                                "content": r.content,
                                "is_error": r.is_error,
                            }
                            for r in turn.tool_results
                        ],
                    }
                )
            elif turn.role == "assistant":
                content = []
                if turn.text:
                    content.append({"type": "text", "text": turn.text})
                for call in turn.tool_calls:
                    content.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.input})
                anthropic_messages.append({"role": "assistant", "content": content})
            else:
                anthropic_messages.append({"role": "user", "content": turn.text})
        return anthropic_messages

    async def send_messages(
        self, system: str, messages: list[Turn], tools: list[dict], max_tokens: int
    ) -> ModelResponse:
        anthropic_messages = self._to_anthropic_messages(messages)

        async with self._client.messages.stream(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=anthropic_messages,
        ) as stream:
            async for _ in stream:
                pass
            response = await stream.get_final_message()

        text = "\n".join(block.text for block in response.content if block.type == "text")
        tool_calls = [
            ToolCall(id=block.id, name=block.name, input=block.input)
            for block in response.content
            if block.type == "tool_use"
        ]
        return ModelResponse(text=text, tool_calls=tool_calls, stop_reason=response.stop_reason or "end_turn")

"""Adapter for any OpenAI-compatible chat completions API -- OpenRouter,
GLM/Zhipu direct, OpenAI itself, etc. Translates the same neutral
Turn/ToolCall/ToolResult/ModelResponse shapes models/base.py defines,
mirroring what AnthropicAdapter does for Anthropic's wire format, so
agent_core.py stays provider-agnostic regardless of which one backs a run.

Kept generic (base_url + which env var holds the key are constructor
params, not hardcoded) rather than writing a GLM- or Qwen-specific class,
since the wire protocol here is OpenAI's, not any one model vendor's -- any
other OpenAI-compatible provider is the same adapter with different
constructor args. See models/__init__.py for how the "openrouter" provider
name wires this to a specific base_url/env var -- one provider entry covers
every model OpenRouter fronts (GLM, Qwen, DeepSeek, ...), selected via
--model, not a new provider per model family.
"""

from __future__ import annotations

import json
import os

import openai

from .base import ModelAdapter, ModelResponse, ToolCall, Turn, Usage

# finish_reason values vary by provider; normalize the two that matter for
# agent_core.py's loop logic to the same vocabulary AnthropicAdapter uses
# ("tool_use"/"end_turn") so run.py's printed stop_reason reads consistently
# regardless of which adapter produced it. Anything else passes through
# as-is rather than being silently mapped to something misleading.
_FINISH_REASON_MAP = {"tool_calls": "tool_use", "stop": "end_turn"}


class OpenAICompatibleAdapter(ModelAdapter):
    def __init__(self, model: str, base_url: str, api_key_env: str):
        api_key = os.environ.get(api_key_env)
        if not api_key:
            print(
                f"warning: {api_key_env} is not set; requests to {base_url} will fail to authenticate.",
            )
        self._client = openai.AsyncOpenAI(base_url=base_url, api_key=api_key)
        self._model = model

    def _to_openai_messages(self, system: str, messages: list[Turn]) -> list[dict]:
        openai_messages: list[dict] = [{"role": "system", "content": system}]
        for turn in messages:
            if turn.tool_results:
                # OpenAI's wire format wants one "tool" message per result,
                # not one message bundling several -- unlike Anthropic's
                # single user-turn-with-multiple-tool_result-blocks shape.
                for result in turn.tool_results:
                    openai_messages.append(
                        {"role": "tool", "tool_call_id": result.tool_call_id, "content": result.content}
                    )
            elif turn.role == "assistant":
                message: dict = {"role": "assistant", "content": turn.text or None}
                if turn.tool_calls:
                    message["tool_calls"] = [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {"name": call.name, "arguments": json.dumps(call.input)},
                        }
                        for call in turn.tool_calls
                    ]
                openai_messages.append(message)
            else:
                openai_messages.append({"role": "user", "content": turn.text})
        return openai_messages

    @staticmethod
    def _to_openai_tools(tools: list[dict]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    async def send_messages(
        self, system: str, messages: list[Turn], tools: list[dict], max_tokens: int
    ) -> ModelResponse:
        openai_messages = self._to_openai_messages(system, messages)

        kwargs: dict = {"model": self._model, "messages": openai_messages, "max_tokens": max_tokens}
        openai_tools = self._to_openai_tools(tools)
        if openai_tools:
            kwargs["tools"] = openai_tools

        response = await self._client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        message = choice.message
        text = message.content or ""

        tool_calls = []
        for tc in message.tool_calls or []:
            try:
                tool_input = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                tool_input = {}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=tool_input))

        stop_reason = _FINISH_REASON_MAP.get(choice.finish_reason, choice.finish_reason or "end_turn")

        # getattr-guarded like AnthropicAdapter's usage extraction -- test
        # doubles / providers that omit usage default to zero, not a crash.
        raw_usage = getattr(response, "usage", None)
        details = getattr(raw_usage, "prompt_tokens_details", None)
        cached = (getattr(details, "cached_tokens", 0) or 0) if details is not None else 0
        usage = Usage(
            input_tokens=getattr(raw_usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(raw_usage, "completion_tokens", 0) or 0,
            cache_read_input_tokens=cached,
        )

        return ModelResponse(text=text, tool_calls=tool_calls, stop_reason=stop_reason, usage=usage)

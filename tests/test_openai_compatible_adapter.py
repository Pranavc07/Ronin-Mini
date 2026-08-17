"""Unit tests for OpenAICompatibleAdapter's Turn <-> OpenAI-chat-completions
translation (used by the "openrouter" provider -- GLM, Qwen, DeepSeek, or
any other OpenAI-compatible model/provider added later).

No network, no real API key needed -- chat.completions.create is mocked.

Run with: pytest tests/test_openai_compatible_adapter.py -v
"""

import asyncio
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from models.base import ToolCall, ToolResult, Turn, Usage  # noqa: E402
from models.openai_compatible_adapter import OpenAICompatibleAdapter  # noqa: E402


def _adapter() -> OpenAICompatibleAdapter:
    return OpenAICompatibleAdapter.__new__(OpenAICompatibleAdapter)  # skip __init__, no real client needed


# --- message translation ----------------------------------------------------


def test_to_openai_messages_translates_turns():
    adapter = _adapter()
    messages = [
        Turn(role="user", text="do the thing"),
        Turn(
            role="assistant",
            text="I'll check it",
            tool_calls=[ToolCall(id="call_1", name="http_request", input={"url": "http://x"})],
        ),
        Turn(role="user", tool_results=[ToolResult(tool_call_id="call_1", content='{"status": 200}', is_error=False)]),
    ]

    out = adapter._to_openai_messages("system prompt", messages)

    assert out[0] == {"role": "system", "content": "system prompt"}
    assert out[1] == {"role": "user", "content": "do the thing"}
    assert out[2]["role"] == "assistant"
    assert out[2]["content"] == "I'll check it"
    assert out[2]["tool_calls"] == [
        {"id": "call_1", "type": "function", "function": {"name": "http_request", "arguments": '{"url": "http://x"}'}}
    ]
    assert out[3] == {"role": "tool", "tool_call_id": "call_1", "content": '{"status": 200}'}


def test_to_openai_messages_expands_multiple_tool_results_into_separate_messages():
    """Unlike Anthropic's single user-turn-with-multiple-blocks shape,
    OpenAI's wire format wants one "tool" message per result.
    """
    adapter = _adapter()
    messages = [
        Turn(
            role="user",
            tool_results=[
                ToolResult(tool_call_id="c1", content="r1"),
                ToolResult(tool_call_id="c2", content="r2"),
            ],
        )
    ]
    out = adapter._to_openai_messages("sys", messages)
    tool_messages = out[1:]
    assert tool_messages == [
        {"role": "tool", "tool_call_id": "c1", "content": "r1"},
        {"role": "tool", "tool_call_id": "c2", "content": "r2"},
    ]


def test_to_openai_messages_assistant_with_no_text_has_none_content():
    adapter = _adapter()
    messages = [Turn(role="assistant", text="", tool_calls=[ToolCall(id="c1", name="x", input={})])]
    out = adapter._to_openai_messages("sys", messages)
    assert out[1]["content"] is None


# --- tool schema translation -------------------------------------------------


def test_to_openai_tools_translates_anthropic_shaped_schema():
    tools = [{"name": "dns_lookup", "description": "Resolve a hostname", "input_schema": {"type": "object", "properties": {}}}]
    out = OpenAICompatibleAdapter._to_openai_tools(tools)
    assert out == [
        {
            "type": "function",
            "function": {
                "name": "dns_lookup",
                "description": "Resolve a hostname",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]


# --- send_messages: response parsing ----------------------------------------


def _fake_response(content, tool_calls=None, finish_reason="stop", usage=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(message=message, finish_reason=finish_reason)
    return SimpleNamespace(choices=[choice], usage=usage)


def test_send_messages_returns_normalized_response_with_tool_calls():
    adapter = _adapter()
    tool_call = SimpleNamespace(id="call_2", function=SimpleNamespace(name="dns_lookup", arguments='{"hostname": "x"}'))
    fake_response = _fake_response(
        content="here's my reasoning",
        tool_calls=[tool_call],
        finish_reason="tool_calls",
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20, prompt_tokens_details=SimpleNamespace(cached_tokens=5)),
    )
    adapter._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=fake_response)))
    )
    adapter._model = "glm-5.2"

    response = asyncio.run(adapter.send_messages("system prompt", [Turn(role="user", text="hi")], [], 4096))

    assert response.text == "here's my reasoning"
    assert response.stop_reason == "tool_use"  # "tool_calls" normalized to Anthropic-style vocabulary
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].id == "call_2"
    assert response.tool_calls[0].name == "dns_lookup"
    assert response.tool_calls[0].input == {"hostname": "x"}
    assert response.usage == Usage(input_tokens=100, output_tokens=20, cache_read_input_tokens=5)


def test_send_messages_stop_finish_reason_normalized_to_end_turn():
    adapter = _adapter()
    fake_response = _fake_response(content="done", tool_calls=None, finish_reason="stop", usage=None)
    adapter._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=fake_response)))
    )
    adapter._model = "glm-5.2"

    response = asyncio.run(adapter.send_messages("sys", [Turn(role="user", text="hi")], [], 4096))

    assert response.text == "done"
    assert response.stop_reason == "end_turn"
    assert response.tool_calls == []
    assert response.usage == Usage()  # no usage on the response -> defaults to zero, not a crash


def test_send_messages_malformed_tool_call_arguments_default_to_empty_dict():
    adapter = _adapter()
    tool_call = SimpleNamespace(id="call_3", function=SimpleNamespace(name="x", arguments="not valid json"))
    fake_response = _fake_response(content="", tool_calls=[tool_call], finish_reason="tool_calls", usage=None)
    adapter._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=fake_response)))
    )
    adapter._model = "glm-5.2"

    response = asyncio.run(adapter.send_messages("sys", [], [], 4096))

    assert response.tool_calls[0].input == {}

"""Unit tests for agent_core.py's HITL gate (confirm_tool_call) and the
AnthropicAdapter's Turn <-> Anthropic-message-block translation.

No network, no Docker, no ANTHROPIC_API_KEY needed -- the Anthropic client
is never actually called (confirm_tool_call doesn't touch it, and the
adapter test mocks messages.stream()).

Run with: pytest tests/test_agent_core.py -v
"""

import asyncio
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

from ronin_mini import agent_core  # noqa: E402
from manifest import ToolMeta, load_manifest  # noqa: E402
from ronin_mini.models.anthropic_adapter import AnthropicAdapter  # noqa: E402
from ronin_mini.models.base import ModelAdapter, ModelResponse, ToolCall, ToolResult, Turn  # noqa: E402

GATED_MANIFEST = load_manifest()  # probe_variant/execute_python/replay_probe are require_approval: true
UNGATED_TOOL = "http_request"
GATED_TOOL = "probe_variant"


# --- confirm_tool_call --------------------------------------------------


def test_ungated_tool_auto_approves_without_prompting(monkeypatch):
    def fail_if_called(*a, **kw):
        raise AssertionError("input() should not be called for an ungated tool")

    monkeypatch.setattr("builtins.input", fail_if_called)
    approved, final_input = agent_core.confirm_tool_call(UNGATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is True
    assert final_input == {"url": "http://x"}


def test_gated_tool_approve_with_y(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    approved, final_input = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is True
    assert final_input == {"url": "http://x"}


def test_gated_tool_deny_with_n(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    approved, final_input = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is False


def test_gated_tool_deny_on_anything_else(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "whatever")
    approved, _ = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is False


def test_gated_tool_edit_with_valid_json(monkeypatch):
    responses = iter(["edit", '{"url": "http://edited"}'])
    monkeypatch.setattr("builtins.input", lambda _: next(responses))
    approved, final_input = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is True
    assert final_input == {"url": "http://edited"}


def test_gated_tool_edit_with_invalid_json_denies(monkeypatch):
    responses = iter(["edit", "not valid json"])
    monkeypatch.setattr("builtins.input", lambda _: next(responses))
    approved, _ = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is False


def test_gated_tool_edit_with_blank_denies(monkeypatch):
    responses = iter(["edit", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(responses))
    approved, _ = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is False


def test_gated_tool_eof_denies_fail_safe(monkeypatch):
    def raise_eof(_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    approved, final_input = agent_core.confirm_tool_call(GATED_TOOL, {"url": "http://x"}, GATED_MANIFEST)
    assert approved is False
    assert final_input == {"url": "http://x"}


def test_unknown_tool_not_in_manifest_auto_approves(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(AssertionError("should not prompt")))
    approved, _ = agent_core.confirm_tool_call("totally_unknown_tool", {}, GATED_MANIFEST)
    assert approved is True


# --- AnthropicAdapter Turn <-> block translation -------------------------


def _fake_content_block(type_: str, **kwargs):
    return SimpleNamespace(type=type_, **kwargs)


def test_to_anthropic_messages_translates_turns():
    adapter = AnthropicAdapter.__new__(AnthropicAdapter)  # skip __init__, no real client needed
    messages = [
        Turn(role="user", text="do the thing"),
        Turn(
            role="assistant",
            text="I'll check it",
            tool_calls=[ToolCall(id="call_1", name="http_request", input={"url": "http://x"})],
        ),
        Turn(role="user", tool_results=[ToolResult(tool_call_id="call_1", content='{"status": 200}', is_error=False)]),
    ]

    out = adapter._to_anthropic_messages(messages)

    assert out[0] == {"role": "user", "content": "do the thing"}
    assert out[1]["role"] == "assistant"
    assert {"type": "text", "text": "I'll check it"} in out[1]["content"]
    assert {"type": "tool_use", "id": "call_1", "name": "http_request", "input": {"url": "http://x"}} in out[1]["content"]
    assert out[2] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": '{"status": 200}', "is_error": False}],
    }


class _FakeStream:
    def __init__(self, final_message):
        self._final_message = final_message

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    def __aiter__(self):
        async def _empty():
            return
            yield  # pragma: no cover -- makes this an async generator

        return _empty()

    async def get_final_message(self):
        return self._final_message


def test_send_messages_returns_normalized_response():
    adapter = AnthropicAdapter.__new__(AnthropicAdapter)

    fake_response = SimpleNamespace(
        content=[
            _fake_content_block("text", text="here's my reasoning"),
            _fake_content_block("tool_use", id="call_2", name="dns_lookup", input={"hostname": "x"}),
        ],
        stop_reason="tool_use",
    )

    fake_client = SimpleNamespace(
        messages=SimpleNamespace(stream=MagicMock(return_value=_FakeStream(fake_response)))
    )
    adapter._client = fake_client
    adapter._model = "fake-model"

    response = asyncio.run(adapter.send_messages("system prompt", [Turn(role="user", text="hi")], [], 4096))

    assert response.text == "here's my reasoning"
    assert response.stop_reason == "tool_use"
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].id == "call_2"
    assert response.tool_calls[0].name == "dns_lookup"
    assert response.tool_calls[0].input == {"hostname": "x"}


# --- run_tool_loop hitl_mode dispatch (auto / manual / plan) ------------


class _FakeSession:
    """Duck-typed stand-in for mcp.ClientSession -- run_tool_loop only ever
    calls session.call_tool(name, tool_input, read_timeout_seconds=...).
    """

    async def call_tool(self, name, tool_input, read_timeout_seconds=None):
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps({"ok": True}))], is_error=False)


class _ScriptedAdapter(ModelAdapter):
    """Replays a fixed sequence of ModelResponse turns, ignoring the actual
    message history -- enough to drive run_tool_loop through N gated tool
    calls deterministically.
    """

    def __init__(self, turns: list[ModelResponse]):
        self._turns = list(turns)

    async def send_messages(self, system, messages, tools, max_tokens):
        return self._turns.pop(0)


def _three_gated_call_turns() -> list[ModelResponse]:
    turns = [
        ModelResponse(text="", tool_calls=[ToolCall(id=f"c{i}", name=GATED_TOOL, input={"n": i})], stop_reason="tool_use")
        for i in range(3)
    ]
    turns.append(ModelResponse(text="done", tool_calls=[], stop_reason="end_turn"))
    return turns


def test_hitl_mode_auto_never_prompts(monkeypatch):
    def fail_if_called(*a, **kw):
        raise AssertionError("input() should never be called in auto mode")

    monkeypatch.setattr("builtins.input", fail_if_called)
    adapter = _ScriptedAdapter(_three_gated_call_turns())
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _FakeSession(), GATED_MANIFEST, "system", [], "begin", 10, 1.0, hitl_mode="auto"
        )
    )
    assert result["tool_call_count"] == 3
    assert all(not t["output"].get("error") for t in result["transcript"])


def test_hitl_mode_manual_prompts_every_gated_call(monkeypatch):
    calls = {"count": 0}

    def count_and_approve(_):
        calls["count"] += 1
        return "y"

    monkeypatch.setattr("builtins.input", count_and_approve)
    adapter = _ScriptedAdapter(_three_gated_call_turns())
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _FakeSession(), GATED_MANIFEST, "system", [], "begin", 10, 1.0, hitl_mode="manual"
        )
    )
    assert calls["count"] == 3
    assert result["tool_call_count"] == 3


def test_hitl_mode_plan_prompts_once_then_reuses_decision(monkeypatch):
    calls = {"count": 0}

    def count_and_approve(_):
        calls["count"] += 1
        return "y"

    monkeypatch.setattr("builtins.input", count_and_approve)
    adapter = _ScriptedAdapter(_three_gated_call_turns())
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _FakeSession(), GATED_MANIFEST, "system", [], "begin", 10, 1.0, hitl_mode="plan"
        )
    )
    assert calls["count"] == 1  # one approval governs all 3 gated calls
    assert result["tool_call_count"] == 3
    assert all(not t["output"].get("error") for t in result["transcript"])


def test_hitl_mode_plan_denial_denies_rest_of_run(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    adapter = _ScriptedAdapter(_three_gated_call_turns())
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _FakeSession(), GATED_MANIFEST, "system", [], "begin", 10, 1.0, hitl_mode="plan"
        )
    )
    assert result["tool_call_count"] == 3
    assert all(t["output"].get("error") == "Tool call denied by operator (HITL gate)." for t in result["transcript"])


def test_hitl_mode_plan_never_prompts_when_no_gated_tools(monkeypatch):
    def fail_if_called(*a, **kw):
        raise AssertionError("input() should not be called when no gated tool is ever invoked")

    monkeypatch.setattr("builtins.input", fail_if_called)
    turns = [
        ModelResponse(text="", tool_calls=[ToolCall(id="c1", name=UNGATED_TOOL, input={})], stop_reason="tool_use"),
        ModelResponse(text="done", tool_calls=[], stop_reason="end_turn"),
    ]
    adapter = _ScriptedAdapter(turns)
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _FakeSession(), GATED_MANIFEST, "system", [], "begin", 10, 1.0, hitl_mode="plan"
        )
    )
    assert result["tool_call_count"] == 1


def test_invalid_hitl_mode_raises():
    import pytest

    adapter = _ScriptedAdapter([ModelResponse(text="done", tool_calls=[], stop_reason="end_turn")])
    with pytest.raises(AssertionError, match="unknown hitl_mode"):
        asyncio.run(
            agent_core.run_tool_loop(
                adapter, _FakeSession(), GATED_MANIFEST, "system", [], "begin", 10, 1.0, hitl_mode="bogus"
            )
        )

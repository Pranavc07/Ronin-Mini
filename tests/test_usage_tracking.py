"""Unit tests for token usage tracking and cost estimation:
models.base.Usage, models.pricing.{estimate_cost_usd,sum_usage}, the
AnthropicAdapter's usage extraction, and agent_core.run_tool_loop's
per-loop usage accumulation.

No network, no Docker, no ANTHROPIC_API_KEY needed.

Run with: pytest tests/test_usage_tracking.py -v
"""

import asyncio
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

from ronin_mini import agent_core  # noqa: E402
from ronin_mini.models.anthropic_adapter import AnthropicAdapter  # noqa: E402
from ronin_mini.models.base import ModelAdapter, ModelResponse, Usage  # noqa: E402
from ronin_mini.models.pricing import estimate_cost_usd, sum_usage  # noqa: E402

# --- Usage dataclass ------------------------------------------------------


def test_usage_add_sums_all_four_fields():
    a = Usage(input_tokens=100, output_tokens=10, cache_creation_input_tokens=5, cache_read_input_tokens=2)
    b = Usage(input_tokens=50, output_tokens=5, cache_creation_input_tokens=1, cache_read_input_tokens=1)
    total = a + b
    assert total.input_tokens == 150
    assert total.output_tokens == 15
    assert total.cache_creation_input_tokens == 6
    assert total.cache_read_input_tokens == 3


def test_usage_default_is_all_zero():
    u = Usage()
    assert u.as_dict() == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }


# --- pricing ----------------------------------------------------------------


def test_estimate_cost_usd_known_model():
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    cost = estimate_cost_usd("claude-sonnet-4-6", usage)
    assert cost == 3.00 + 15.00  # 1M input @ $3/M + 1M output @ $15/M


def test_estimate_cost_usd_unknown_model_falls_back_to_default_rates():
    usage = {"input_tokens": 1_000_000, "output_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    cost = estimate_cost_usd("some-brand-new-model-nobody-has-priced-yet", usage)
    assert cost == 3.00  # default input rate


def test_estimate_cost_usd_missing_keys_default_to_zero():
    cost = estimate_cost_usd("claude-sonnet-4-6", {})
    assert cost == 0.0


def test_estimate_cost_usd_glm_free_tier_is_genuinely_zero():
    usage = {"input_tokens": 5_000_000, "output_tokens": 5_000_000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    cost = estimate_cost_usd("z-ai/glm-5.2:free", usage)
    assert cost == 0.0


def test_estimate_cost_usd_glm_paid_tier_is_not_priced_as_free():
    """Regression guard for a real bug caught live-testing this model against
    DVWA: the paid "z-ai/glm-5.2" id (no ":free" suffix) was falling through
    _rates_for's old bidirectional substring fallback and matching the
    unrelated "z-ai/glm-5.2:free" entry (since "z-ai/glm-5.2" is literally a
    substring of "z-ai/glm-5.2:free") -- a run with over a million real
    tokens reported $0.0000. Real rates confirmed via openrouter.ai/z-ai/glm-5.2.
    """
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    cost = estimate_cost_usd("z-ai/glm-5.2", usage)
    assert cost == 0.50 + 3.15


def test_estimate_cost_usd_qwen_uses_real_rates_not_sonnet_fallback():
    """Regression guard: qwen/qwen3.6-plus wasn't in PRICING at all, so every
    run used the Sonnet-tier _DEFAULT_RATES -- roughly a 9x overestimate of
    its real, much cheaper OpenRouter rate.
    """
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    cost = estimate_cost_usd("qwen/qwen3.6-plus", usage)
    assert cost == 0.325 + 1.95


def test_rates_for_substring_fallback_requires_boundary_not_bare_substring():
    """A bare `name in model` check would match "glm-5" against
    "glm-5.2:free-tier-variant" or similar false positives. The boundary
    check (next char must be '/', ':', or end-of-string) prevents that --
    confirmed here with a synthetic id that's a raw substring but not a real
    versioned/prefixed variant.
    """
    from models.pricing import _rates_for

    assert _rates_for("z-ai/glm-5.2extra") == _rates_for("some-unknown-model")


def test_sum_usage_across_multiple_dicts():
    u1 = {"input_tokens": 10, "output_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    u2 = {"input_tokens": 20, "output_tokens": 2, "cache_creation_input_tokens": 3, "cache_read_input_tokens": 4}
    total = sum_usage(u1, u2)
    assert total == {
        "input_tokens": 30,
        "output_tokens": 3,
        "cache_creation_input_tokens": 3,
        "cache_read_input_tokens": 4,
    }


def test_sum_usage_with_no_args_is_all_zero():
    assert sum_usage() == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }


# --- AnthropicAdapter usage extraction --------------------------------------


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
            yield  # pragma: no cover

        return _empty()

    async def get_final_message(self):
        return self._final_message


def _adapter_with_response(response: SimpleNamespace) -> AnthropicAdapter:
    adapter = AnthropicAdapter.__new__(AnthropicAdapter)
    adapter._client = SimpleNamespace(messages=SimpleNamespace(stream=MagicMock(return_value=_FakeStream(response))))
    adapter._model = "fake-model"
    return adapter


def test_send_messages_captures_real_usage():
    fake_response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="ok")],
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=123, output_tokens=45, cache_creation_input_tokens=6, cache_read_input_tokens=7
        ),
    )
    adapter = _adapter_with_response(fake_response)
    response = asyncio.run(adapter.send_messages("sys", [], [], 4096))
    assert response.usage == Usage(
        input_tokens=123, output_tokens=45, cache_creation_input_tokens=6, cache_read_input_tokens=7
    )


def test_send_messages_defaults_to_zero_usage_when_absent():
    # No `.usage` attribute at all -- mirrors older/mocked responses.
    fake_response = SimpleNamespace(content=[SimpleNamespace(type="text", text="ok")], stop_reason="end_turn")
    adapter = _adapter_with_response(fake_response)
    response = asyncio.run(adapter.send_messages("sys", [], [], 4096))
    assert response.usage == Usage()


# --- run_tool_loop usage accumulation ---------------------------------------


class _ScriptedUsageAdapter(ModelAdapter):
    def __init__(self, turns: list[ModelResponse]):
        self._turns = list(turns)

    async def send_messages(self, system, messages, tools, max_tokens):
        return self._turns.pop(0)


class _NoOpSession:
    async def call_tool(self, name, tool_input, read_timeout_seconds=None):
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="{}")], is_error=False)


def test_run_tool_loop_sums_usage_across_turns():
    turns = [
        ModelResponse(text="", tool_calls=[], stop_reason="end_turn", usage=Usage(input_tokens=100, output_tokens=10)),
    ]
    adapter = _ScriptedUsageAdapter(turns)
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _NoOpSession(), {}, "sys", [], "go", max_iterations=10, max_minutes=5, hitl_mode="auto"
        )
    )
    assert result["usage"] == {
        "input_tokens": 100,
        "output_tokens": 10,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }


def test_run_tool_loop_sums_usage_across_multiple_model_calls():
    from models.base import ToolCall

    turns = [
        ModelResponse(
            text="",
            tool_calls=[ToolCall(id="c1", name="http_request", input={})],
            stop_reason="tool_use",
            usage=Usage(input_tokens=100, output_tokens=10),
        ),
        ModelResponse(text="done", tool_calls=[], stop_reason="end_turn", usage=Usage(input_tokens=200, output_tokens=20)),
    ]
    adapter = _ScriptedUsageAdapter(turns)
    result = asyncio.run(
        agent_core.run_tool_loop(
            adapter, _NoOpSession(), {}, "sys", [], "go", max_iterations=10, max_minutes=5, hitl_mode="auto"
        )
    )
    assert result["usage"]["input_tokens"] == 300
    assert result["usage"]["output_tokens"] == 30

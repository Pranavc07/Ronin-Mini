"""Unit tests for agent_core.py's real-time live-print + JSONL append-log
behavior: run_tool_loop's label/log_path params print every model reasoning
turn and tool call/result as it happens (not buffered until the stage ends),
and persist the same events to a JSONL file for a replayable record of the
whole run -- including recon's own reasoning, previously discarded entirely
once recon returned only its extracted findings.

Run with: pytest tests/test_live_logging.py -v
"""

import asyncio
import json
import os
import sys
from types import SimpleNamespace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

from ronin_mini import agent_core  # noqa: E402
from ronin_mini.models.base import ModelAdapter, ModelResponse, ToolCall, Usage  # noqa: E402


class _ScriptedAdapter(ModelAdapter):
    def __init__(self, turns):
        self._turns = list(turns)

    async def send_messages(self, system, messages, tools, max_tokens):
        return self._turns.pop(0)


class _NoOpSession:
    async def call_tool(self, name, tool_input, read_timeout_seconds=None):
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps({"ok": True}))], is_error=False)


# --- _short -----------------------------------------------------------------


def test_short_leaves_text_under_limit_unchanged():
    assert agent_core._short("hello world", 100) == "hello world"


def test_short_truncates_and_notes_remaining_chars():
    text = "a" * 500
    out = agent_core._short(text, 100)
    assert out.startswith("a" * 100)
    assert "+400 chars" in out


def test_short_collapses_newlines_and_whitespace():
    assert agent_core._short("line one\n\n  line two", 100) == "line one line two"


# --- _live_print ---------------------------------------------------------


def test_live_print_falls_back_when_terminal_cant_encode_the_text(monkeypatch):
    """Reproduces a real crash hit live-testing on Windows: a model's
    reasoning text containing a character outside the console's legacy
    codepage (e.g. '→', not in cp1252) used to raise UnicodeEncodeError
    straight out of print() and kill the whole run over cosmetic terminal
    output. _live_print must fall back to a replaced-character version in
    that case, not propagate the error.
    """
    import io

    class Cp1252Stdout(io.TextIOBase):
        encoding = "cp1252"

        def __init__(self):
            self.chunks: list[str] = []

        def write(self, s):
            s.encode("cp1252")  # emulate a real cp1252 console raising here
            self.chunks.append(s)
            return len(s)

        def flush(self):
            pass

    fake_stdout = Cp1252Stdout()
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    agent_core._live_print("exploit:f1", "Step 1 → Step 2")

    written = "".join(fake_stdout.chunks)
    assert "Step 1" in written
    assert "Step 2" in written
    assert "→" not in written  # replaced, not crashed


def test_live_print_plain_ascii_unaffected(capsys):
    agent_core._live_print("recon", "hello world")
    assert capsys.readouterr().out == "[recon] hello world\n"


# --- _append_log --------------------------------------------------------


def test_append_log_noop_when_no_path():
    # Must not raise -- log_path=None is the common case (no persistent log configured).
    agent_core._append_log(None, {"type": "reasoning", "text": "x"})


def test_append_log_writes_one_json_line(tmp_path):
    log_path = str(tmp_path / "run.jsonl")
    agent_core._append_log(log_path, {"type": "reasoning", "text": "first"})
    agent_core._append_log(log_path, {"type": "reasoning", "text": "second"})
    lines = open(log_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["text"] == "first"
    assert json.loads(lines[1])["text"] == "second"


# --- run_tool_loop: live printing + persisted log ---------------------------


def _turns_with_one_tool_call():
    return [
        ModelResponse(
            text="I'll check the target's open ports first.",
            tool_calls=[ToolCall(id="c1", name="http_request", input={"url": "http://x/"})],
            stop_reason="tool_use",
            usage=Usage(input_tokens=10, output_tokens=5),
        ),
        ModelResponse(text="Nothing else to check.", tool_calls=[], stop_reason="end_turn", usage=Usage(8, 3)),
    ]


def test_run_tool_loop_prints_reasoning_and_tool_calls_live(capsys):
    adapter = _ScriptedAdapter(_turns_with_one_tool_call())
    asyncio.run(
        agent_core.run_tool_loop(
            adapter, _NoOpSession(), {}, "sys", [], "go", 10, 5, hitl_mode="auto", label="recon"
        )
    )
    out = capsys.readouterr().out
    assert "[recon] reasoning: I'll check the target's open ports first." in out
    assert '[recon] -> http_request({"url": "http://x/"})' in out
    assert "[recon] <- http_request [ok]:" in out
    assert "[recon] reasoning: Nothing else to check." in out


def test_run_tool_loop_marks_errored_tool_calls_in_live_output(capsys):
    class _ErrorSession:
        async def call_tool(self, name, tool_input, read_timeout_seconds=None):
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps({"error": "boom"}))], is_error=True)

    turns = [
        ModelResponse(
            text="", tool_calls=[ToolCall(id="c1", name="nmap", input={})], stop_reason="tool_use", usage=Usage()
        ),
        ModelResponse(text="done", tool_calls=[], stop_reason="end_turn", usage=Usage()),
    ]
    adapter = _ScriptedAdapter(turns)
    asyncio.run(
        agent_core.run_tool_loop(adapter, _ErrorSession(), {}, "sys", [], "go", 10, 5, hitl_mode="auto", label="exploit:f1")
    )
    out = capsys.readouterr().out
    assert "[exploit:f1] <- nmap [ERROR]:" in out


def test_run_tool_loop_no_label_omits_prefix(capsys):
    turns = [ModelResponse(text="hi", tool_calls=[], stop_reason="end_turn", usage=Usage())]
    adapter = _ScriptedAdapter(turns)
    asyncio.run(agent_core.run_tool_loop(adapter, _NoOpSession(), {}, "sys", [], "go", 10, 5, hitl_mode="auto"))
    out = capsys.readouterr().out
    assert out.startswith("reasoning: hi")


def test_run_tool_loop_persists_events_to_log_path(tmp_path):
    log_path = str(tmp_path / "run.jsonl")
    adapter = _ScriptedAdapter(_turns_with_one_tool_call())
    asyncio.run(
        agent_core.run_tool_loop(
            adapter, _NoOpSession(), {}, "sys", [], "go", 10, 5, hitl_mode="auto", label="recon", log_path=log_path
        )
    )
    events = [json.loads(line) for line in open(log_path, encoding="utf-8").read().splitlines()]
    types = [e["type"] for e in events]
    assert types == ["reasoning", "tool_call", "reasoning"]
    assert events[1]["tool"] == "http_request"
    assert events[1]["output"] == {"ok": True}
    assert all(e["label"] == "recon" for e in events)


def test_run_tool_loop_without_log_path_writes_no_file(tmp_path):
    # Sanity check: log_path is opt-in, not a side effect that always fires.
    adapter = _ScriptedAdapter([ModelResponse(text="hi", tool_calls=[], stop_reason="end_turn", usage=Usage())])
    asyncio.run(agent_core.run_tool_loop(adapter, _NoOpSession(), {}, "sys", [], "go", 10, 5, hitl_mode="auto"))
    assert list(tmp_path.iterdir()) == []


# --- slugify / new_run_log_path ---------------------------------------------


def test_slugify_strips_scheme_and_special_chars():
    assert agent_core.slugify("http://192.168.56.5:8080/path") == "192-168-56-5-8080-path"


def test_slugify_empty_falls_back_to_target():
    assert agent_core.slugify("http://") == "target"


def test_new_run_log_path_creates_logs_dir_and_returns_jsonl_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = agent_core.new_run_log_path("192.168.56.5", logs_dir="logs")
    assert path.startswith("logs" + os.sep) or path.startswith("logs/")
    assert path.endswith(".jsonl")
    assert os.path.isdir("logs")

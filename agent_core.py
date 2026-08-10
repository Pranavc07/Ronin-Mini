"""Shared MCP + Claude tool-calling loop mechanics.

Every agent in this repo (the legacy single-agent loop.py, recon_agent,
exploit_agent) is a thin wrapper around the same core: connect to the Ronin
MCP tool server, run a Claude<->tool conversation with hard caps, return a
transcript. This module is that core, extracted once so the three agents
don't carry three slowly-drifting copies of the same ~150 lines.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client  # noqa: F401  (re-exported for callers)

TOOL_TIMEOUT_SECONDS = 15

FINDING_START = "<<<FINDING>>>"
FINDING_END = "<<<END_FINDING>>>"

_REPO_ROOT = os.path.dirname(os.path.realpath(__file__))
_MCP_SERVER_PATH = os.path.join(_REPO_ROOT, "ronin-tools-mcp", "server.py")
AGENTS_DIR = os.path.join(_REPO_ROOT, "agents")
SKILLS_DIR = os.path.join(_REPO_ROOT, "skills")

_TOOLS_DIR = os.path.join(_REPO_ROOT, "ronin-tools-mcp")
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from manifest import DEFAULT_TIMEOUT_SECONDS, ToolMeta, load_manifest  # noqa: E402


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_agent_prompt(name: str) -> str:
    """Load a role prompt from agents/{name}.md. This is a format() template --
    callers fill {target}, {tool_schemas}, etc. exactly as the old hardcoded
    SYSTEM_PROMPT_TEMPLATE strings did. Kept as .format() so externalizing the
    prompt is a pure move with no behavior change.
    """
    with open(os.path.join(AGENTS_DIR, f"{name}.md"), "r", encoding="utf-8") as f:
        return f.read()


def load_skill(finding_type: str) -> str | None:
    """Return the raw markdown of skills/{finding_type}.md, or None if no file
    matches. The returned text is appended to an already-formatted prompt as a
    literal string -- it is NOT run through str.format(), so skill files can
    contain braces (payloads, JSON, SSTI like {{7*7}}) freely. Returning None
    is the explicit "no skill matched, fall back to base reasoning" signal.
    """
    if not finding_type:
        return None
    path = os.path.join(SKILLS_DIR, f"{finding_type}.md")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def mcp_server_params(
    scope_dir: str, allowed_hosts: list[str], findings_path: str | None = None
) -> StdioServerParameters:
    args = [_MCP_SERVER_PATH, "--scope-dir", scope_dir]
    for host in allowed_hosts:
        args += ["--allowed-host", host]
    # Only the verify agent's replay_probe needs the findings file server-side;
    # the other agents spawn the server without it and it's simply unused.
    if findings_path is not None:
        args += ["--findings-path", findings_path]
    return StdioServerParameters(command=sys.executable, args=args)


_MANIFEST_CACHE: dict[str, ToolMeta] | None = None


def _tool_read_timeout(name: str) -> float:
    """Per-tool client-side read timeout, derived from the manifest's own
    per-tool timeout (+ margin) so a legitimately slow tool (execute_python's
    Docker spin-up, replay_probe re-running several calls) isn't killed by a
    flat 15s cap. Falls back to TOOL_TIMEOUT_SECONDS for unknown tools.
    """
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is None:
        _MANIFEST_CACHE = load_manifest()
    meta = _MANIFEST_CACHE.get(name)
    if meta is None:
        return TOOL_TIMEOUT_SECONDS
    return max(TOOL_TIMEOUT_SECONDS, meta.timeout_seconds + 5)


def mcp_tools_to_anthropic_schema(mcp_tools: list) -> list[dict]:
    """Convert MCP Tool objects (session.list_tools().tools) into the shape
    the Anthropic Messages API's `tools=` parameter expects. MCP's
    `input_schema` field name already matches Anthropic's -- no reshaping
    needed there, just picking the three fields Anthropic cares about.
    """
    return [
        {
            "name": t.name,
            "description": (t.description or "").strip(),
            "input_schema": t.input_schema,
        }
        for t in mcp_tools
    ]


def filter_tools_by_category(mcp_tools: list, manifest: dict[str, ToolMeta], allowed_categories: set[str]) -> list:
    """Client-side allowlist: an agent only gets tools whose manifest.yaml
    category is in allowed_categories. The server exposes everything; each
    agent decides what it's allowed to reach for.
    """
    allowed_names = {name for name, meta in manifest.items() if meta.category in allowed_categories}
    return [t for t in mcp_tools if t.name in allowed_names]


async def execute_tool(session: ClientSession, name: str, tool_input: dict) -> tuple[dict, bool]:
    """Call a tool through the MCP session with a hard per-call timeout.

    Returns (output_dict, is_error). Tool-level failures (bad URL, path
    traversal, scope violation) come back as {"error": "..."} payloads from
    the server -- normal data the model should see and reason about, not an
    exception.
    """
    try:
        result = await session.call_tool(name, tool_input, read_timeout_seconds=_tool_read_timeout(name))
    except Exception as e:  # noqa: BLE001 -- MCP transport/timeout errors, connection drops, etc.
        return {"error": f"MCP call to '{name}' failed: {type(e).__name__}: {e}"}, True

    text_parts = [block.text for block in result.content if getattr(block, "type", None) == "text"]
    raw_text = "\n".join(text_parts)

    if not raw_text:
        return {"error": f"Tool '{name}' returned no content"}, True

    try:
        output = json.loads(raw_text)
    except json.JSONDecodeError:
        output = {"raw": raw_text}

    is_error = bool(result.is_error) or (isinstance(output, dict) and "error" in output)
    return output, is_error


def extract_blocks(text: str, start_marker: str, end_marker: str) -> list[dict]:
    """Pull every {start_marker}...JSON...{end_marker} block out of text and
    parse it. Skips anything that isn't valid JSON rather than raising --
    a malformed block shouldn't take down the run. Generic over the marker
    pair so different agents can use different block types (findings,
    exploit verdicts) without duplicating the parsing logic.
    """
    pattern = re.compile(re.escape(start_marker) + r"(.*?)" + re.escape(end_marker), re.DOTALL)
    blocks = []
    for raw in pattern.findall(text or ""):
        try:
            obj = json.loads(raw.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            blocks.append(obj)
    return blocks


async def run_tool_loop(
    anthropic_client,
    session: ClientSession,
    model: str,
    system_prompt: str,
    tool_defs: list[dict],
    initial_message: str,
    max_iterations: int,
    max_minutes: float,
    max_tokens: int = 4096,
    extract_markers: tuple[str, str] | None = None,
) -> dict:
    """Run one Claude<->tool conversation until the model stops calling
    tools or a cap is hit. This is the mechanics every agent in this repo
    shares -- what differs per agent is the system prompt, the tool
    allowlist, and what it does with the result afterward.

    Returns {transcript, extracted_blocks, tool_call_count, stop_reason}.
    extracted_blocks is populated only if extract_markers is given.
    """
    messages = [{"role": "user", "content": initial_message}]
    transcript: list[dict] = []
    extracted_blocks: list[dict] = []
    start_time = time.monotonic()
    tool_call_count = 0
    stop_reason_final = "unknown"

    while True:
        elapsed_minutes = (time.monotonic() - start_time) / 60.0
        if elapsed_minutes >= max_minutes:
            stop_reason_final = "wall_clock_cap"
            break
        if tool_call_count >= max_iterations:
            stop_reason_final = "iteration_cap"
            break

        async with anthropic_client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            tools=tool_defs,
            messages=messages,
        ) as stream:
            async for _ in stream:
                pass
            response = await stream.get_final_message()

        assistant_text = "\n".join(block.text for block in response.content if block.type == "text")
        if extract_markers:
            extracted_blocks.extend(extract_blocks(assistant_text, *extract_markers))

        messages.append({"role": "assistant", "content": response.content})

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

        if not tool_use_blocks:
            stop_reason_final = response.stop_reason or "end_turn"
            break

        tool_results = []
        for block in tool_use_blocks:
            if tool_call_count >= max_iterations:
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": "Iteration cap reached; tool not executed.",
                        "is_error": True,
                    }
                )
                continue

            tool_call_count += 1
            call_started = _now_iso()
            output, is_error = await execute_tool(session, block.name, block.input)
            transcript.append(
                {
                    "timestamp": call_started,
                    "tool": block.name,
                    "input": block.input,
                    "output": output,
                    "model_reasoning_text": assistant_text,
                }
            )
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(output),
                    "is_error": is_error,
                }
            )

        messages.append({"role": "user", "content": tool_results})

        if tool_call_count >= max_iterations:
            stop_reason_final = "iteration_cap"
            break

    return {
        "transcript": transcript,
        "extracted_blocks": extracted_blocks,
        "tool_call_count": tool_call_count,
        "stop_reason": stop_reason_final,
    }

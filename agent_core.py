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
from dataclasses import dataclass, field
from datetime import datetime, timezone

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client  # noqa: F401  (re-exported for callers)

from models import ModelAdapter, ToolResult, Turn, Usage  # noqa: E402

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


def slugify(value: str) -> str:
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-")
    return value[:60] or "target"


def new_run_log_path(target: str, logs_dir: str = "logs") -> str:
    """A fresh, timestamped path for this run's live JSONL log (see
    run_tool_loop's label/log_path params) -- one file for the whole
    recon->exploit->verify pipeline, or a single-agent run.
    """
    os.makedirs(logs_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(logs_dir, f"run_{slugify(target)}_{timestamp}.jsonl")


def _short(text: str, limit: int) -> str:
    """Collapse to one line and truncate for terminal-friendly live output.
    Full, untruncated content still goes to the JSONL log via _append_log.
    """
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [+{len(text) - limit} chars]"


def _live_print(label: str, message: str) -> None:
    prefix = f"[{label}] " if label else ""
    print(f"{prefix}{message}", flush=True)


def _append_log(log_path: str | None, event: dict) -> None:
    """Append one JSON line to the run's live log file, if one is configured.
    Opened/closed per call rather than holding a shared handle open across
    the whole (possibly hours-long, multi-stage) run -- simpler lifecycle,
    negligible overhead at the volumes a single run produces, and a run that
    crashes mid-way still leaves every event up to that point on disk.
    """
    if not log_path:
        return
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str) + "\n")


def load_agent_prompt(name: str) -> str:
    """Load a role prompt from agents/{name}.md. This is a format() template --
    callers fill {target}, {tool_schemas}, etc. exactly as the old hardcoded
    SYSTEM_PROMPT_TEMPLATE strings did. Kept as .format() so externalizing the
    prompt is a pure move with no behavior change.
    """
    with open(os.path.join(AGENTS_DIR, f"{name}.md"), "r", encoding="utf-8") as f:
        return f.read()


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?\n)---\s*\n?", re.DOTALL)


@dataclass(frozen=True)
class SkillDoc:
    """A parsed skills/{type}.md file: YAML frontmatter metadata (status,
    cwe, attack_technique, attack_tactic) plus the markdown body. `body` is
    still meant to be appended to an already-formatted prompt as a literal
    string -- it is NOT run through str.format(), so skill files can contain
    braces (payloads, JSON, SSTI like {{7*7}}) freely.
    """

    metadata: dict = field(default_factory=dict)
    body: str = ""


def load_skill(finding_type: str) -> SkillDoc | None:
    """Return the parsed skills/{finding_type}.md, or None if no file
    matches. Returning None is the explicit "no skill matched, fall back to
    base reasoning" signal -- distinct from a matched file whose
    metadata["status"] is "stub" (a file exists but has no real hand-authored
    methodology yet).
    """
    if not finding_type:
        return None
    path = os.path.join(SKILLS_DIR, f"{finding_type}.md")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    match = _FRONTMATTER_RE.match(raw)
    if not match:
        return SkillDoc(metadata={}, body=raw)

    metadata = yaml.safe_load(match.group(1)) or {}
    body = raw[match.end():]
    return SkillDoc(metadata=metadata, body=body)


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


HITL_MODES = ("auto", "manual", "plan")


def confirm_plan_for_run(gated_tool_names: set[str]) -> bool:
    """The one-shot approval used by hitl_mode == "plan": asked once, before
    the first gated tool call of a run_tool_loop invocation (one finding's
    investigation for exploit_agent/verify_agent; the whole run for
    recon_agent/the legacy single-agent loop, which have no per-finding
    boundary). The answer governs every gated call for the rest of that run
    -- no further prompts until the next run_tool_loop call starts fresh.
    """
    print(f"\n[HITL] This run may call gated tools: {', '.join(sorted(gated_tool_names))}")
    try:
        choice = input("Approve gated tool calls for this entire run? [y/n]: ").strip().lower()
    except EOFError:
        print("[HITL] No interactive stdin available; denying by default.")
        return False
    return choice in ("y", "yes")


def confirm_tool_call(name: str, tool_input: dict, manifest: dict[str, ToolMeta]) -> tuple[bool, dict]:
    """The HITL approval gate for hitl_mode == "manual": one prompt per
    gated tool call. Auto-approves (no prompt) unless the tool's category
    defaults to require_approval: true in manifest.yaml. Blocks on stdin --
    this harness runs one turn at a time with no concurrent async work
    competing for the event loop, so a blocking input() inside the async
    loop is the simplest thing that satisfies "CLI-based, blocks on stdin,
    no dashboard needed".

    Returns (approved, final_input) -- final_input is tool_input unchanged
    unless the operator chose to edit it.
    """
    meta = manifest.get(name)
    if meta is None or not meta.require_approval:
        return True, tool_input

    print(f"\n[HITL] Tool call requires approval: {name}")
    print(json.dumps(tool_input, indent=2))
    try:
        choice = input("Approve this tool call? [y/n/edit]: ").strip().lower()
    except EOFError:
        # Non-interactive stdin (e.g. a CI subprocess with no TTY) -- fail
        # safe by denying rather than crashing the run.
        print("[HITL] No interactive stdin available; denying by default.")
        return False, tool_input

    if choice in ("y", "yes"):
        return True, tool_input
    if choice in ("edit", "e"):
        raw = input("Enter replacement JSON input (blank to deny): ").strip()
        if not raw:
            return False, tool_input
        try:
            edited = json.loads(raw)
        except json.JSONDecodeError:
            print("[HITL] Invalid JSON; denying this tool call.")
            return False, tool_input
        return True, edited
    return False, tool_input


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
    model_adapter: ModelAdapter,
    session: ClientSession,
    manifest: dict[str, ToolMeta],
    system_prompt: str,
    tool_defs: list[dict],
    initial_message: str,
    max_iterations: int,
    max_minutes: float,
    max_tokens: int = 4096,
    extract_markers: tuple[str, str] | None = None,
    hitl_mode: str = "manual",
    label: str = "",
    log_path: str | None = None,
) -> dict:
    """Run one model<->tool conversation until the model stops calling tools
    or a cap is hit. This is the mechanics every agent in this repo shares --
    what differs per agent is the system prompt, the tool allowlist, and what
    it does with the result afterward.

    hitl_mode controls the approval gate for require_approval tools:
      - "auto": never prompt, every tool call executes immediately.
      - "manual": confirm_tool_call() prompts on every gated call.
      - "plan": one confirm_plan_for_run() prompt before the first gated call
        this run makes; that decision governs every gated call for the rest
        of this run_tool_loop invocation (one finding, for exploit/verify).

    label prefixes every live-printed line (e.g. "recon", "exploit:f3") so a
    terminal watching the whole recon->exploit->verify pipeline can tell
    which stage/finding a line belongs to. Every model turn's reasoning text
    and every tool call/result prints immediately (flushed) as it happens --
    this is what makes a run's progress visible in real time instead of
    going silent until the stage finishes. log_path, if given, gets the same
    events appended as JSON lines (one per event) for a persistent, replayable
    record of the whole run, including recon's own reasoning -- previously
    discarded once recon returned only its extracted findings.

    Returns {transcript, extracted_blocks, tool_call_count, stop_reason, usage}.
    extracted_blocks is populated only if extract_markers is given. usage is
    the summed token usage (input/output/cache) across every model call this
    invocation made -- see models.Usage / models.estimate_cost_usd to turn it
    into a dollar figure.
    """
    assert hitl_mode in HITL_MODES, f"unknown hitl_mode {hitl_mode!r}, expected one of {HITL_MODES}"

    messages: list[Turn] = [Turn(role="user", text=initial_message)]
    transcript: list[dict] = []
    extracted_blocks: list[dict] = []
    start_time = time.monotonic()
    tool_call_count = 0
    stop_reason_final = "unknown"
    total_usage = Usage()
    plan_decision: bool | None = None  # only used when hitl_mode == "plan"
    gated_tool_names = {t["name"] for t in tool_defs if (manifest.get(t["name"]) or None) and manifest[t["name"]].require_approval}

    while True:
        elapsed_minutes = (time.monotonic() - start_time) / 60.0
        if elapsed_minutes >= max_minutes:
            stop_reason_final = "wall_clock_cap"
            break
        if tool_call_count >= max_iterations:
            stop_reason_final = "iteration_cap"
            break

        response = await model_adapter.send_messages(system_prompt, messages, tool_defs, max_tokens)
        total_usage = total_usage + response.usage

        assistant_text = response.text
        if assistant_text.strip():
            _live_print(label, f"reasoning: {_short(assistant_text, 400)}")
            _append_log(
                log_path,
                {"timestamp": _now_iso(), "label": label, "type": "reasoning", "text": assistant_text},
            )
        if extract_markers:
            extracted_blocks.extend(extract_blocks(assistant_text, *extract_markers))

        messages.append(Turn(role="assistant", text=assistant_text, tool_calls=response.tool_calls))

        if not response.tool_calls:
            stop_reason_final = response.stop_reason or "end_turn"
            break

        tool_results: list[ToolResult] = []
        for call in response.tool_calls:
            if tool_call_count >= max_iterations:
                tool_results.append(
                    ToolResult(
                        tool_call_id=call.id,
                        content="Iteration cap reached; tool not executed.",
                        is_error=True,
                    )
                )
                continue

            tool_call_count += 1
            call_started = _now_iso()
            _live_print(label, f"-> {call.name}({_short(json.dumps(call.input, default=str), 200)})")

            if hitl_mode == "auto":
                approved, final_input = True, call.input
            elif hitl_mode == "plan":
                meta = manifest.get(call.name)
                if meta is None or not meta.require_approval:
                    approved, final_input = True, call.input
                else:
                    if plan_decision is None:
                        plan_decision = confirm_plan_for_run(gated_tool_names)
                    approved, final_input = plan_decision, call.input
            else:  # "manual"
                approved, final_input = confirm_tool_call(call.name, call.input, manifest)

            if not approved:
                output = {"error": "Tool call denied by operator (HITL gate)."}
                is_error = True
            else:
                output, is_error = await execute_tool(session, call.name, final_input)

            status = "ERROR" if is_error else "ok"
            _live_print(label, f"<- {call.name} [{status}]: {_short(json.dumps(output, default=str), 250)}")
            _append_log(
                log_path,
                {
                    "timestamp": call_started,
                    "label": label,
                    "type": "tool_call",
                    "tool": call.name,
                    "input": final_input,
                    "output": output,
                    "is_error": is_error,
                },
            )

            transcript.append(
                {
                    "timestamp": call_started,
                    "tool": call.name,
                    "input": final_input,
                    "output": output,
                    "model_reasoning_text": assistant_text,
                }
            )
            tool_results.append(ToolResult(tool_call_id=call.id, content=json.dumps(output), is_error=is_error))

        messages.append(Turn(role="user", tool_results=tool_results))

        if tool_call_count >= max_iterations:
            stop_reason_final = "iteration_cap"
            break

    return {
        "transcript": transcript,
        "extracted_blocks": extracted_blocks,
        "tool_call_count": tool_call_count,
        "stop_reason": stop_reason_final,
        "usage": total_usage.as_dict(),
    }

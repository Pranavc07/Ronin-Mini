"""Single-agent entry point -- the original Ronin-Mini loop, now a thin
wrapper over agent_core.run_tool_loop. Kept as-is for continuity: same
external behavior as before the recon/exploit split, just delegating the
shared mechanics instead of owning a private copy of them.
"""

import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.stdio import stdio_client

import agent_core
import models

SYSTEM_PROMPT_TEMPLATE = """You are an authorized penetration testing assistant. You have \
been explicitly engaged to test the target below for security vulnerabilities. All testing \
is authorized and in-scope; the operator has confirmed they own this target or have written \
permission to test it.

TARGET: {target}
OBJECTIVE: {objective}

You have access to the following tools, available via native tool use:

{tool_schemas}

Rules:
- Only interact with the stated target. Do not pivot to unrelated hosts -- network tools
  will refuse any host outside the allowed scope regardless of what you ask for.
- code_search and file_read are scoped to a local directory ({scope_dir}) and cannot escape it.
- Reason step by step: form a hypothesis, use a tool to test it, interpret the result, and \
decide the next step.
- Whenever you identify a genuine vulnerability or noteworthy security finding, emit it \
immediately using EXACTLY this format (raw JSON between the markers, no markdown fences):

{finding_start}
{{"title": "...", "severity": "critical|high|medium|low|info", "evidence": "...", \
"reproduction_steps": ["step 1", "step 2", "..."]}}
{finding_end}

  You may include this block inline with your normal reasoning text, then continue working.
- Stop calling tools and end your turn once you have reasonably exhausted useful lines of \
investigation for the objective, or explain why you cannot proceed further.
"""


def build_system_prompt(target: str, objective: str, scope_dir: str, tool_defs: list[dict]) -> str:
    return SYSTEM_PROMPT_TEMPLATE.format(
        target=target,
        objective=objective,
        scope_dir=scope_dir,
        tool_schemas=json.dumps(tool_defs, indent=2),
        finding_start=agent_core.FINDING_START,
        finding_end=agent_core.FINDING_END,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def run_agent(
    target: str,
    objective: str,
    scope_dir: str,
    model: str,
    provider: str = "anthropic",
    hitl_mode: str = "auto",
    max_iterations: int = 40,
    max_minutes: float = 20.0,
    max_tokens: int = 4096,
    allowed_hosts: list[str] | None = None,
    log_path: str | None = None,
) -> dict:
    if allowed_hosts is None:
        allowed_hosts = [urlparse(target).hostname or target]

    model_adapter = models.build_adapter(provider, model)
    server_params = agent_core.mcp_server_params(scope_dir, allowed_hosts)
    started_at = _now_iso()

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            manifest = agent_core.load_manifest()
            tool_defs = agent_core.mcp_tools_to_anthropic_schema(tools_result.tools)

            system_prompt = build_system_prompt(target, objective, scope_dir, tool_defs)
            initial_message = f"Begin the authorized security assessment of {target}. Objective: {objective}"

            result = await agent_core.run_tool_loop(
                model_adapter,
                session,
                manifest,
                system_prompt,
                tool_defs,
                initial_message,
                max_iterations,
                max_minutes,
                max_tokens,
                extract_markers=(agent_core.FINDING_START, agent_core.FINDING_END),
                hitl_mode=hitl_mode,
                label="agent",
                log_path=log_path,
            )

    ended_at = _now_iso()
    findings = [
        {"timestamp": _now_iso(), **block} for block in result["extracted_blocks"] if "title" in block
    ]

    return {
        "metadata": {
            "target": target,
            "objective": objective,
            "scope_dir": scope_dir,
            "allowed_hosts": allowed_hosts,
            "model": model,
            "max_iterations": max_iterations,
            "max_minutes": max_minutes,
            "started_at": started_at,
            "ended_at": ended_at,
            "tool_call_count": result["tool_call_count"],
            "stop_reason": result["stop_reason"],
            "usage": result["usage"],
        },
        "transcript": result["transcript"],
        "findings": findings,
    }

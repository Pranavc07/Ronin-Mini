"""recon_agent: explores the target using recon + fileops tools only, and
writes structured candidate findings to findings.json for exploit_agent to
pick up. Does not attempt exploitation itself -- that's exploit_agent's job.
"""

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.stdio import stdio_client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import agent_core  # noqa: E402
import models  # noqa: E402

ALLOWED_CATEGORIES = {"recon", "fileops", "network_exploit"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_system_prompt(target: str, objective: str, tool_defs: list[dict]) -> str:
    # Role prompt lives in agents/recon.md now (loaded as a format() template).
    return agent_core.load_agent_prompt("recon").format(
        target=target,
        objective=objective,
        tool_schemas=json.dumps(tool_defs, indent=2),
        finding_start=agent_core.FINDING_START,
        finding_end=agent_core.FINDING_END,
    )


def _write_findings(findings_path: str, findings: list[dict]) -> None:
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f, indent=2)


async def run_recon_agent(
    target: str,
    objective: str,
    scope_dir: str,
    model: str,
    findings_path: str,
    provider: str = "anthropic",
    hitl_mode: str = "auto",
    max_iterations: int = 40,
    max_minutes: float = 20.0,
    max_tokens: int = 4096,
    allowed_hosts: list[str] | None = None,
) -> dict:
    if allowed_hosts is None:
        allowed_hosts = [urlparse(target).hostname or target]

    model_adapter = models.build_adapter(provider, model)
    server_params = agent_core.mcp_server_params(scope_dir, allowed_hosts)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            manifest = agent_core.load_manifest()
            allowed_tools = agent_core.filter_tools_by_category(
                tools_result.tools, manifest, ALLOWED_CATEGORIES
            )
            tool_defs = agent_core.mcp_tools_to_anthropic_schema(allowed_tools)

            system_prompt = build_system_prompt(target, objective, tool_defs)
            initial_message = f"Begin reconnaissance against {target}. Objective: {objective}"

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
            )

    findings = []
    for i, block in enumerate(result["extracted_blocks"], start=1):
        if "type" not in block or "target" not in block:
            continue
        findings.append(
            {
                "id": f"f{i}",
                "type": block["type"],
                "target": block["target"],
                "evidence": block.get("evidence", ""),
                "status": "new",
                "discovered_by": "recon-agent",
                "exploit_attempts": [],
            }
        )

    _write_findings(findings_path, findings)

    return {
        "metadata": {
            "target": target,
            "objective": objective,
            "model": model,
            "tool_call_count": result["tool_call_count"],
            "stop_reason": result["stop_reason"],
            "usage": result["usage"],
        },
        "transcript": result["transcript"],
        "findings_path": findings_path,
        "findings_count": len(findings),
    }

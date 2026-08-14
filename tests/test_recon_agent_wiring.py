"""Wiring tests confirming recon_agent has real agent-level access to the
network_exploit toolset (the fix for the gap surfaced by the Metasploitable
live check: recon previously had no path to ever produce a finding that
would reach nmap/hydra/etc.). Spins up the real MCP server, no API key or
Kali container needed -- this only checks tool *visibility*, not execution.

Run with: pytest tests/test_recon_agent_wiring.py -v
"""

import asyncio
import os
import sys

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

import agent_core  # noqa: E402
import recon_agent.loop as recon_loop  # noqa: E402
import exploit_agent.loop as exploit_loop  # noqa: E402

NETWORK_EXPLOIT_TOOLS = {"nmap", "nikto", "sqlmap", "hydra", "gobuster", "enum4linux", "searchsploit"}


def test_recon_agent_allowed_categories_include_network_exploit():
    assert "network_exploit" in recon_loop.ALLOWED_CATEGORIES
    assert "recon" in recon_loop.ALLOWED_CATEGORIES
    assert "fileops" in recon_loop.ALLOWED_CATEGORIES


def test_exploit_agent_still_has_network_exploit_too():
    assert "network_exploit" in exploit_loop.ALLOWED_CATEGORIES


async def _list_allowed_tool_names(scope_dir: str, categories: set[str]) -> set[str]:
    server_params = agent_core.mcp_server_params(scope_dir, ["localhost"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            manifest = agent_core.load_manifest()
            allowed = agent_core.filter_tools_by_category(tools_result.tools, manifest, categories)
            return {t.name for t in allowed}


def test_recon_agent_actually_sees_all_seven_kali_tools(tmp_path):
    names = asyncio.run(_list_allowed_tool_names(str(tmp_path), recon_loop.ALLOWED_CATEGORIES))
    assert NETWORK_EXPLOIT_TOOLS.issubset(names), names
    assert {"http_request", "dns_lookup"}.issubset(names)


def test_verify_agent_still_isolated():
    import verify_agent.loop as verify_loop

    assert verify_loop.ALLOWED_CATEGORIES == {"verify"}

"""End-to-end tests for the Ronin MCP tool server: spins up the real server
as a subprocess over stdio and exercises it through a real MCP ClientSession,
so this covers the actual wiring (server.py, categories/*, scope.py,
executor.py) rather than just the isolated Scope class.

No network access to third-party hosts, no Anthropic API key needed --
dns_lookup against "localhost" resolves locally, and the http_request checks
below never get far enough to send a real request when they're scope
violations.

Run with: pytest tests/test_mcp_server.py -v -s
"""

import asyncio
import os
import shutil
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SERVER_PATH = os.path.join(_REPO_ROOT, "ronin-tools-mcp", "server.py")
RG_AVAILABLE = shutil.which("rg") is not None


async def _connect(scope_dir: str, allowed_hosts: list[str]):
    params = StdioServerParameters(
        command=sys.executable,
        args=[_SERVER_PATH, "--scope-dir", scope_dir]
        + [arg for host in allowed_hosts for arg in ("--allowed-host", host)],
    )
    return stdio_client(params)


async def _call(session: ClientSession, name: str, arguments: dict) -> dict:
    import json

    result = await session.call_tool(name, arguments, read_timeout_seconds=15)
    text = "\n".join(b.text for b in result.content if getattr(b, "type", None) == "text")
    return json.loads(text)


async def _run_full_flow(scope_dir: str):
    async with await _connect(scope_dir, ["localhost"]) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # --- tool discovery ---
            tools_result = await session.list_tools()
            names = {t.name for t in tools_result.tools}
            assert names == {
                "http_request",
                "dns_lookup",
                "code_search",
                "file_read",
                "probe_variant",
                "execute_python",
                "replay_probe",
            }

            # --- fileops: within scope ---
            result = await _call(session, "file_read", {"path": "inside.txt"})
            assert result.get("content") == "safe content", result

            # --- fileops: traversal blocked ---
            result = await _call(session, "file_read", {"path": os.path.join("..", "outside", "secret.txt")})
            assert "error" in result
            assert "secret" not in result.get("content", "")

            # --- fileops: code_search traversal blocked (before rg ever runs) ---
            result = await _call(
                session, "code_search", {"pattern": "secret", "path": os.path.join("..", "outside")}
            )
            assert "error" in result

            if RG_AVAILABLE:
                result = await _call(session, "code_search", {"pattern": "safe", "path": "."})
                assert "error" not in result, result
                assert result["match_count"] >= 1

            # --- recon: dns_lookup, allowed host ---
            result = await _call(session, "dns_lookup", {"hostname": "localhost"})
            assert "error" not in result, result
            assert result["records"].get("A") or result["records"].get("AAAA")

            # --- recon: dns_lookup, disallowed host blocked before any lookup happens ---
            result = await _call(session, "dns_lookup", {"hostname": "evil.example.org"})
            assert "error" in result
            assert "outside the allowed scope" in result["error"]

            # --- recon: http_request, disallowed host blocked before any request is sent ---
            result = await _call(session, "http_request", {"method": "GET", "url": "http://evil.example.org/"})
            assert "error" in result
            assert "outside the allowed scope" in result["error"]


def test_mcp_server_full_flow(tmp_path):
    root = tmp_path / "scope"
    root.mkdir()
    (root / "inside.txt").write_text("safe content")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("top secret")

    asyncio.run(_run_full_flow(str(root)))

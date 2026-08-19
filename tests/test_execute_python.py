"""End-to-end tests for the execute_python sandbox tool: spins up the real
MCP server and runs real Docker containers. Skipped automatically if Docker
isn't available.

Slower than the other test files (each case builds/runs a container) --
run on its own when iterating: pytest tests/test_execute_python.py -v -s

Requires the Ronin harness's own Juice Shop test instance for the network
happy-path case (see README) -- that case is skipped if localhost:3000
isn't reachable, same spirit as test_e2e.py's ANTHROPIC_API_KEY skip.
"""

import asyncio
import json
import os
import shutil
import sys
import urllib.request

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ronin_mini import agent_core  # noqa: E402

DOCKER_AVAILABLE = shutil.which("docker") is not None


def _juice_shop_available() -> bool:
    try:
        urllib.request.urlopen("http://localhost:3000", timeout=2)
        return True
    except Exception:
        return False


async def _call(session: ClientSession, name: str, arguments: dict) -> dict:
    result = await session.call_tool(name, arguments, read_timeout_seconds=30)
    text = "\n".join(b.text for b in result.content if getattr(b, "type", None) == "text")
    return json.loads(text)


async def _run_checks(scope_dir: str, juice_shop_available: bool):
    params = agent_core.mcp_server_params(scope_dir, ["localhost"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # --- filesystem isolation: root FS read-only, scratch dir writable ---
            code = """
try:
    with open("/etc/ronin_write_test", "w") as f:
        f.write("should fail")
    print("WRITE_TO_ROOT_SUCCEEDED")
except OSError:
    print("WRITE_TO_ROOT_BLOCKED")
with open("evidence.txt", "w") as f:
    f.write("ok")
print("SCRATCH_WRITE_OK")
"""
            result = await _call(session, "execute_python", {"code": code, "timeout": 20})
            assert result.get("returncode") == 0, result
            assert "WRITE_TO_ROOT_BLOCKED" in result["stdout"]
            assert "WRITE_TO_ROOT_SUCCEEDED" not in result["stdout"]
            assert "SCRATCH_WRITE_OK" in result["stdout"]

            # --- scope enforcement via the injected ronin_target helper ---
            code = """
from ronin_target import request
try:
    request("GET", "http://evil.example.org/")
    print("SCOPE_BYPASSED")
except Exception as e:
    print("SCOPE_BLOCKED:", type(e).__name__)
"""
            result = await _call(session, "execute_python", {"code": code, "timeout": 20})
            assert "SCOPE_BLOCKED: ScopeError" in result["stdout"]
            assert "SCOPE_BYPASSED" not in result["stdout"]

            # --- timeout enforcement ---
            code = "import time\ntime.sleep(30)\n"
            result = await _call(session, "execute_python", {"code": code, "timeout": 3})
            assert "error" in result
            assert "timed out" in result["error"]

            # --- happy path: real network call through the scope-checked helper ---
            if juice_shop_available:
                code = """
from ronin_target import request
r = request("GET", "http://localhost:3000")
print("STATUS", r.status_code)
"""
                result = await _call(session, "execute_python", {"code": code, "timeout": 20})
                assert result.get("returncode") == 0, result
                assert "STATUS 200" in result["stdout"]


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="docker not installed or not on PATH")
def test_execute_python_sandbox(tmp_path):
    asyncio.run(_run_checks(str(tmp_path), _juice_shop_available()))

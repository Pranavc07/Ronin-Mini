#!/usr/bin/env python3
"""Ronin MCP tool server -- exposes the recon/fileops/web_exploit tools over
stdio to any MCP client.

Run directly (this is what loop.py spawns as a subprocess):
    python server.py --scope-dir <path> --allowed-host <host> [--allowed-host <host> ...]
"""

from __future__ import annotations

import argparse
import os
import sys

# Run as a plain script, not an installed package -- put this directory on
# sys.path so `import manifest`, `import scope`, etc. resolve regardless of
# the caller's own working directory.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from mcp.server.mcpserver import MCPServer  # noqa: E402

import executor  # noqa: E402
from manifest import load_manifest  # noqa: E402
from scope import Scope  # noqa: E402
from categories import attack_reference, exploit_runtime, fileops, network_exploit, recon, verify, web_exploit  # noqa: E402


def build_server(scope_dir: str, allowed_hosts: list[str], findings_path: str | None = None) -> MCPServer:
    manifest = load_manifest()
    timeouts = {name: meta.timeout_seconds for name, meta in manifest.items()}
    scope = Scope(scope_dir=scope_dir, allowed_hosts=allowed_hosts)

    mcp = MCPServer("ronin-tools")
    recon.register(mcp, scope, executor, timeouts)
    fileops.register(mcp, scope, executor, timeouts)
    web_exploit.register(mcp, scope, executor, timeouts)
    exploit_runtime.register(mcp, scope, executor, timeouts)
    # verify.register takes findings_path (its replay_probe reads the winning
    # attempt from there); the uniform register() signature doesn't carry it.
    verify.register(mcp, scope, executor, timeouts, findings_path)
    network_exploit.register(mcp, scope, executor, timeouts)
    attack_reference.register(mcp, scope, executor, timeouts)
    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Ronin MCP tool server")
    parser.add_argument(
        "--scope-dir", required=True, help="Directory that fileops tools are sandboxed to"
    )
    parser.add_argument(
        "--allowed-host",
        action="append",
        required=True,
        help="Host allowed for network tools (repeatable for multiple hosts)",
    )
    parser.add_argument(
        "--findings-path",
        default=None,
        help="findings.json path -- only used by the verify agent's replay_probe tool",
    )
    args = parser.parse_args()

    mcp = build_server(args.scope_dir, args.allowed_host, args.findings_path)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

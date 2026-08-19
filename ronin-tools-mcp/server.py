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
# the caller's own working directory. Also put the repo root on sys.path so
# `import findings_store` resolves -- this subprocess is spawned with no
# guarantee the root dir is already on sys.path (unlike recon_agent/loop.py
# etc, which live under the root and get it via a relative sys.path.insert).
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from mcp.server.mcpserver import MCPServer  # noqa: E402

import executor  # noqa: E402
from manifest import load_manifest  # noqa: E402
from scope import Scope  # noqa: E402
from categories import attack_reference, exploit_runtime, fileops, metasploit, network_exploit, recon, verify, web_exploit  # noqa: E402


def build_server(
    scope_dir: str,
    allowed_hosts: list[str],
    mongo_uri: str | None = None,
    mission_id: str | None = None,
) -> MCPServer:
    manifest = load_manifest()
    timeouts = {name: meta.timeout_seconds for name, meta in manifest.items()}
    scope = Scope(scope_dir=scope_dir, allowed_hosts=allowed_hosts)

    # Only the verify agent's replay_probe needs mission findings server-side.
    # Deferred import: findings_store pulls in pymongo, which every other
    # agent's server spawn shouldn't need to have installed/importable just
    # to run recon/exploit's tool categories.
    findings_loader = None
    if mongo_uri is not None and mission_id is not None:
        from findings_store import FindingsStore

        store = FindingsStore(mongo_uri)
        findings_loader = lambda: store.load_findings(mission_id)  # noqa: E731

    mcp = MCPServer("ronin-tools")
    recon.register(mcp, scope, executor, timeouts)
    fileops.register(mcp, scope, executor, timeouts)
    web_exploit.register(mcp, scope, executor, timeouts)
    exploit_runtime.register(mcp, scope, executor, timeouts)
    # verify.register takes findings_loader (its replay_probe reads the
    # winning attempt via this callable); the uniform register() signature
    # doesn't carry it.
    verify.register(mcp, scope, executor, timeouts, findings_loader)
    network_exploit.register(mcp, scope, executor, timeouts)
    attack_reference.register(mcp, scope, executor, timeouts)
    metasploit.register(mcp, scope, executor, timeouts)
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
        "--mongo-uri",
        default=None,
        help="Mongo connection URI -- only used by the verify agent's replay_probe tool",
    )
    parser.add_argument(
        "--mission-id",
        default=None,
        help="Mission id in the missions collection -- only used by replay_probe",
    )
    args = parser.parse_args()

    mcp = build_server(args.scope_dir, args.allowed_host, args.mongo_uri, args.mission_id)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

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

# This directory's name has a hyphen, so it can never be `import`ed as a
# real Python package -- server.py is always run as a spawned subprocess by
# file path (see agent_core.mcp_server_params), never imported. Put this
# directory on sys.path so `import manifest`, `import scope`, etc. resolve
# regardless of the caller's own working directory. Also put the parent
# (ronin_mini/) on sys.path so `import findings_store` resolves -- this
# subprocess has no guarantee that directory is already on sys.path, unlike
# same-package modules that reach it via a relative import.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from mcp.server.mcpserver import MCPServer  # noqa: E402

import executor  # noqa: E402
from manifest import load_manifest  # noqa: E402
from scope import Scope  # noqa: E402
from categories import (  # noqa: E402
    attack_reference,
    exploit_runtime,
    fileops,
    metasploit,
    network_exploit,
    oob_interaction,
    recon,
    verify,
    web_exploit,
)


def build_server(
    scope_dir: str,
    allowed_hosts: list[str],
    mongo_uri: str | None = None,
    mission_id: str | None = None,
) -> MCPServer:
    manifest = load_manifest()
    timeouts = {name: meta.timeout_seconds for name, meta in manifest.items()}
    scope = Scope(scope_dir=scope_dir, allowed_hosts=allowed_hosts)

    # verify_agent's replay_probe and exploit_agent's oob_interaction tools
    # both need mission-scoped Mongo state server-side; recon's server spawn
    # needs neither. Deferred import: findings_store pulls in pymongo, which
    # a spawn that needs neither shouldn't have to have installed/importable.
    findings_loader = None
    oob_store = None
    if mongo_uri is not None and mission_id is not None:
        from findings_store import FindingsStore

        store = FindingsStore(mongo_uri)
        findings_loader = lambda: store.load_findings(mission_id)  # noqa: E731

        def oob_store(action, mid, correlation_id, session):  # noqa: F811
            if action == "save":
                store.save_oob_session(mid, correlation_id, session)
                return None
            return store.get_oob_session(mid, correlation_id)

    mcp = MCPServer("ronin-tools")
    recon.register(mcp, scope, executor, timeouts)
    fileops.register(mcp, scope, executor, timeouts)
    web_exploit.register(mcp, scope, executor, timeouts)
    exploit_runtime.register(mcp, scope, executor, timeouts)
    # verify.register takes findings_loader (its replay_probe reads the
    # winning attempt via this callable, and also needs oob_store to replay
    # poll_oob_interactions calls); the uniform register() signature doesn't
    # carry either.
    verify.register(mcp, scope, executor, timeouts, findings_loader, oob_store)
    network_exploit.register(mcp, scope, executor, timeouts)
    attack_reference.register(mcp, scope, executor, timeouts)
    metasploit.register(mcp, scope, executor, timeouts)
    oob_interaction.register(mcp, scope, executor, timeouts, oob_store)
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
        help="Mongo connection URI -- used by verify's replay_probe and exploit_agent's oob_interaction tools",
    )
    parser.add_argument(
        "--mission-id",
        default=None,
        help="Mission id in the missions collection -- used by replay_probe and oob_interaction tools",
    )
    args = parser.parse_args()

    mcp = build_server(args.scope_dir, args.allowed_host, args.mongo_uri, args.mission_id)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

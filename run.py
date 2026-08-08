#!/usr/bin/env python3
"""Top-level orchestrator for the two-agent recon -> exploit flow.

Runs recon_agent to completion, then exploit_agent, sequentially, against a
single target. This IS the entire orchestrator -- no scheduler, no queue.

WARNING: For authorized security testing only. Only run this against targets
you own or have explicit written permission to test.
"""

import argparse
import asyncio
import os
import sys

from exploit_agent.loop import run_exploit_agent
from recon_agent.loop import run_recon_agent

DEFAULT_MODEL = "claude-sonnet-4-6"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Ronin two-agent recon->exploit orchestrator. FOR AUTHORIZED "
            "SECURITY TESTING ONLY."
        )
    )
    parser.add_argument("--target", required=True, help="Target URL or host")
    parser.add_argument("--objective", required=True, help="Recon objective")
    parser.add_argument("--scope-dir", required=True, help="Directory that fileops tools are sandboxed to")
    parser.add_argument("--findings-path", default="findings.json", help="Where recon writes / exploit reads findings")
    parser.add_argument("--recon-max-iterations", type=int, default=40)
    parser.add_argument("--recon-max-minutes", type=float, default=20.0)
    parser.add_argument("--exploit-per-finding-max-iterations", type=int, default=10)
    parser.add_argument("--exploit-per-finding-max-minutes", type=float, default=5.0)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    scope_dir = os.path.realpath(args.scope_dir)
    if not os.path.isdir(scope_dir):
        print(f"error: --scope-dir does not exist or is not a directory: {args.scope_dir}", file=sys.stderr)
        return 1

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("warning: ANTHROPIC_API_KEY is not set; the Anthropic SDK will fail to authenticate.", file=sys.stderr)

    print(f"[recon] target={args.target}")
    print(f"[recon] objective={args.objective!r}")
    recon_result = await run_recon_agent(
        target=args.target,
        objective=args.objective,
        scope_dir=scope_dir,
        model=args.model,
        findings_path=args.findings_path,
        max_iterations=args.recon_max_iterations,
        max_minutes=args.recon_max_minutes,
    )
    meta = recon_result["metadata"]
    print(
        f"[recon] stopped: {meta['stop_reason']}, {meta['tool_call_count']} tool calls, "
        f"{recon_result['findings_count']} candidate findings -> {recon_result['findings_path']}"
    )

    if recon_result["findings_count"] == 0:
        print("[exploit] no findings to process, skipping exploit_agent")
        return 0

    print(f"[exploit] processing findings from {args.findings_path}")
    exploit_result = await run_exploit_agent(
        target=args.target,
        scope_dir=scope_dir,
        findings_path=args.findings_path,
        model=args.model,
        per_finding_max_iterations=args.exploit_per_finding_max_iterations,
        per_finding_max_minutes=args.exploit_per_finding_max_minutes,
    )
    print(f"[exploit] processed {exploit_result['processed']}/{exploit_result['total_findings']} findings")
    print(f"[exploit] final results in {exploit_result['findings_path']}")
    return 0


def main() -> int:
    args = parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())

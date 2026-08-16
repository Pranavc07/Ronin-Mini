#!/usr/bin/env python3
"""Top-level orchestrator for the three-agent recon -> exploit -> verify flow.

Runs recon_agent, then exploit_agent, then verify_agent, sequentially, against a
single target. This IS the entire orchestrator -- no scheduler, no queue.

WARNING: For authorized security testing only. Only run this against targets
you own or have explicit written permission to test.
"""

import argparse
import asyncio
import os
import sys

from exploit_agent.loop import run_exploit_agent
from models import estimate_cost_usd, sum_usage
from recon_agent.loop import run_recon_agent
from verify_agent.loop import run_verify_agent

DEFAULT_MODEL = "claude-sonnet-4-6"


def _fmt_usage(usage: dict) -> str:
    return (
        f"input={usage['input_tokens']} output={usage['output_tokens']} "
        f"cache_write={usage['cache_creation_input_tokens']} cache_read={usage['cache_read_input_tokens']}"
    )


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
    parser.add_argument("--verify-per-finding-max-iterations", type=int, default=6)
    parser.add_argument("--verify-per-finding-max-minutes", type=float, default=5.0)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--provider",
        default="anthropic",
        help="Model provider adapter to use (default anthropic; see models/__init__.py)",
    )
    parser.add_argument(
        "--hitl-mode",
        choices=["auto", "manual", "plan"],
        default="auto",
        help=(
            "Human-in-the-loop approval for gated tools (probe_variant/execute_python/"
            "replay_probe/network_exploit): 'auto' never prompts, 'manual' prompts "
            "every gated call, 'plan' prompts once per run/finding and applies that "
            "decision to every gated call after. Default: auto."
        ),
    )
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
        provider=args.provider,
        hitl_mode=args.hitl_mode,
        findings_path=args.findings_path,
        max_iterations=args.recon_max_iterations,
        max_minutes=args.recon_max_minutes,
    )
    meta = recon_result["metadata"]
    print(
        f"[recon] stopped: {meta['stop_reason']}, {meta['tool_call_count']} tool calls, "
        f"{recon_result['findings_count']} candidate findings -> {recon_result['findings_path']}"
    )
    recon_cost = estimate_cost_usd(args.model, meta["usage"])
    print(f"[recon] tokens: {_fmt_usage(meta['usage'])} (~${recon_cost:.4f})")

    if recon_result["findings_count"] == 0:
        print("[exploit] no findings to process, skipping exploit_agent")
        return 0

    print(f"[exploit] processing findings from {args.findings_path}")
    exploit_result = await run_exploit_agent(
        target=args.target,
        scope_dir=scope_dir,
        findings_path=args.findings_path,
        model=args.model,
        provider=args.provider,
        hitl_mode=args.hitl_mode,
        per_finding_max_iterations=args.exploit_per_finding_max_iterations,
        per_finding_max_minutes=args.exploit_per_finding_max_minutes,
    )
    print(f"[exploit] processed {exploit_result['processed']}/{exploit_result['total_findings']} findings")
    exploit_cost = estimate_cost_usd(args.model, exploit_result["usage"])
    print(f"[exploit] tokens: {_fmt_usage(exploit_result['usage'])} (~${exploit_cost:.4f})")

    print(f"[verify] independently re-checking exploited findings from {args.findings_path}")
    verify_result = await run_verify_agent(
        target=args.target,
        scope_dir=scope_dir,
        findings_path=args.findings_path,
        model=args.model,
        provider=args.provider,
        hitl_mode=args.hitl_mode,
        per_finding_max_iterations=args.verify_per_finding_max_iterations,
        per_finding_max_minutes=args.verify_per_finding_max_minutes,
    )
    print(f"[verify] verified {verify_result['processed']} exploited finding(s)")
    verify_cost = estimate_cost_usd(args.model, verify_result["usage"])
    print(f"[verify] tokens: {_fmt_usage(verify_result['usage'])} (~${verify_cost:.4f})")
    print(f"[verify] final results in {verify_result['findings_path']}")

    total_usage = sum_usage(meta["usage"], exploit_result["usage"], verify_result["usage"])
    total_cost = recon_cost + exploit_cost + verify_cost
    print(f"\n[total] tokens: {_fmt_usage(total_usage)}")
    print(f"[total] estimated cost: ${total_cost:.4f} (model={args.model}; approximate -- verify against console.anthropic.com billing)")
    return 0


def main() -> int:
    args = parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())

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

from . import agent_core
from .exploit_agent.loop import run_exploit_agent
from .findings_store import DEFAULT_MONGO_URI, FindingsStore
from .models import estimate_cost_usd, sum_usage
from .recon_agent.loop import run_recon_agent
from .verify_agent.loop import run_verify_agent

DEFAULT_MODEL = "claude-sonnet-4-6"

# Empirically measured (2026-08-21, stress test against a 100-finding mission on
# a single Windows dev host): worker_count scaled cleanly through 10/20/40/80
# concurrent workers (each spawns its own MCP server subprocess), then broke
# hard at 150 with WinError 1450/8 -- the OS ran out of process/handle table
# space, not a MongoDB or model-provider limit. This default sits well under
# that measured ceiling; --allow-high-worker-count lifts it for hosts known to
# have more headroom (more RAM, a higher OS file-descriptor/process limit).
DEFAULT_MAX_WORKER_COUNT = 25


def check_worker_count_cap(exploit_worker_count: int, verify_worker_count: int, allow_high: bool) -> str | None:
    """Returns an error message if either worker count exceeds the default cap
    and --allow-high-worker-count wasn't passed, else None. A pure function so
    the cap logic is testable without spinning up the async pipeline."""
    if allow_high:
        return None
    over_cap = [
        (name, count)
        for name, count in (("--exploit-worker-count", exploit_worker_count), ("--verify-worker-count", verify_worker_count))
        if count > DEFAULT_MAX_WORKER_COUNT
    ]
    if not over_cap:
        return None
    flags = ", ".join(f"{name}={count}" for name, count in over_cap)
    return (
        f"error: {flags} exceeds the default cap of {DEFAULT_MAX_WORKER_COUNT}. "
        f"Each worker spawns its own MCP server subprocess -- on the host this cap was "
        f"measured on, concurrency scaled cleanly up to 80 workers but broke at 150 from "
        f"OS process/handle exhaustion (WinError 1450/8), not a code or MongoDB limit. "
        f"Pass --allow-high-worker-count if you've confirmed this host can handle more."
    )


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
    parser.add_argument(
        "--mongo-uri",
        default=DEFAULT_MONGO_URI,
        help=f"MongoDB connection URI where mission findings are stored (default: {DEFAULT_MONGO_URI})",
    )
    parser.add_argument(
        "--mission-id",
        default=None,
        help="Resume an existing mission (skips recon if it already has findings). Default: create a fresh mission.",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help="Optional mission-level cost cap (approximate, same estimate the per-stage cost lines use). "
        "Checked between stages; the run stops before starting a stage that would exceed it.",
    )
    parser.add_argument("--recon-max-iterations", type=int, default=40)
    parser.add_argument("--recon-max-minutes", type=float, default=20.0)
    parser.add_argument("--exploit-per-finding-max-iterations", type=int, default=10)
    parser.add_argument("--exploit-per-finding-max-minutes", type=float, default=5.0)
    parser.add_argument(
        "--exploit-worker-count",
        type=int,
        default=1,
        help="Concurrent exploit_agent workers claiming findings from the same mission "
        "(default 1 = today's sequential behavior). Each worker opens its own MCP session. "
        "Note: --budget-usd is only checked between stages, not mid-stage, so a higher "
        "worker count can overshoot the cap further before it's caught.",
    )
    parser.add_argument("--verify-per-finding-max-iterations", type=int, default=6)
    parser.add_argument("--verify-per-finding-max-minutes", type=float, default=5.0)
    parser.add_argument(
        "--verify-worker-count",
        type=int,
        default=1,
        help="Concurrent verify_agent workers claiming findings from the same mission "
        "(default 1 = today's sequential behavior). Same budget-check caveat as "
        "--exploit-worker-count.",
    )
    parser.add_argument(
        "--allow-high-worker-count",
        action="store_true",
        help=f"Lift the default cap of {DEFAULT_MAX_WORKER_COUNT} on --exploit-worker-count/"
        "--verify-worker-count. Only pass this if you've confirmed the host has the "
        "process/memory headroom -- see check_worker_count_cap()'s docstring in run.py "
        "for how that default was measured.",
    )
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
    parser.add_argument(
        "--log-path",
        default=None,
        help=(
            "Where to write the full pipeline's live JSONL log (every model reasoning "
            "turn + tool call/result, across recon/exploit/verify). Default: auto-"
            "generated under logs/ as run_<target>_<timestamp>.jsonl."
        ),
    )
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    scope_dir = os.path.realpath(args.scope_dir)
    if not os.path.isdir(scope_dir):
        print(f"error: --scope-dir does not exist or is not a directory: {args.scope_dir}", file=sys.stderr)
        return 1

    cap_error = check_worker_count_cap(args.exploit_worker_count, args.verify_worker_count, args.allow_high_worker_count)
    if cap_error:
        print(cap_error, file=sys.stderr)
        return 1

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("warning: ANTHROPIC_API_KEY is not set; the Anthropic SDK will fail to authenticate.", file=sys.stderr)

    log_path = args.log_path or agent_core.new_run_log_path(args.target)
    print(f"[+] Live pipeline log: {log_path}")

    store = FindingsStore(args.mongo_uri)
    try:
        if args.mission_id:
            mission_id = args.mission_id
            if store.get_mission(mission_id) is None:
                print(f"error: --mission-id {mission_id!r} does not exist in {args.mongo_uri}", file=sys.stderr)
                return 1
            print(f"[+] Resuming mission {mission_id}")
        else:
            mission_id = store.create_mission(args.target, args.objective, budget_usd=args.budget_usd)
            print(f"[+] Mission id: {mission_id} (mongo={args.mongo_uri})")

        def _budget_status(total_cost: float) -> str | None:
            if args.budget_usd is None:
                return None
            if total_cost >= args.budget_usd:
                return (
                    f"[!] budget exceeded: ~${total_cost:.4f} spent >= ${args.budget_usd:.2f} cap "
                    "-- stopping before the next stage"
                )
            return None

        recon_findings_count = len(store.load_findings(mission_id)) if args.mission_id else None
        total_cost = 0.0
        total_usage_parts: list[dict] = []

        if recon_findings_count is None:
            print(f"[recon] target={args.target}")
            print(f"[recon] objective={args.objective!r}")
            recon_result = await run_recon_agent(
                target=args.target,
                objective=args.objective,
                scope_dir=scope_dir,
                model=args.model,
                provider=args.provider,
                hitl_mode=args.hitl_mode,
                store=store,
                mission_id=mission_id,
                max_iterations=args.recon_max_iterations,
                max_minutes=args.recon_max_minutes,
                log_path=log_path,
            )
            meta = recon_result["metadata"]
            print(
                f"[recon] stopped: {meta['stop_reason']}, {meta['tool_call_count']} tool calls, "
                f"{recon_result['findings_count']} candidate findings -> mission {mission_id}"
            )
            recon_cost = estimate_cost_usd(args.model, meta["usage"])
            print(f"[recon] tokens: {_fmt_usage(meta['usage'])} (~${recon_cost:.4f})")
            total_cost += recon_cost
            total_usage_parts.append(meta["usage"])
            recon_findings_count = recon_result["findings_count"]
        else:
            print(f"[recon] skipped -- resumed mission already has {recon_findings_count} finding(s)")

        if recon_findings_count == 0:
            print("[exploit] no findings to process, skipping exploit_agent")
            return 0

        budget_msg = _budget_status(total_cost)
        if budget_msg:
            print(budget_msg)
            return 0

        print(f"[exploit] processing findings from mission {mission_id}")
        exploit_result = await run_exploit_agent(
            target=args.target,
            scope_dir=scope_dir,
            store=store,
            mission_id=mission_id,
            model=args.model,
            mongo_uri=args.mongo_uri,
            provider=args.provider,
            hitl_mode=args.hitl_mode,
            per_finding_max_iterations=args.exploit_per_finding_max_iterations,
            per_finding_max_minutes=args.exploit_per_finding_max_minutes,
            log_path=log_path,
            worker_count=args.exploit_worker_count,
        )
        print(f"[exploit] processed {exploit_result['processed']}/{exploit_result['total_findings']} findings")
        exploit_cost = estimate_cost_usd(args.model, exploit_result["usage"])
        print(f"[exploit] tokens: {_fmt_usage(exploit_result['usage'])} (~${exploit_cost:.4f})")
        total_cost += exploit_cost
        total_usage_parts.append(exploit_result["usage"])

        budget_msg = _budget_status(total_cost)
        if budget_msg:
            print(budget_msg)
            return 0

        print(f"[verify] independently re-checking exploited findings from mission {mission_id}")
        verify_result = await run_verify_agent(
            target=args.target,
            scope_dir=scope_dir,
            store=store,
            mission_id=mission_id,
            model=args.model,
            mongo_uri=args.mongo_uri,
            provider=args.provider,
            hitl_mode=args.hitl_mode,
            per_finding_max_iterations=args.verify_per_finding_max_iterations,
            per_finding_max_minutes=args.verify_per_finding_max_minutes,
            log_path=log_path,
            worker_count=args.verify_worker_count,
        )
        print(f"[verify] verified {verify_result['processed']} exploited finding(s)")
        verify_cost = estimate_cost_usd(args.model, verify_result["usage"])
        print(f"[verify] tokens: {_fmt_usage(verify_result['usage'])} (~${verify_cost:.4f})")
        total_cost += verify_cost
        total_usage_parts.append(verify_result["usage"])
        print(f"[verify] final results in mission {mission_id} ({args.mongo_uri})")

        total_usage = sum_usage(*total_usage_parts)
        billing_dashboard = {"anthropic": "console.anthropic.com"}.get(
            args.provider, f"your {args.provider} provider's dashboard"
        )
        print(f"\n[total] tokens: {_fmt_usage(total_usage)}")
        print(
            f"[total] estimated cost: ${total_cost:.4f} (model={args.model}; approximate -- "
            f"verify against {billing_dashboard})"
        )
        print(f"[total] full pipeline log: {log_path}")
        return 0
    finally:
        store.close()


def main() -> int:
    args = parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())

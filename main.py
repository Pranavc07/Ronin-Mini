#!/usr/bin/env python3
"""CLI entry point for the pentest agent harness.

Usage:
    python main.py --target <url> --objective "<text>" --scope-dir <path> \
        [--max-iterations 40] [--max-minutes 20] [--model claude-sonnet-4-6]

WARNING: For authorized security testing only. Only run this against targets
you own or have explicit written permission to test.
"""

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone

from loop import run_agent

DEFAULT_MODEL = "claude-sonnet-4-6"


def slugify(value: str) -> str:
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-")
    return value[:60] or "target"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "AI pentesting agent harness. FOR AUTHORIZED SECURITY TESTING "
            "ONLY — only run this against targets you own or have explicit "
            "written permission to test."
        )
    )
    parser.add_argument("--target", required=True, help="Target URL or host")
    parser.add_argument("--objective", required=True, help="Testing objective for the agent")
    parser.add_argument(
        "--scope-dir",
        required=True,
        help="Directory that code_search/file_read are sandboxed to",
    )
    parser.add_argument("--max-iterations", type=int, default=40, help="Max tool calls (default 40)")
    parser.add_argument("--max-minutes", type=float, default=20.0, help="Wall-clock cap in minutes (default 20)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Model ID (default {DEFAULT_MODEL})")
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
            "every gated call, 'plan' prompts once per run and applies that decision "
            "to every gated call after. Default: auto."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to write the transcript JSON file to (default: current directory)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    scope_dir = os.path.realpath(args.scope_dir)
    if not os.path.isdir(scope_dir):
        print(f"error: --scope-dir does not exist or is not a directory: {args.scope_dir}", file=sys.stderr)
        return 1

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("warning: ANTHROPIC_API_KEY is not set; the Anthropic SDK will fail to authenticate.", file=sys.stderr)

    print(f"[+] Target:      {args.target}")
    print(f"[+] Objective:   {args.objective}")
    print(f"[+] Scope dir:   {scope_dir}")
    print(f"[+] Provider:    {args.provider}")
    print(f"[+] Model:       {args.model}")
    print(f"[+] HITL mode:   {args.hitl_mode}")
    print(f"[+] Max iters:   {args.max_iterations}   Max minutes: {args.max_minutes}")
    print("[+] Starting agent loop...\n")

    result = asyncio.run(
        run_agent(
            target=args.target,
            objective=args.objective,
            scope_dir=scope_dir,
            model=args.model,
            provider=args.provider,
            hitl_mode=args.hitl_mode,
            max_iterations=args.max_iterations,
            max_minutes=args.max_minutes,
        )
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"transcript_{slugify(args.target)}_{timestamp}.json"
    output_path = os.path.join(args.output_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    meta = result["metadata"]
    print(f"\n[+] Stopped: {meta['stop_reason']}")
    print(f"[+] Tool calls made: {meta['tool_call_count']}")
    print(f"[+] Findings: {len(result['findings'])}")
    print(f"[+] Transcript written to: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

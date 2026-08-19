"""verify_agent: independently re-checks each finding the exploit agent marked
"exploited". It has exactly one tool -- replay_probe -- which literally re-runs
the winning attempt's recorded tool calls. It cannot discover, explore, or
invent new attempts; it can only reproduce what already happened and judge
whether the claimed impact still holds.

Reads findings from the mission's Mongo document (via findings_store), processes each status == "exploited" finding one at a time
in its own fresh conversation (claim pattern: exploited -> verifying ->
verified | false_positive | unverifiable | verify_incomplete), appending its
own reasoning to a new verify_attempts field on the finding.

unverifiable is distinct from false_positive: it means replay_probe reported
replayable: false for the calls central to the claim (no replay support
exists for those tools yet) -- a tooling coverage gap, not a replay that ran
and contradicted the claim. false_positive is reserved for the latter.
verify_incomplete (parallel to exploit_agent's "incomplete") means neither
verdict was reached before the budget ran out.
"""

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.stdio import stdio_client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import agent_core  # noqa: E402
import models  # noqa: E402
from findings_store import FindingsStore  # noqa: E402
from models import sum_usage  # noqa: E402

ALLOWED_CATEGORIES = {"verify"}

VERIFY_START = "<<<VERIFY>>>"
VERIFY_END = "<<<END_VERIFY>>>"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_system_prompt(target: str, finding: dict, tool_defs: list[dict], injection_token: str) -> str:
    """claimed_evidence is exploit_agent's verdict text -- same category of
    risk as exploit_agent's own finding_evidence (quoted target content
    landing directly in a system prompt), wrapped with wrap_untrusted_data()
    for the same reason. See exploit_agent/loop.py's build_system_prompt
    docstring for why a value containing literal braces is safe to pass
    through .format() regardless (single-pass substitution, not re-parsed).
    """
    claimed = ""
    winning = [
        a for a in finding.get("exploit_attempts", [])
        if a.get("verdict", {}).get("status") == "exploited"
    ]
    if winning:
        claimed = winning[-1].get("verdict", {}).get("evidence", "")
    return agent_core.load_agent_prompt("verify").format(
        target=target,
        tool_schemas=json.dumps(tool_defs, indent=2),
        finding_id=finding["id"],
        finding_type=finding.get("type", ""),
        finding_target=finding.get("target", ""),
        claimed_evidence=agent_core.wrap_untrusted_data(claimed, injection_token),
        injection_token=injection_token,
        verify_start=VERIFY_START,
        verify_end=VERIFY_END,
    )


async def _process_one_finding(
    model_adapter: models.ModelAdapter,
    session: ClientSession,
    manifest: dict,
    target: str,
    finding: dict,
    tool_defs: list[dict],
    max_iterations: int,
    max_minutes: float,
    max_tokens: int,
    hitl_mode: str = "auto",
    log_path: str | None = None,
) -> tuple[dict, str]:
    injection_token = agent_core.new_injection_token()
    system_prompt = build_system_prompt(target, finding, tool_defs, injection_token)
    initial_message = (
        f"Verify finding {finding['id']} ({finding.get('type')}) at {finding.get('target')} "
        f"by replaying its winning attempt. Call replay_probe with finding id "
        f"\"{finding['id']}\", then judge whether the claimed exploitation reproduces."
    )
    label = f"verify:{finding['id']}"
    print(f"[{label}] verifying -- {finding.get('type')} at {finding.get('target')}", flush=True)

    result = await agent_core.run_tool_loop(
        model_adapter,
        session,
        manifest,
        system_prompt,
        tool_defs,
        initial_message,
        max_iterations,
        max_minutes,
        max_tokens,
        injection_token=injection_token,
        extract_markers=(VERIFY_START, VERIFY_END),
        hitl_mode=hitl_mode,
        label=label,
        log_path=log_path,
    )

    verdicts = [b for b in result["extracted_blocks"] if b.get("status") in ("verified", "false_positive", "unverifiable")]
    if verdicts:
        verdict = verdicts[-1]
        status = verdict["status"]
    else:
        # Parallel to the exploit agent's "incomplete": the verify agent never
        # delivered a clean verdict -- don't silently call that a false positive.
        status = "verify_incomplete"
        verdict = {
            "status": "verify_incomplete",
            "evidence": (
                f"No verify verdict produced before stopping (stop_reason={result['stop_reason']}, "
                f"{result['tool_call_count']} tool calls)."
            ),
        }

    attempt = {
        "timestamp": _now_iso(),
        "tool_call_count": result["tool_call_count"],
        "stop_reason": result["stop_reason"],
        "usage": result["usage"],
        "transcript": result["transcript"],
        "verdict": verdict,
    }
    return attempt, status


async def run_verify_agent(
    target: str,
    scope_dir: str,
    store: FindingsStore,
    mission_id: str,
    model: str,
    mongo_uri: str = "mongodb://localhost:27017",
    provider: str = "anthropic",
    hitl_mode: str = "auto",
    per_finding_max_iterations: int = 6,
    per_finding_max_minutes: float = 5.0,
    max_tokens: int = 4096,
    allowed_hosts: list[str] | None = None,
    log_path: str | None = None,
) -> dict:
    if allowed_hosts is None:
        allowed_hosts = [urlparse(target).hostname or target]

    findings = store.load_findings(mission_id)

    model_adapter = models.build_adapter(provider, model)
    # The server needs mongo_uri/mission_id so replay_probe can look up winning
    # attempts directly from the mission document (it runs in a separate
    # subprocess, so it opens its own Mongo connection rather than sharing
    # `store`).
    server_params = agent_core.mcp_server_params(
        scope_dir, allowed_hosts, mongo_uri=mongo_uri, mission_id=mission_id
    )

    processed = 0
    attempt_usages: list[dict] = []
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            manifest = agent_core.load_manifest()
            allowed_tools = agent_core.filter_tools_by_category(
                tools_result.tools, manifest, ALLOWED_CATEGORIES
            )
            tool_defs = agent_core.mcp_tools_to_anthropic_schema(allowed_tools)

            for finding in findings:
                if finding.get("status") != "exploited":
                    continue

                finding["status"] = "verifying"
                store.save_findings(mission_id, findings)

                attempt, outcome_status = await _process_one_finding(
                    model_adapter,
                    session,
                    manifest,
                    target,
                    finding,
                    tool_defs,
                    per_finding_max_iterations,
                    per_finding_max_minutes,
                    max_tokens,
                    hitl_mode=hitl_mode,
                    log_path=log_path,
                )
                finding.setdefault("verify_attempts", []).append(attempt)
                finding["status"] = outcome_status
                store.save_findings(mission_id, findings)
                processed += 1
                attempt_usages.append(attempt["usage"])

    total_usage = sum_usage(*attempt_usages)
    store.record_stage_usage(mission_id, "verify", total_usage)

    return {
        "processed": processed,
        "total_findings": len(findings),
        "mission_id": mission_id,
        "usage": total_usage,
    }

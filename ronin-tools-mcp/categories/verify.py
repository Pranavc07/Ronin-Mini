"""verify category: replay_probe -- the ONLY tool the verify agent gets.

It does not discover or invent anything. Given a finding id, it looks up that
finding's winning (status == "exploited") exploit attempt in findings.json and
literally re-executes the exact tool calls that attempt made -- same
probe_variant requests, same execute_python code -- through the identical
scope-checked execution paths the exploit agent used. It returns the original
recorded output alongside the fresh replay output for each call, so the verify
agent can judge whether the claimed impact still reproduces.

This is a replay, not a probe: no free-form exploration, no new payloads.
"""

from __future__ import annotations

import json

from manifest import DEFAULT_TIMEOUT_SECONDS

from .exploit_runtime import run_execute_python
from .web_exploit import run_probe_variant

# A winning attempt occasionally iterated many times (execute_python "write,
# fail, adjust"). Replaying every recorded call is faithful but bounded here so
# one pathological attempt can't spawn dozens of containers during verification.
MAX_REPLAYED_CALLS = 12


def _winning_attempt(finding: dict) -> dict | None:
    exploited = [
        a
        for a in finding.get("exploit_attempts", [])
        if a.get("verdict", {}).get("status") == "exploited"
    ]
    return exploited[-1] if exploited else None


def register(mcp, scope, executor, timeouts: dict, findings_path: str | None) -> None:
    def replay_probe(finding_id: str) -> dict:
        """Replay the exact tool calls from a finding's winning exploit attempt
        and return original-vs-replayed output for each, so you can judge
        whether the claimed exploitation still reproduces. Pass the finding id
        (e.g. "f3"). This re-runs what already happened -- it does not let you
        craft new requests or explore.
        """
        if not findings_path:
            return {"error": "replay_probe has no findings file configured on the server"}

        try:
            with open(findings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except OSError as e:
            return {"error": f"could not read findings file: {e}"}

        finding = next((x for x in data.get("findings", []) if x.get("id") == finding_id), None)
        if finding is None:
            return {"error": f"no finding with id {finding_id!r}"}

        attempt = _winning_attempt(finding)
        if attempt is None:
            return {"error": f"finding {finding_id!r} has no winning (exploited) attempt to replay"}

        recorded_calls = [t for t in attempt.get("transcript", []) if t.get("tool") in ("probe_variant", "execute_python")]
        if not recorded_calls:
            return {"error": f"winning attempt for {finding_id!r} recorded no replayable tool calls"}

        truncated = len(recorded_calls) > MAX_REPLAYED_CALLS
        replays = []
        for call in recorded_calls[:MAX_REPLAYED_CALLS]:
            tool = call["tool"]
            tool_input = call.get("input", {})
            if tool == "probe_variant":
                replay_output = run_probe_variant(
                    scope,
                    executor,
                    timeouts.get("probe_variant", DEFAULT_TIMEOUT_SECONDS),
                    tool_input.get("method", "GET"),
                    tool_input.get("url", ""),
                    tool_input.get("baseline_headers"),
                    tool_input.get("variant_headers"),
                    tool_input.get("baseline_params"),
                    tool_input.get("variant_params"),
                    tool_input.get("body"),
                )
            else:  # execute_python
                exec_max = timeouts.get("execute_python", DEFAULT_TIMEOUT_SECONDS)
                exec_timeout = min(int(tool_input.get("timeout") or exec_max), exec_max)
                replay_output = run_execute_python(scope, executor, exec_timeout, tool_input.get("code", ""))

            replays.append(
                {
                    "tool": tool,
                    "input": tool_input,
                    "original_output": call.get("output"),
                    "replay_output": replay_output,
                }
            )

        return {
            "finding_id": finding_id,
            "finding_type": finding.get("type"),
            "finding_target": finding.get("target"),
            "claimed_evidence": attempt.get("verdict", {}).get("evidence", ""),
            "replayed_call_count": len(replays),
            "note": (
                "Each entry is a literal replay of a tool call from the winning attempt. "
                "Compare original_output vs replay_output to judge whether the claimed "
                "impact still reproduces."
                + (f" (Only the first {MAX_REPLAYED_CALLS} calls were replayed.)" if truncated else "")
            ),
            "replays": replays,
        }

    mcp.add_tool(replay_probe)

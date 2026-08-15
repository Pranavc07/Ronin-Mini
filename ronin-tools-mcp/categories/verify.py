"""verify category: replay_probe -- the ONLY tool the verify agent gets.

It does not discover or invent anything. Given a finding id, it looks up that
finding's winning (status == "exploited") exploit attempt in findings.json and
literally re-executes the exact tool calls that attempt made -- same
probe_variant requests, same execute_python code, same nmap/hydra/metasploit
invocations -- through the identical scope-checked execution paths the
exploit agent used. It returns the original recorded output alongside the
fresh replay output for each call, so the verify agent can judge whether the
claimed impact still reproduces.

This is a replay, not a probe: no free-form exploration, no new payloads.

Every tool exploit_agent can produce a winning attempt with must have a
replay case here (REPLAYABLE_TOOLS + _replay_call) -- a finding's winning
attempt using a tool this file doesn't know how to replay means replay_probe
finds nothing to replay, and verify_agent (having nothing to confirm)
concludes false_positive on a real exploit. That happened in practice:
network_exploit's 7 tools and metasploit were added to exploit_agent's
toolset without this file being updated, and a live run against real
Metasploitable mislabeled 3 genuine Metasploit-confirmed exploits (incl. a
root shell) as false positives purely because replay had nothing to run.
Keep this list in sync with every tool exploit_agent can reach.
"""

from __future__ import annotations

import json

from manifest import DEFAULT_TIMEOUT_SECONDS

from .attack_reference import run_lookup_attack_technique
from .exploit_runtime import run_execute_python
from .metasploit import run_metasploit
from .network_exploit import (
    run_enum4linux,
    run_gobuster,
    run_hydra,
    run_nikto,
    run_nmap,
    run_searchsploit,
    run_sqlmap,
)
from .web_exploit import run_probe_variant

# A winning attempt occasionally iterated many times (execute_python "write,
# fail, adjust"). Replaying every recorded call is faithful but bounded here so
# one pathological attempt can't spawn dozens of containers/exploit attempts
# during verification. Note replaying hydra/metasploit means literally
# re-attempting the brute-force/exploit a second time -- same tradeoff this
# design already accepted for execute_python, not a new risk in kind. This
# category is require_approval: true same as everywhere else; HITL is the
# actual control, not special-casing which tools are "safe" to replay.
MAX_REPLAYED_CALLS = 12

REPLAYABLE_TOOLS = (
    "probe_variant",
    "execute_python",
    "nmap",
    "nikto",
    "sqlmap",
    "hydra",
    "gobuster",
    "enum4linux",
    "searchsploit",
    "metasploit",
    "lookup_attack_technique",
)


def _replay_call(scope, executor, timeouts: dict, tool: str, tool_input: dict):
    if tool == "probe_variant":
        return run_probe_variant(
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
    if tool == "execute_python":
        exec_max = timeouts.get("execute_python", DEFAULT_TIMEOUT_SECONDS)
        exec_timeout = min(int(tool_input.get("timeout") or exec_max), exec_max)
        return run_execute_python(scope, executor, exec_timeout, tool_input.get("code", ""))
    if tool == "nmap":
        return run_nmap(
            scope,
            executor,
            timeouts.get("nmap", DEFAULT_TIMEOUT_SECONDS),
            tool_input.get("target", ""),
            tool_input.get("scan_type", ""),
            tool_input.get("ports"),
        )
    if tool == "nikto":
        return run_nikto(scope, executor, timeouts.get("nikto", DEFAULT_TIMEOUT_SECONDS), tool_input.get("target", ""))
    if tool == "sqlmap":
        return run_sqlmap(
            scope,
            executor,
            timeouts.get("sqlmap", DEFAULT_TIMEOUT_SECONDS),
            tool_input.get("target_url", ""),
            tool_input.get("data"),
            tool_input.get("level", 1),
            tool_input.get("risk", 1),
        )
    if tool == "hydra":
        return run_hydra(
            scope,
            executor,
            timeouts.get("hydra", DEFAULT_TIMEOUT_SECONDS),
            tool_input.get("target", ""),
            tool_input.get("service", ""),
            tool_input.get("username"),
            tool_input.get("username_wordlist"),
            tool_input.get("password_wordlist", "common_top100"),
        )
    if tool == "gobuster":
        return run_gobuster(
            scope,
            executor,
            timeouts.get("gobuster", DEFAULT_TIMEOUT_SECONDS),
            tool_input.get("target_url", ""),
            tool_input.get("wordlist", "common"),
        )
    if tool == "enum4linux":
        return run_enum4linux(
            scope,
            executor,
            timeouts.get("enum4linux", DEFAULT_TIMEOUT_SECONDS),
            tool_input.get("target", ""),
            tool_input.get("level", "basic"),
        )
    if tool == "searchsploit":
        return run_searchsploit(
            executor, timeouts.get("searchsploit", DEFAULT_TIMEOUT_SECONDS), tool_input.get("query", "")
        )
    if tool == "metasploit":
        return run_metasploit(
            scope,
            executor,
            timeouts.get("metasploit", DEFAULT_TIMEOUT_SECONDS),
            tool_input.get("module", ""),
            tool_input.get("target", ""),
            tool_input.get("port"),
            tool_input.get("payload"),
            tool_input.get("lhost"),
            tool_input.get("lport"),
            tool_input.get("options"),
            tool_input.get("post_exploit_command"),
        )
    if tool == "lookup_attack_technique":
        return run_lookup_attack_technique(tool_input.get("query", ""))
    return {"error": f"tool {tool!r} is not replayable"}  # should be unreachable given REPLAYABLE_TOOLS filtering


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

        recorded_calls = [t for t in attempt.get("transcript", []) if t.get("tool") in REPLAYABLE_TOOLS]
        if not recorded_calls:
            return {"error": f"winning attempt for {finding_id!r} recorded no replayable tool calls"}

        truncated = len(recorded_calls) > MAX_REPLAYED_CALLS
        replays = []
        for call in recorded_calls[:MAX_REPLAYED_CALLS]:
            tool = call["tool"]
            tool_input = call.get("input", {})
            replay_output = _replay_call(scope, executor, timeouts, tool, tool_input)

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

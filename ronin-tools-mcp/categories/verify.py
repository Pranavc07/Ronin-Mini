"""verify category: replay_probe -- the ONLY tool the verify agent gets.

It does not discover or invent anything. Given a finding id, it looks up that
finding's winning (status == "exploited") exploit attempt in findings.json and
walks every recorded tool call in that attempt's transcript. For a tool with
real replay support (manifest.yaml's replayable: "true"/"partial"), it
literally re-executes the exact call -- same probe_variant requests, same
execute_python code, same nmap/hydra/metasploit invocations -- through the
identical scope-checked execution paths the exploit agent used, and returns
the original recorded output alongside the fresh replay output. For a tool
with no declared replay support (replayable: "false"), it returns an explicit
{"replayable": false, "reason": ...} stub instead of silently omitting the
call -- so a coverage gap produces a structurally distinguishable signal, not
something that looks identical to "replay ran and found nothing."

This is a replay, not a probe: no free-form exploration, no new payloads.

Why the explicit stub matters (this happened for real): a finding's winning
attempt using only tools replay_probe doesn't know how to replay used to mean
the whole call list got silently filtered down to nothing -- and verify_agent,
seeing zero replayed calls, concluded "false_positive" (claim disproven) on
findings that were never actually re-checked at all. That happened when
network_exploit's 7 tools and metasploit were added to exploit_agent's toolset
without categories/verify.py being updated: a live run against real
Metasploitable mislabeled 3 genuine Metasploit-confirmed exploits (incl. a
root shell) as false positives purely because replay had nothing to run.
That specific gap is fixed (every tool exploit_agent can reach today has a
real dispatch case below) -- but the *structural* fix is what prevents it from
recurring for a tool added later: manifest.yaml requires every tool to declare
replayable: "true"/"false"/"partial" (a missing field fails loudly at
load_manifest() time), and tests/test_replay_coverage.py fails automatically
the moment a tool lands in a category exploit_agent can reach without a
working _replay_call case. A tool correctly declared replayable: "false"
produces the explicit stub above, and verify_agent's prompt is instructed to
conclude "unverifiable" from that -- a coverage gap, not a falsification --
never "false_positive".
"""

from __future__ import annotations

import json

from manifest import DEFAULT_TIMEOUT_SECONDS, load_manifest

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
# actual control, not special-casing which tools are "safe" to replay. Only
# counts calls that are actually replayed (real dispatch) -- calls that get
# the "not replayable" stub are free and don't consume this budget.
MAX_REPLAYED_CALLS = 12

_MANIFEST = load_manifest()

# Tools with real _replay_call dispatch below -- derived from manifest.yaml's
# replayable field ("true" or "partial"), not a separately hand-maintained
# list, so this can't drift out of sync with the manifest the way the old
# hardcoded tuple did. tests/test_replay_coverage.py asserts every tool in
# this set actually has a working dispatch case, and every exploit_agent-
# reachable tool NOT in this set is explicitly declared replayable: "false".
REPLAYABLE_TOOLS = {name for name, meta in _MANIFEST.items() if meta.replayable in ("true", "partial")}


def _replay_call(scope, executor, timeouts: dict, tool: str, tool_input: dict):
    """Dispatch a single replay. Only ever called for tool in REPLAYABLE_TOOLS
    (run_replay_probe below routes replayable: "false" tools to the explicit
    stub before reaching here) -- so the fallback at the bottom firing means a
    tool is declared replayable in manifest.yaml but this function has no real
    case for it yet, a genuine implementation gap tests/test_replay_coverage.py
    catches, distinct from a deliberately-declared "false".
    """
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
    return {
        "error": (
            f"tool {tool!r} is declared replayable in manifest.yaml but _replay_call has no "
            "dispatch case for it -- this is an implementation gap, add a case above."
        )
    }


def _not_replayable_reason(tool: str) -> str:
    meta = _MANIFEST.get(tool)
    if meta is None:
        return (
            f"tool {tool!r} is not present in manifest.yaml at all -- replay support cannot "
            "be determined. Treat as unverifiable, not disproven."
        )
    return (
        f"tool {tool!r} is declared replayable: \"false\" in manifest.yaml -- no replay "
        "implementation exists for it. This is a tooling coverage gap, not evidence the "
        "original claim is false; conclude unverifiable, never false_positive, from this "
        "alone."
    )


def _winning_attempt(finding: dict) -> dict | None:
    exploited = [
        a
        for a in finding.get("exploit_attempts", [])
        if a.get("verdict", {}).get("status") == "exploited"
    ]
    return exploited[-1] if exploited else None


def run_replay_probe(scope, executor, timeouts: dict, findings_path: str | None, finding_id: str) -> dict:
    """The actual replay logic, as a module-level function so it's testable
    without spinning up the MCP server (mirrors every other category's
    run_* / register() split).
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

    recorded_calls = attempt.get("transcript", [])
    if not recorded_calls:
        return {"error": f"winning attempt for {finding_id!r} recorded no tool calls at all"}

    replays = []
    replayed_count = 0
    for call in recorded_calls:
        tool = call.get("tool")
        tool_input = call.get("input", {})

        if tool not in REPLAYABLE_TOOLS:
            replays.append(
                {
                    "tool": tool,
                    "replayable": False,
                    "input": tool_input,
                    "original_output": call.get("output"),
                    "reason": _not_replayable_reason(tool),
                }
            )
            continue

        if replayed_count >= MAX_REPLAYED_CALLS:
            replays.append(
                {
                    "tool": tool,
                    "replayable": True,
                    "input": tool_input,
                    "original_output": call.get("output"),
                    "reason": f"skipped -- replay cap of {MAX_REPLAYED_CALLS} actually-replayed calls reached",
                }
            )
            continue

        replay_output = _replay_call(scope, executor, timeouts, tool, tool_input)
        replayed_count += 1
        replays.append(
            {
                "tool": tool,
                "replayable": True,
                "input": tool_input,
                "original_output": call.get("output"),
                "replay_output": replay_output,
            }
        )

    unreplayable_count = sum(1 for r in replays if r["replayable"] is False)

    return {
        "finding_id": finding_id,
        "finding_type": finding.get("type"),
        "finding_target": finding.get("target"),
        "claimed_evidence": attempt.get("verdict", {}).get("evidence", ""),
        "total_call_count": len(recorded_calls),
        "replayed_call_count": replayed_count,
        "unreplayable_call_count": unreplayable_count,
        "any_call_replayed": replayed_count > 0,
        "note": (
            "Each entry with replayable: true is a literal replay of a recorded tool call -- "
            "compare original_output vs replay_output to judge whether the claimed impact "
            "still reproduces. Each entry with replayable: false could NOT be re-executed "
            "(no replay support exists for that tool) -- its \"reason\" field explains why; "
            "this is a tooling coverage gap, not evidence against the claim. If "
            "any_call_replayed is false, nothing in this winning attempt could actually be "
            "re-checked at all."
        ),
        "replays": replays,
    }


def register(mcp, scope, executor, timeouts: dict, findings_path: str | None) -> None:
    def replay_probe(finding_id: str) -> dict:
        """Replay the exact tool calls from a finding's winning exploit attempt
        and return original-vs-replayed output for each, so you can judge
        whether the claimed exploitation still reproduces. Pass the finding id
        (e.g. "f3"). This re-runs what already happened -- it does not let you
        craft new requests or explore. Some recorded calls may come back with
        replayable: false instead of a replay_output -- that means no replay
        support exists for that specific tool (a tooling gap), not that the
        call failed to reproduce; see each entry's "reason".
        """
        return run_replay_probe(scope, executor, timeouts, findings_path, finding_id)

    mcp.add_tool(replay_probe)

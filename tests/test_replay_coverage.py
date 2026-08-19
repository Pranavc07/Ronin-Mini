"""Manifest-driven replay coverage audit.

The bug this guards against: a tool lands in a category exploit_agent can
reach, and nobody decides (in manifest.yaml) or implements (in
categories/verify.py's _replay_call) what replay_probe should do with it --
the exact silent gap that mislabeled real Metasploit-confirmed exploits as
false_positive (see categories/verify.py's module docstring).

Three layers of guard, tested here:
  1. manifest.yaml requires every tool to declare replayable ("true"/"false"/
     "partial") -- load_manifest() fails loudly if it's missing, before any
     test even runs (test_load_manifest_raises_if_replayable_missing proves
     this behaviorally, not just by inspection).
  2. Every tool declared replayable "true"/"partial" in a category
     exploit_agent can reach must have a REAL dispatch case in _replay_call --
     not fall through to the generic "not implemented" default
     (test_replayable_true_or_partial_tools_have_real_dispatch).
  3. Every tool declared replayable "false" must never reach real dispatch --
     replay_probe routes it to the explicit "not replayable" stub instead
     (test_replayable_false_tools_are_not_dispatched).

Run with: pytest tests/test_replay_coverage.py -v
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin-tools-mcp"))

import exploit_agent.loop as exploit_loop  # noqa: E402
from categories import verify  # noqa: E402
from manifest import REPLAYABLE_VALUES, load_manifest  # noqa: E402
from scope import Scope  # noqa: E402

MANIFEST = load_manifest()
EXPLOIT_REACHABLE = {name: meta for name, meta in MANIFEST.items() if meta.category in exploit_loop.ALLOWED_CATEGORIES}

# tool name -> the categories.verify module attribute _replay_call should
# dispatch to. Every tool declared replayable "true"/"partial" in a category
# exploit_agent can reach must appear here -- a tool present in EXPLOIT_REACHABLE
# with replayable in ("true", "partial") but missing from this map fails the
# coverage test below with a clear message telling you to add it here.
_DISPATCH_TARGETS = {
    "probe_variant": "run_probe_variant",
    "execute_python": "run_execute_python",
    "nmap": "run_nmap",
    "nikto": "run_nikto",
    "sqlmap": "run_sqlmap",
    "hydra": "run_hydra",
    "gobuster": "run_gobuster",
    "enum4linux": "run_enum4linux",
    "searchsploit": "run_searchsploit",
    "metasploit": "run_metasploit",
    "lookup_attack_technique": "run_lookup_attack_technique",
}


def _scope():
    return Scope(scope_dir=_REPO_ROOT, allowed_hosts=["10.0.0.5"])


def _executor():
    ex = MagicMock()
    ex.KALI_LPORT_RANGE = (44440, 44450)
    return ex


TIMEOUTS = {name: 60 for name in MANIFEST}


# --- layer 1: manifest schema ------------------------------------------------


def test_every_manifest_tool_declares_a_valid_replayable_value():
    for name, meta in MANIFEST.items():
        assert meta.replayable in REPLAYABLE_VALUES, (
            f"{name}: replayable must be one of {REPLAYABLE_VALUES}, got {meta.replayable!r}"
        )


def test_load_manifest_raises_if_replayable_missing(tmp_path):
    """Behavioral proof, not just inspection: a manifest.yaml entry missing
    the replayable field fails load_manifest() itself (KeyError), not just a
    dedicated test -- this fires for the real server, every agent loop, and
    every test file that loads the manifest, the moment a new tool is added
    without deciding this.
    """
    bad_manifest = tmp_path / "manifest.yaml"
    bad_manifest.write_text(
        "categories:\n"
        "  recon: {require_approval: false}\n"
        "tools:\n"
        "  some_new_tool:\n"
        "    category: recon\n"
        "    description: a tool someone forgot to declare replay support for\n"
        "    timeout_seconds: 10\n",
        encoding="utf-8",
    )
    with pytest.raises(KeyError):
        load_manifest(str(bad_manifest))


def test_load_manifest_raises_on_invalid_replayable_value(tmp_path):
    bad_manifest = tmp_path / "manifest.yaml"
    bad_manifest.write_text(
        "categories:\n"
        "  recon: {require_approval: false}\n"
        "tools:\n"
        "  some_new_tool:\n"
        "    category: recon\n"
        "    description: a tool with a typo'd replayable value\n"
        "    timeout_seconds: 10\n"
        '    replayable: "maybe"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_manifest(str(bad_manifest))


# --- layer 2: replayable "true"/"partial" tools have real dispatch ---------


@pytest.mark.parametrize("name", sorted(n for n, m in EXPLOIT_REACHABLE.items() if m.replayable in ("true", "partial")))
def test_replayable_true_or_partial_tool_has_real_dispatch(name):
    """The core coverage check. A tool declared replayable in manifest.yaml,
    reachable by exploit_agent, must have a working _replay_call case -- not
    fall through to the generic "not implemented" default. This is what
    fails automatically the moment someone adds a new tool to a category
    exploit_agent can reach, declares it replayable: "true", and forgets to
    actually implement the dispatch.
    """
    target_attr = _DISPATCH_TARGETS.get(name)
    assert target_attr is not None, (
        f"{name} is declared replayable ({MANIFEST[name].replayable!r}) in manifest.yaml but "
        f"this test doesn't know which categories.verify.run_* function it should dispatch to "
        f"-- add {name!r} to _DISPATCH_TARGETS in tests/test_replay_coverage.py."
    )
    with patch(f"categories.verify.{target_attr}", return_value={"__sentinel__": True}) as mock_run:
        result = verify._replay_call(_scope(), _executor(), TIMEOUTS, name, {})
    assert result == {"__sentinel__": True}, (
        f"{name} is declared replayable ({MANIFEST[name].replayable!r}) in manifest.yaml but "
        f"_replay_call has no real dispatch case for it -- falls through to the generic "
        f"'not replayable' default. Add a dispatch case in categories/verify.py's _replay_call."
    )
    mock_run.assert_called_once()


# --- layer 3: replayable "false" tools never reach real dispatch -----------


def test_replayable_false_tools_are_excluded_from_replayable_tools_set():
    for name, meta in EXPLOIT_REACHABLE.items():
        if meta.replayable != "false":
            continue
        assert name not in verify.REPLAYABLE_TOOLS, (
            f"{name} is declared replayable: \"false\" but is in verify.REPLAYABLE_TOOLS -- "
            "these must stay consistent, REPLAYABLE_TOOLS is derived from the manifest."
        )


def test_replayable_false_tool_gets_structured_stub_via_run_replay_probe(tmp_path):
    """End-to-end through the real entry point (not just REPLAYABLE_TOOLS
    membership): a winning attempt calling a replayable: "false" tool must
    get the explicit stub, never a silent omission or a real dispatch
    attempt. No tool exploit_agent can reach is declared "false" today (see
    manifest.yaml's audit comments), so this constructs a synthetic manifest
    tool to prove the mechanism itself, independent of today's specific
    tool set.
    """
    false_tools = [name for name, meta in EXPLOIT_REACHABLE.items() if meta.replayable == "false"]
    if false_tools:
        # If a real exploit-agent-reachable tool is ever declared "false",
        # exercise the real one instead of a synthetic stand-in.
        tool_name = false_tools[0]
    else:
        tool_name = "synthetic_declared_unreplayable_tool"

    findings = [
        {
            "id": "f1",
            "type": "command_injection",
            "target": "10.0.0.5",
            "status": "exploited",
            "exploit_attempts": [
                {
                    "transcript": [{"tool": tool_name, "input": {}, "output": {"claim": "rce"}}],
                    "verdict": {"status": "exploited", "evidence": "claimed rce"},
                }
            ],
        }
    ]

    result = verify.run_replay_probe(_scope(), _executor(), TIMEOUTS, findings, "f1")

    assert result["any_call_replayed"] is False
    entry = result["replays"][0]
    assert entry["replayable"] is False
    assert "reason" in entry

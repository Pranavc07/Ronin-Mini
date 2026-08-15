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
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin-tools-mcp"))

import exploit_agent.loop as exploit_loop  # noqa: E402
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


def test_every_exploit_agent_tool_is_replayable():
    """If exploit_agent can call it and it can produce a winning attempt,
    verify must be able to replay it. This is the exact gap that caused
    real Metasploit-confirmed exploits to be marked false_positive.
    """
    manifest = load_manifest()
    exploit_agent_tools = {name for name, meta in manifest.items() if meta.category in exploit_loop.ALLOWED_CATEGORIES}
    missing = exploit_agent_tools - set(verify.REPLAYABLE_TOOLS)
    assert not missing, f"exploit_agent can call these tools but verify.REPLAYABLE_TOOLS can't replay them: {missing}"


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

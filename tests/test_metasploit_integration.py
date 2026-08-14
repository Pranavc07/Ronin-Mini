"""End-to-end tests for the metasploit tool: builds the real image, starts
the real long-lived container, and runs real msfconsole commands. Skipped
automatically if Docker isn't available -- same spirit as
test_network_exploit_integration.py.

A real *successful* exploit run needs an actual vulnerable service (the
live check against Metasploitable, not CI-style tests) -- these tests only
confirm the tool actually works: metasploit-framework is installed, and a
real module run against a closed/unreachable port completes cleanly within
its timeout rather than hanging (the actual risk with a non-interactive
`msfconsole -r` invocation).

Slower than the other integration tests -- run on its own when iterating:
pytest tests/test_metasploit_integration.py -v -s
"""

from __future__ import annotations

import os
import shutil
import sys
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ronin-tools-mcp"))

import executor  # noqa: E402
from categories import metasploit as ms  # noqa: E402
from scope import Scope  # noqa: E402

DOCKER_AVAILABLE = shutil.which("docker") is not None


def _dvwa_available() -> bool:
    try:
        urllib.request.urlopen("http://localhost:4280/login.php", timeout=2)
        return True
    except Exception:
        return False


DVWA_AVAILABLE = _dvwa_available()


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="docker not installed or not on PATH")
@pytest.mark.skipif(not DVWA_AVAILABLE, reason="DVWA not reachable at localhost:4280")
class TestMetasploitIntegration:
    @classmethod
    def setup_class(cls):
        error = executor.ensure_kali_container_ready()
        assert error is None, error

    def _scope(self):
        return Scope(scope_dir=".", allowed_hosts=["localhost"])

    def test_metasploit_framework_is_installed(self):
        result = executor.run_in_kali_container(["msfconsole", "-v"], 60)
        assert result.get("returncode") == 0, result
        # msfconsole -v prints to stderr, not stdout -- confirmed directly
        # against the real container, not assumed.
        assert "Framework Version" in result["stderr"]

    def test_lport_range_is_published(self):
        result = executor.run_in_kali_container(["true"], 15)
        assert "error" not in result
        # Confirms the container itself is up with the port range from
        # ensure_kali_container_ready(); actual reachability from outside
        # the host isn't testable here without a real listener + external
        # client, covered by the live check against Metasploitable instead.
        assert executor._kali_container_has_published_ports()

    def test_vsftpd_backdoor_against_closed_port_completes_without_hanging(self):
        # DVWA doesn't run vsftpd, so this module will fail to connect/exploit
        # -- the point is confirming a real, non-interactive msfconsole -r run
        # completes cleanly within its timeout rather than hanging waiting for
        # interactive input.
        result = ms.run_metasploit(
            self._scope(),
            executor,
            120,
            "exploit/unix/ftp/vsftpd_234_backdoor",
            "localhost",
            21,
            None,
            None,
            None,
            None,
            None,
        )
        assert "error" not in result or "timed out" not in result.get("error", "")
        if "returncode" in result:
            assert result["returncode"] in (0, 1)  # msfconsole itself exits cleanly either way

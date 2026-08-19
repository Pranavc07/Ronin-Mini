"""Scope enforcement shared by every tool category: filesystem paths and
network targets both funnel through here before a tool touches anything.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a tool call would touch something outside the allowed scope."""


class Scope:
    def __init__(self, scope_dir: str, allowed_hosts: list[str]):
        self.scope_dir = os.path.realpath(scope_dir)
        self.allowed_hosts = {h.lower() for h in allowed_hosts}

    def resolve_safe_path(self, user_path: str) -> str:
        """Resolve user_path against scope_dir and verify it does not escape it.

        Ported from Ronin-Mini's tools.py::resolve_safe_path. Uses realpath on
        both sides so a symlink inside scope_dir pointing outside it is caught
        before the containment check runs.
        """
        if os.path.isabs(user_path):
            candidate = user_path
        else:
            candidate = os.path.join(self.scope_dir, user_path)
        target_real = os.path.realpath(candidate)

        if target_real == self.scope_dir:
            return target_real
        if not target_real.startswith(self.scope_dir + os.sep):
            raise ScopeError(
                f"Path '{user_path}' resolves outside the allowed scope directory"
            )
        return target_real

    def validate_host(self, url_or_hostname: str) -> str:
        """Verify a URL or bare hostname's host is in the allowed set.

        Returns the validated hostname (lowercased). Every network tool
        (http_request, dns_lookup, probe_variant) must call this before
        touching the network -- the allowlist is enforced here in code, not
        left to the model's judgment or prompt instructions alone.
        """
        parsed = urlparse(url_or_hostname)
        host = (parsed.hostname or url_or_hostname).lower()
        if host not in self.allowed_hosts:
            raise ScopeError(
                f"Host '{host}' is outside the allowed scope {sorted(self.allowed_hosts)}"
            )
        return host

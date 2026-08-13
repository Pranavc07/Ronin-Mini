"""Unit tests for manifest.py's require_approval resolution: each tool's
require_approval flag comes from its category's default in manifest.yaml's
categories: block, not a per-tool setting.

Run with: pytest tests/test_manifest.py -v
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin-tools-mcp"))

from manifest import load_manifest  # noqa: E402

GATED_TOOLS = {"probe_variant", "execute_python", "replay_probe"}
UNGATED_TOOLS = {"http_request", "dns_lookup", "code_search", "file_read", "lookup_attack_technique"}


def test_gated_tools_require_approval():
    manifest = load_manifest()
    for name in GATED_TOOLS:
        assert manifest[name].require_approval is True, name


def test_ungated_tools_do_not_require_approval():
    manifest = load_manifest()
    for name in UNGATED_TOOLS:
        assert manifest[name].require_approval is False, name


def test_every_tool_has_a_require_approval_bool():
    manifest = load_manifest()
    for name, meta in manifest.items():
        assert isinstance(meta.require_approval, bool), name

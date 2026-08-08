"""Unit tests for ronin-tools-mcp/scope.py -- the security boundary every
tool call funnels through. No subprocess, no network, no MCP protocol here;
see test_mcp_server.py for the end-to-end version through the real server.

Run with: pytest tests/test_scope.py -v
"""

import os

import pytest

from scope import Scope, ScopeError


@pytest.fixture()
def scope(tmp_path):
    root = tmp_path / "scope"
    root.mkdir()
    (root / "inside.txt").write_text("safe content")
    sub = root / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("top secret")

    return Scope(scope_dir=str(root), allowed_hosts=["localhost", "example.com"])


# --- resolve_safe_path ---


def test_relative_path_within_root_ok(scope):
    resolved = scope.resolve_safe_path("inside.txt")
    assert resolved == os.path.realpath(os.path.join(scope.scope_dir, "inside.txt"))


def test_nested_relative_path_ok(scope):
    resolved = scope.resolve_safe_path(os.path.join("sub", "nested.txt"))
    assert resolved.endswith("nested.txt")


def test_dot_traversal_blocked(scope):
    with pytest.raises(ScopeError):
        scope.resolve_safe_path(os.path.join("..", "outside", "secret.txt"))


def test_deep_dot_traversal_blocked(scope):
    with pytest.raises(ScopeError):
        scope.resolve_safe_path(os.path.join("sub", "..", "..", "outside", "secret.txt"))


def test_absolute_path_outside_root_blocked(scope, tmp_path):
    outside_file = str(tmp_path / "outside" / "secret.txt")
    with pytest.raises(ScopeError):
        scope.resolve_safe_path(outside_file)


def test_absolute_path_inside_root_ok(scope):
    inside_file = os.path.join(scope.scope_dir, "inside.txt")
    resolved = scope.resolve_safe_path(inside_file)
    assert resolved == os.path.realpath(inside_file)


def test_root_itself_ok(scope):
    resolved = scope.resolve_safe_path(".")
    assert resolved == scope.scope_dir


# --- validate_host ---


def test_allowed_bare_hostname_ok(scope):
    assert scope.validate_host("localhost") == "localhost"


def test_allowed_url_host_ok(scope):
    assert scope.validate_host("http://localhost:3000/rest/user/login") == "localhost"


def test_host_case_insensitive(scope):
    assert scope.validate_host("http://LocalHost:3000/") == "localhost"


def test_disallowed_host_blocked(scope):
    with pytest.raises(ScopeError):
        scope.validate_host("http://evil.example.org/steal")


def test_disallowed_hostname_blocked(scope):
    with pytest.raises(ScopeError):
        scope.validate_host("attacker.net")

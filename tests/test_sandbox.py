"""Path traversal / sandbox escape tests for tools.py.

Run with: pytest tests/test_sandbox.py -v
"""

import os
import shutil

import pytest

import tools

RG_AVAILABLE = shutil.which("rg") is not None


@pytest.fixture()
def scope_dir(tmp_path):
    root = tmp_path / "scope"
    root.mkdir()
    (root / "inside.txt").write_text("safe content")
    sub = root / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("top secret")

    return str(root)


def test_relative_path_within_root_ok(scope_dir):
    resolved = tools.resolve_safe_path(scope_dir, "inside.txt")
    assert resolved == os.path.realpath(os.path.join(scope_dir, "inside.txt"))


def test_nested_relative_path_ok(scope_dir):
    resolved = tools.resolve_safe_path(scope_dir, os.path.join("sub", "nested.txt"))
    assert resolved.endswith("nested.txt")


def test_dot_traversal_blocked(scope_dir):
    with pytest.raises(ValueError):
        tools.resolve_safe_path(scope_dir, os.path.join("..", "outside", "secret.txt"))


def test_deep_dot_traversal_blocked(scope_dir):
    with pytest.raises(ValueError):
        tools.resolve_safe_path(scope_dir, os.path.join("sub", "..", "..", "outside", "secret.txt"))


def test_absolute_path_outside_root_blocked(scope_dir, tmp_path):
    outside_file = str(tmp_path / "outside" / "secret.txt")
    with pytest.raises(ValueError):
        tools.resolve_safe_path(scope_dir, outside_file)


def test_absolute_path_inside_root_ok(scope_dir):
    inside_file = os.path.join(scope_dir, "inside.txt")
    resolved = tools.resolve_safe_path(scope_dir, inside_file)
    assert resolved == os.path.realpath(inside_file)


def test_root_itself_ok(scope_dir):
    resolved = tools.resolve_safe_path(scope_dir, ".")
    assert resolved == os.path.realpath(scope_dir)


def test_file_read_blocks_traversal(scope_dir):
    result = tools.file_read(os.path.join("..", "outside", "secret.txt"), scope_dir)
    assert "error" in result
    assert "secret" not in result.get("content", "")


def test_file_read_within_scope_ok(scope_dir):
    result = tools.file_read("inside.txt", scope_dir)
    assert result.get("content") == "safe content"


def test_file_read_nonexistent_file(scope_dir):
    result = tools.file_read("does-not-exist.txt", scope_dir)
    assert "error" in result


def test_code_search_blocks_traversal(scope_dir, tmp_path):
    # Path traversal must be rejected before ripgrep is ever invoked, so this
    # runs regardless of whether rg is installed.
    result = tools.code_search(pattern="secret", path=os.path.join("..", "outside"), scope_dir=scope_dir)
    assert "error" in result


@pytest.mark.skipif(not RG_AVAILABLE, reason="ripgrep (rg) not installed on PATH")
def test_code_search_within_scope_ok(scope_dir):
    result = tools.code_search(pattern="safe", path=".", scope_dir=scope_dir)
    assert "error" not in result
    assert result["match_count"] >= 1


def test_truncate_short_text_unchanged():
    assert tools.truncate("short") == "short"


def test_truncate_long_text_capped():
    long_text = "a" * 5000
    truncated = tools.truncate(long_text, limit=4000)
    assert truncated.startswith("a" * 4000)
    assert "truncated" in truncated

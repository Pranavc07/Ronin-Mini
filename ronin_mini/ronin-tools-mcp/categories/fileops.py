"""fileops category: code_search, file_read -- ported from Ronin-Mini's
tools.py, sandbox checks intact (now enforced via scope.Scope).
"""

from __future__ import annotations

import json
import os
import subprocess

from manifest import DEFAULT_TIMEOUT_SECONDS


def register(mcp, scope, executor, timeouts: dict) -> None:
    def code_search(pattern: str, path: str = ".") -> dict:
        """Search source code for a regex pattern using ripgrep, scoped to the allowed directory."""
        try:
            safe_path = scope.resolve_safe_path(path or ".")
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

        if not os.path.exists(safe_path):
            return {"error": f"Path does not exist: {path}"}

        timeout = timeouts.get("code_search", DEFAULT_TIMEOUT_SECONDS)
        try:
            proc = subprocess.run(
                ["rg", "--json", "--max-count", "50", pattern, safe_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return {"error": "ripgrep (rg) is not installed or not on PATH"}
        except subprocess.TimeoutExpired:
            return {"error": f"code_search timed out after {timeout}s"}

        if proc.returncode not in (0, 1):  # 1 == no matches, still valid
            return {"error": executor.truncate(proc.stderr or "ripgrep failed")}

        matches = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "match":
                continue
            data = obj.get("data", {})
            matches.append(
                {
                    "path": data.get("path", {}).get("text"),
                    "line_number": data.get("line_number"),
                    "line": (data.get("lines", {}).get("text") or "").rstrip("\n"),
                }
            )

        return {
            "pattern": pattern,
            "path": path,
            "match_count": len(matches),
            "matches": executor.truncate(json.dumps(matches)),
        }

    def file_read(path: str) -> dict:
        """Read a file's contents, read-only, scoped to the allowed directory."""
        try:
            safe_path = scope.resolve_safe_path(path)
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

        if not os.path.isfile(safe_path):
            return {"error": f"Not a file: {path}"}

        try:
            with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            return {"error": f"{type(e).__name__}: {e}"}

        return {"path": path, "content": executor.truncate(content)}

    mcp.add_tool(code_search)
    mcp.add_tool(file_read)

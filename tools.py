"""Sandboxed tool implementations for the pentest agent harness.

Four tools only: http_request, dns_lookup, code_search, file_read.
Every tool call is wrapped by loop.py in a hard 15s timeout via a thread pool.
"""

import json
import os
import socket
import subprocess

import requests

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None

MAX_OUTPUT_CHARS = 4000
HTTP_TIMEOUT_SECONDS = 15
RG_TIMEOUT_SECONDS = 15
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT")


def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


def resolve_safe_path(root: str, user_path: str) -> str:
    """Resolve user_path against root and verify it does not escape root.

    Raises ValueError if the resolved path is outside root. Uses
    os.path.realpath so symlinks are resolved before the containment check.
    """
    root_real = os.path.realpath(root)
    if os.path.isabs(user_path):
        candidate = user_path
    else:
        candidate = os.path.join(root_real, user_path)
    target_real = os.path.realpath(candidate)

    if target_real == root_real:
        return target_real
    if not target_real.startswith(root_real + os.sep):
        raise ValueError(
            f"Path '{user_path}' resolves outside the allowed scope directory"
        )
    return target_real


def http_request(method: str, url: str, headers: dict | None = None, body: str | None = None) -> dict:
    """Send an HTTP request via `requests`, in-process, 15s timeout."""
    method = (method or "GET").upper()
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers or {},
            data=body,
            timeout=HTTP_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": truncate(resp.text),
            "final_url": resp.url,
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"{type(e).__name__}: {e}"}


def dns_lookup(hostname: str) -> dict:
    """Resolve A/AAAA/CNAME/TXT records for hostname via dnspython (fallback to socket)."""
    results: dict[str, list[str]] = {}
    errors: dict[str, str] = {}

    if dns is not None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = HTTP_TIMEOUT_SECONDS
        resolver.lifetime = HTTP_TIMEOUT_SECONDS
        for rtype in DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(hostname, rtype)
                results[rtype] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                results[rtype] = []
            except dns.resolver.NXDOMAIN:
                errors["NXDOMAIN"] = f"{hostname} does not exist"
                break
            except Exception as e:  # noqa: BLE001
                errors[rtype] = f"{type(e).__name__}: {e}"
    else:  # pragma: no cover - fallback path when dnspython missing
        try:
            infos = socket.getaddrinfo(hostname, None)
            addrs = sorted({info[4][0] for info in infos})
            results["A"] = [a for a in addrs if ":" not in a]
            results["AAAA"] = [a for a in addrs if ":" in a]
        except socket.gaierror as e:
            errors["socket"] = str(e)

    out = {"hostname": hostname, "records": results}
    if errors:
        out["errors"] = errors
    return out


def code_search(pattern: str, path: str, scope_dir: str) -> dict:
    """ripgrep --json wrapper, scoped to scope_dir. No shell, argument list only."""
    try:
        safe_path = resolve_safe_path(scope_dir, path or ".")
    except ValueError as e:
        return {"error": str(e)}

    if not os.path.exists(safe_path):
        return {"error": f"Path does not exist: {path}"}

    try:
        proc = subprocess.run(
            ["rg", "--json", "--max-count", "50", pattern, safe_path],
            capture_output=True,
            text=True,
            timeout=RG_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return {"error": "ripgrep (rg) is not installed or not on PATH"}
    except subprocess.TimeoutExpired:
        return {"error": f"code_search timed out after {RG_TIMEOUT_SECONDS}s"}

    if proc.returncode not in (0, 1):  # 1 == no matches, still valid
        return {"error": truncate(proc.stderr or "ripgrep failed")}

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

    return {"pattern": pattern, "path": path, "match_count": len(matches), "matches": truncate(json.dumps(matches))}


def file_read(path: str, scope_dir: str) -> dict:
    """Read-only file read, scoped to scope_dir, capped at ~4000 chars."""
    try:
        safe_path = resolve_safe_path(scope_dir, path)
    except ValueError as e:
        return {"error": str(e)}

    if not os.path.isfile(safe_path):
        return {"error": f"Not a file: {path}"}

    try:
        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e}"}

    return {"path": path, "content": truncate(content)}

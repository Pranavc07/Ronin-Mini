"""Shared execution wrappers used by every tool category: HTTP requests and
subprocess calls, with consistent truncation and error handling.
"""

from __future__ import annotations

import os
import subprocess
import uuid

import requests

MAX_OUTPUT_CHARS = 4000

DOCKER_IMAGE = "ronin-exploit-runtime"
_DOCKERFILE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "docker")
_DOCKERFILE_PATH = os.path.join(_DOCKERFILE_DIR, "exploit-runtime.Dockerfile")
DOCKER_MEMORY_LIMIT = "256m"
DOCKER_CPU_LIMIT = "0.5"
DOCKER_PIDS_LIMIT = "64"


def truncate(text: str | None, limit: int = MAX_OUTPUT_CHARS) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


def run_http(
    method: str,
    url: str,
    headers: dict | None,
    body: str | None,
    timeout: int,
) -> dict:
    try:
        resp = requests.request(
            method=(method or "GET").upper(),
            url=url,
            headers=headers or {},
            data=body,
            timeout=timeout,
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


def run_subprocess(args: list[str], timeout: int) -> dict:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": truncate(proc.stdout),
            "stderr": truncate(proc.stderr),
        }
    except FileNotFoundError as e:
        return {"error": f"{type(e).__name__}: {e}"}
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}


def ensure_docker_image_built() -> dict | None:
    """Build the execute_python sandbox image if it isn't already present.
    Returns an error dict on failure, None on success (including "already
    built"). Docker layer caching means this is a no-op after the first call.
    """
    try:
        check = subprocess.run(
            ["docker", "image", "inspect", DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return {"error": "docker is not installed or not on PATH"}

    if check.returncode == 0:
        return None

    try:
        build = subprocess.run(
            ["docker", "build", "-t", DOCKER_IMAGE, "-f", _DOCKERFILE_PATH, _DOCKERFILE_DIR],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"error": "Timed out building the execute_python sandbox image"}

    if build.returncode != 0:
        return {"error": f"Failed to build sandbox image: {truncate(build.stderr)}"}
    return None


def run_docker_python(scratch_dir: str, timeout: int) -> dict:
    """Run `code` inside an ephemeral, resource-capped, network-isolated-
    from-the-host-filesystem Docker container. `scratch_dir` is the ONLY
    thing mounted in; everything else on the host is unreachable from
    inside the container regardless of what the code tries. The caller is
    responsible for writing the script (and any helper modules) into
    scratch_dir before calling this, and cleaning it up after.
    """
    build_error = ensure_docker_image_built()
    if build_error:
        return build_error

    container_name = f"ronin-exec-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--memory",
        DOCKER_MEMORY_LIMIT,
        "--memory-swap",
        DOCKER_MEMORY_LIMIT,  # no swap beyond the memory limit itself
        "--cpus",
        DOCKER_CPU_LIMIT,
        "--pids-limit",
        DOCKER_PIDS_LIMIT,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=16m",
        "--network",
        "bridge",
        "--add-host",
        "host.docker.internal:host-gateway",  # no-op on Docker Desktop, needed on native Linux
        "-v",
        f"{scratch_dir}:/workspace:rw",
        "-w",
        "/workspace",
        DOCKER_IMAGE,
        "python",
        "exploit.py",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Belt-and-suspenders: --rm cleans up on normal exit, but if `docker
        # run` itself was killed by our timeout, the container may still be
        # running. Make sure it's actually gone.
        subprocess.run(["docker", "kill", container_name], capture_output=True, text=True, timeout=10)
        return {"error": f"execute_python timed out after {timeout}s (container killed)"}
    except FileNotFoundError:
        return {"error": "docker is not installed or not on PATH"}

    return {
        "returncode": proc.returncode,
        "stdout": truncate(proc.stdout),
        "stderr": truncate(proc.stderr),
    }

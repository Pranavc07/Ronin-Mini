"""Shared execution wrappers used by every tool category: HTTP requests and
subprocess calls, with consistent truncation and error handling.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from urllib.parse import urljoin, urlparse

import requests

MAX_OUTPUT_CHARS = 4000

# Redirects are followed manually (allow_redirects=False on every actual
# request) rather than letting requests.request follow them automatically,
# so every hop's destination gets independently re-validated against scope
# before it's followed -- a target can't redirect an in-scope request out of
# scope. 5 is deliberately conservative: plenty for a legitimate same-app
# redirect (http->https, a login redirect, a www redirect) while making a
# redirect loop or an absurd chain fail fast rather than hang. Sanity-
# checked against DVWA's actual login mechanic (POST /login.php -> a single
# 302 to index.php on success) which is well within this -- not empirically
# re-verified against a live DVWA instance in this pass (Docker wasn't
# running), so treat this as reasoned, not measured, and re-check live if
# a DVWA regression run ever burns budget specifically on redirect
# rejection rather than the already-documented session/login limitation.
MAX_REDIRECTS = 5
_ALLOWED_REDIRECT_SCHEMES = {"http", "https"}
_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

DOCKER_IMAGE = "ronin-exploit-runtime"
_DOCKERFILE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "docker")
_DOCKERFILE_PATH = os.path.join(_DOCKERFILE_DIR, "exploit-runtime.Dockerfile")
DOCKER_MEMORY_LIMIT = "256m"
DOCKER_CPU_LIMIT = "0.5"
DOCKER_PIDS_LIMIT = "64"

KALI_IMAGE = "ronin-kali-tools"
KALI_CONTAINER_NAME = "ronin-kali-box"
_KALI_DOCKERFILE_PATH = os.path.join(_DOCKERFILE_DIR, "kali-tools.Dockerfile")
KALI_BUILD_TIMEOUT_SECONDS = 1800  # apt-installing nmap/sqlmap/exploitdb etc. is much slower than the execute_python image

# Fixed, modest published port range for metasploit's reverse-payload
# listeners -- not "any port," so categories/metasploit.py can validate
# `lport` against something concrete instead of silently opening a listener
# nothing can reach. Docker Desktop on Windows publishes container ports to
# all host interfaces by default, so an external target can reach these via
# the host's IP on whatever network route exists (see CLAUDE.md's LHOST note).
KALI_LPORT_RANGE = (44440, 44450)


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
    scope,
) -> dict:
    """Send an HTTP request, following redirects manually rather than via
    requests' own allow_redirects=True. Every hop -- including the first --
    is independently re-validated against `scope.validate_host` (the SAME
    check every other network tool uses, not a separate/weaker one) before
    it's requested, so a target cannot redirect an in-scope request to an
    out-of-scope host. Non-http(s) redirect targets (e.g. file://) are
    rejected outright. A full record of every hop -- validated or rejected
    -- is returned as "redirect_chain" so it's visible in the transcript.

    This is scope enforcement (does the destination match the allowlist?),
    not a general SSRF-proof network boundary -- it doesn't resolve DNS to
    check for a rebinding attack against an *allowed* hostname, for example.
    See CLAUDE.md's redirect-validation section for the documented scope.
    """
    chain: list[dict] = []
    current_url = url
    current_method = (method or "GET").upper()
    current_body = body

    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in _ALLOWED_REDIRECT_SCHEMES:
            chain.append({"url": current_url, "allowed": False, "reason": f"unsupported scheme {parsed.scheme!r}"})
            return {"error": f"Redirect to unsupported scheme {parsed.scheme!r}: {current_url}", "redirect_chain": chain}

        try:
            scope.validate_host(current_url)
        except Exception as e:  # noqa: BLE001 -- ScopeError from scope.py, kept generic to not import it here
            chain.append({"url": current_url, "allowed": False, "reason": str(e)})
            return {"error": str(e), "redirect_chain": chain}

        try:
            resp = requests.request(
                method=current_method,
                url=current_url,
                headers=headers or {},
                data=current_body,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            chain.append({"url": current_url, "allowed": True, "error": f"{type(e).__name__}: {e}"})
            return {"error": f"{type(e).__name__}: {e}", "redirect_chain": chain}

        chain.append({"url": current_url, "allowed": True, "status_code": resp.status_code})

        location = resp.headers.get("Location") if resp.status_code in _REDIRECT_STATUS_CODES else None
        if not location:
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": truncate(resp.text),
                "final_url": current_url,
                "redirect_chain": chain,
            }

        if hop == MAX_REDIRECTS:
            chain.append({"url": location, "allowed": False, "reason": f"exceeded max redirect count ({MAX_REDIRECTS})"})
            return {"error": f"Exceeded max redirect count ({MAX_REDIRECTS})", "redirect_chain": chain}

        # 303 always downgrades to GET; 301/302 downgrade a POST to GET too,
        # matching requests' own default behavior for those codes when it
        # follows redirects itself -- not a scope-specific choice, just
        # preserving the same semantics now that this is done manually.
        if resp.status_code == 303 or (resp.status_code in (301, 302) and current_method == "POST"):
            current_method = "GET"
            current_body = None
        current_url = urljoin(current_url, location)

    return {"error": "redirect loop guard exhausted", "redirect_chain": chain}  # unreachable given the loop bound


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


def _kali_container_exists() -> bool:
    try:
        result = subprocess.run(
            ["docker", "inspect", KALI_CONTAINER_NAME, "--format", "{{.State.Running}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0


def _kali_container_has_published_ports() -> bool:
    """Checked via the container's own config (works whether it's running or
    stopped), not `docker port` (which is unreliable on stopped containers).
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", KALI_CONTAINER_NAME, "--format", "{{json .HostConfig.PortBindings}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return False
    if result.returncode != 0:
        return False
    return f"{KALI_LPORT_RANGE[0]}/tcp" in result.stdout


def _create_kali_container() -> dict | None:
    port_range = f"{KALI_LPORT_RANGE[0]}-{KALI_LPORT_RANGE[1]}"
    run = subprocess.run(
        [
            "docker", "run", "-d", "--name", KALI_CONTAINER_NAME,
            "--network", "bridge",
            "--add-host", "host.docker.internal:host-gateway",
            "-p", f"{port_range}:{port_range}",  # metasploit reverse-payload listeners
            KALI_IMAGE, "sleep", "infinity",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if run.returncode != 0:
        return {"error": f"Failed to start {KALI_CONTAINER_NAME}: {truncate(run.stderr)}"}
    return None


def ensure_kali_container_ready() -> dict | None:
    """Build the Kali image if it isn't already present, and make sure a
    long-lived container from it is running with the metasploit reverse-
    payload port range published. Unlike execute_python's ephemeral
    per-call containers, this one is started once and reused across tool
    calls -- nmap/sqlmap/msfconsole/etc. run via `docker exec` against it.
    Idempotent: a no-op after the first successful call.

    Returns an error dict on failure, None on success.
    """
    try:
        image_check = subprocess.run(
            ["docker", "image", "inspect", KALI_IMAGE], capture_output=True, text=True, timeout=15
        )
    except FileNotFoundError:
        return {"error": "docker is not installed or not on PATH"}

    if image_check.returncode != 0:
        try:
            build = subprocess.run(
                ["docker", "build", "-t", KALI_IMAGE, "-f", _KALI_DOCKERFILE_PATH, _DOCKERFILE_DIR],
                capture_output=True,
                text=True,
                timeout=KALI_BUILD_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"Timed out building the {KALI_IMAGE} image"}
        if build.returncode != 0:
            return {"error": f"Failed to build {KALI_IMAGE}: {truncate(build.stderr)}"}

    if not _kali_container_exists():
        return _create_kali_container()

    if not _kali_container_has_published_ports():
        # Docker can't add port publishing to an already-created container --
        # the only way to get the metasploit LPORT range published is to
        # remove and recreate it. This is a real behavior change from a
        # previously-created container (e.g. from before this port range
        # existed) and will lose anything running inside it (nothing persists
        # in this container by design -- it's stateless tooling, not data).
        subprocess.run(["docker", "rm", "-f", KALI_CONTAINER_NAME], capture_output=True, text=True, timeout=30)
        return _create_kali_container()

    try:
        state = subprocess.run(
            ["docker", "inspect", KALI_CONTAINER_NAME, "--format", "{{.State.Running}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return {"error": "docker is not installed or not on PATH"}

    if state.stdout.strip() != "true":
        start = subprocess.run(
            ["docker", "start", KALI_CONTAINER_NAME], capture_output=True, text=True, timeout=30
        )
        if start.returncode != 0:
            return {"error": f"Failed to start {KALI_CONTAINER_NAME}: {truncate(start.stderr)}"}

    return None


def run_in_kali_container(args: list[str], timeout: int) -> dict:
    """Run a command inside the long-lived Kali tools container via `docker
    exec`. `args` is a real argv list (e.g. ["nmap", "-F", "-Pn", target]) --
    never a shell string -- so there is no shell for injected metacharacters
    to reach regardless of what ends up in a parameter.
    """
    ready_error = ensure_kali_container_ready()
    if ready_error:
        return ready_error

    cmd = ["docker", "exec", KALI_CONTAINER_NAME, *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "docker is not installed or not on PATH"}

    return {
        "returncode": proc.returncode,
        "stdout": truncate(proc.stdout),
        "stderr": truncate(proc.stderr),
    }


def write_file_in_kali_container(path: str, content: str) -> dict | None:
    """Write `content` to `path` inside the long-lived Kali container, via
    stdin piped through `docker exec -i ... tee` -- no shell, no quoting of
    the content itself (it's passed as raw bytes through subprocess's
    `input=`, not interpolated into a command string). Used by
    categories/metasploit.py to get a resource script into the container
    before running it (this container has no bind mount the way
    execute_python's ephemeral containers do, so a file has to be written
    in-place rather than mounted in).

    Returns an error dict on failure, None on success.
    """
    ready_error = ensure_kali_container_ready()
    if ready_error:
        return ready_error

    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", KALI_CONTAINER_NAME, "tee", path],
            input=content,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out writing {path} into {KALI_CONTAINER_NAME}"}
    except FileNotFoundError:
        return {"error": "docker is not installed or not on PATH"}

    if proc.returncode != 0:
        return {"error": f"Failed to write {path} into {KALI_CONTAINER_NAME}: {truncate(proc.stderr)}"}
    return None

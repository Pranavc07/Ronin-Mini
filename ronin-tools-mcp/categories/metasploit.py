"""metasploit_exploit category: metasploit -- runs a real Metasploit exploit
module against a scope-validated target inside the long-lived Kali
container. exploit_agent-only (never recon_agent) -- see manifest.yaml's
categories: block and CLAUDE.md for why.

Unlike every other tool in this repo, `module` is a free-text Metasploit
module path, not a fixed enum -- an explicit, deliberate exception (see this
category's module docstring in CLAUDE.md for the full reasoning). What IS
still enforced, regardless of that choice:
  - scope.validate_host on the target, same as every other network tool.
  - A resource-script injection guard: module/payload/options/
    post_exploit_command may not contain newlines, since they're written
    into a line-based .rc file the console interprets one command per line.
    This isn't about restricting *which* module runs -- it's preventing a
    parameter value from smuggling in *extra* commands beyond the ones this
    code intends to send.
  - lport, when given, must fall inside the fixed published range
    (executor.KALI_LPORT_RANGE) -- otherwise a reverse payload would open a
    listener nothing can reach, failing silently far from a useful error.
"""

from __future__ import annotations

import uuid

from manifest import DEFAULT_TIMEOUT_SECONDS

from .network_exploit import _container_target

POST_EXPLOIT_WAIT_SECONDS = 3


def _has_newline(value: str | None) -> bool:
    return value is not None and ("\n" in value or "\r" in value)


def _build_resource_script(
    module: str,
    target: str,
    port: int | None,
    payload: str | None,
    lhost: str | None,
    lport: int | None,
    options: dict[str, str] | None,
    post_exploit_command: str | None,
) -> str:
    lines = [f"use {module}", f"set RHOSTS {target}"]
    if port is not None:
        lines.append(f"set RPORT {port}")
    if payload is not None:
        lines.append(f"set PAYLOAD {payload}")
    if lhost is not None:
        lines.append(f"set LHOST {lhost}")
    if lport is not None:
        lines.append(f"set LPORT {lport}")
    for key, value in (options or {}).items():
        lines.append(f"set {key} {value}")
    # -z backgrounds any opened session immediately instead of dropping into
    # interactive mode, which would hang a non-interactive `msfconsole -r` run.
    lines.append("exploit -z")
    if post_exploit_command is not None:
        lines.append(f"sleep {POST_EXPLOIT_WAIT_SECONDS}")
        lines.append(f'sessions -c "{post_exploit_command}" -i 1')
    # Kill any session before exiting -- hygiene for a long-lived container
    # reused across many calls, not left to accumulate orphaned sessions.
    lines.append("sessions -K")
    lines.append("exit -y")
    return "\n".join(lines) + "\n"


def run_metasploit(
    scope,
    executor,
    timeout: int,
    module: str,
    target: str,
    port: int | None,
    payload: str | None,
    lhost: str | None,
    lport: int | None,
    options: dict[str, str] | None,
    post_exploit_command: str | None,
) -> dict:
    try:
        scope.validate_host(target)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    if not module or not module.strip():
        return {"error": "module must be a non-empty Metasploit module path"}

    for name, value in (
        ("module", module),
        ("payload", payload),
        ("post_exploit_command", post_exploit_command),
    ):
        if _has_newline(value):
            return {"error": f"{name} must not contain newlines"}
    for key, value in (options or {}).items():
        if _has_newline(key) or _has_newline(value):
            return {"error": "options keys/values must not contain newlines"}

    if lport is not None:
        low, high = executor.KALI_LPORT_RANGE
        if not (low <= lport <= high):
            return {
                "error": (
                    f"lport {lport} is outside the published range {low}-{high} -- "
                    "a reverse payload listener on any other port would be unreachable"
                )
            }

    ready_error = executor.ensure_kali_container_ready()
    if ready_error:
        return ready_error

    script_content = _build_resource_script(
        module, _container_target(target), port, payload, lhost, lport, options, post_exploit_command
    )
    script_path = f"/tmp/ronin_msf_{uuid.uuid4().hex[:12]}.rc"

    write_result = executor.write_file_in_kali_container(script_path, script_content)
    if write_result is not None:
        return write_result

    return executor.run_in_kali_container(["msfconsole", "-q", "-r", script_path], timeout)


def register(mcp, scope, executor, timeouts: dict) -> None:
    def metasploit(
        module: str,
        target: str,
        port: int | None = None,
        payload: str | None = None,
        lhost: str | None = None,
        lport: int | None = None,
        options: dict[str, str] | None = None,
        post_exploit_command: str | None = None,
    ) -> dict:
        """Run a Metasploit exploit module against a target. module is a
        full module path (e.g. "exploit/unix/ftp/vsftpd_234_backdoor").
        port sets RPORT if the module needs it. For payload-based modules,
        set payload (e.g. "cmd/unix/reverse") plus lhost/lport for reverse
        payloads -- lport must be within the published range (44440-44450).
        options accepts any other module-specific `set KEY VALUE` pairs.
        post_exploit_command, if given, is run in the opened session (once
        established) as concrete evidence before the session is closed.
        Judge success from the returned msfconsole output (e.g. "Command
        shell session N opened" / "Meterpreter session N opened" /
        "Exploit completed, but no session was created") -- this tool
        returns raw output, it does not pre-judge exploitation for you.
        """
        max_timeout = timeouts.get("metasploit", DEFAULT_TIMEOUT_SECONDS)
        return run_metasploit(
            scope, executor, max_timeout, module, target, port, payload, lhost, lport, options, post_exploit_command
        )

    mcp.add_tool(metasploit)

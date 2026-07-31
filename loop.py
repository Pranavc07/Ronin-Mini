"""Tool-calling agent loop for the pentest harness.

A single-threaded, synchronous loop: call Claude, execute any requested
tools under a hard per-call timeout, feed results back, repeat until the
model stops calling tools or a cap (iteration / wall-clock) is hit.
"""

import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone

import anthropic

import tools

TOOL_TIMEOUT_SECONDS = 15

FINDING_START = "<<<FINDING>>>"
FINDING_END = "<<<END_FINDING>>>"
FINDING_RE = re.compile(
    re.escape(FINDING_START) + r"(.*?)" + re.escape(FINDING_END), re.DOTALL
)

TOOL_DEFINITIONS = [
    {
        "name": "http_request",
        "description": (
            "Send an HTTP request to a target URL. Use to probe endpoints, "
            "inspect responses, headers, and test for common web "
            "vulnerabilities. Response body is truncated to ~4000 chars. "
            "15s timeout."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "description": "HTTP method",
                },
                "url": {"type": "string", "description": "Full URL to request"},
                "headers": {
                    "type": "object",
                    "description": "Optional HTTP headers as key-value pairs",
                },
                "body": {"type": "string", "description": "Optional request body"},
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Resolve A/AAAA/CNAME/TXT DNS records for a hostname. 15s timeout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Hostname to resolve"}
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "code_search",
        "description": (
            "Search source code for a regex pattern using ripgrep. Scoped to "
            "the allowed scope directory only; paths cannot escape it. 15s timeout."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "path": {
                    "type": "string",
                    "description": "Path within the scope directory to search (default '.')",
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "file_read",
        "description": (
            "Read a file's contents, read-only. Scoped to the allowed scope "
            "directory only; paths cannot escape it. Output truncated to "
            "~4000 chars."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file to read"}
            },
            "required": ["path"],
        },
    },
]

SYSTEM_PROMPT_TEMPLATE = """You are an authorized penetration testing assistant. You have \
been explicitly engaged to test the target below for security vulnerabilities. All testing \
is authorized and in-scope; the operator has confirmed they own this target or have written \
permission to test it.

TARGET: {target}
OBJECTIVE: {objective}

You have access to exactly four tools, described here and available via native tool use:

{tool_schemas}

Rules:
- Only interact with the stated target. Do not pivot to unrelated hosts.
- code_search and file_read are scoped to a local directory ({scope_dir}) and cannot escape it.
- Reason step by step: form a hypothesis, use a tool to test it, interpret the result, and \
decide the next step.
- Whenever you identify a genuine vulnerability or noteworthy security finding, emit it \
immediately using EXACTLY this format (raw JSON between the markers, no markdown fences):

{finding_start}
{{"title": "...", "severity": "critical|high|medium|low|info", "evidence": "...", \
"reproduction_steps": ["step 1", "step 2", "..."]}}
{finding_end}

  You may include this block inline with your normal reasoning text, then continue working.
- Stop calling tools and end your turn once you have reasonably exhausted useful lines of \
investigation for the objective, or explain why you cannot proceed further.
"""


def build_system_prompt(target: str, objective: str, scope_dir: str) -> str:
    tool_schemas = json.dumps(TOOL_DEFINITIONS, indent=2)
    return SYSTEM_PROMPT_TEMPLATE.format(
        target=target,
        objective=objective,
        scope_dir=scope_dir,
        tool_schemas=tool_schemas,
        finding_start=FINDING_START,
        finding_end=FINDING_END,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def execute_tool(name: str, tool_input: dict, scope_dir: str) -> dict:
    """Dispatch a single tool call with a hard 15s timeout enforced uniformly."""

    def _run():
        if name == "http_request":
            return tools.http_request(
                method=tool_input.get("method", "GET"),
                url=tool_input.get("url", ""),
                headers=tool_input.get("headers"),
                body=tool_input.get("body"),
            )
        if name == "dns_lookup":
            return tools.dns_lookup(hostname=tool_input.get("hostname", ""))
        if name == "code_search":
            return tools.code_search(
                pattern=tool_input.get("pattern", ""),
                path=tool_input.get("path", "."),
                scope_dir=scope_dir,
            )
        if name == "file_read":
            return tools.file_read(path=tool_input.get("path", ""), scope_dir=scope_dir)
        return {"error": f"Unknown tool: {name}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_run)
        try:
            return future.result(timeout=TOOL_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            return {"error": f"Tool '{name}' timed out after {TOOL_TIMEOUT_SECONDS}s"}
        except Exception as e:  # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}


def extract_findings(text: str) -> list[dict]:
    findings = []
    for raw in FINDING_RE.findall(text or ""):
        raw = raw.strip()
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "title" in obj:
            findings.append(obj)
    return findings


def run_agent(
    target: str,
    objective: str,
    scope_dir: str,
    model: str,
    max_iterations: int = 40,
    max_minutes: float = 20.0,
    max_tokens: int = 4096,
) -> dict:
    client = anthropic.Anthropic()
    system_prompt = build_system_prompt(target, objective, scope_dir)

    messages = [
        {
            "role": "user",
            "content": (
                f"Begin the authorized security assessment of {target}. "
                f"Objective: {objective}"
            ),
        }
    ]

    transcript: list[dict] = []
    findings: list[dict] = []
    start_time = time.monotonic()
    started_at = _now_iso()
    tool_call_count = 0
    stop_reason_final = "unknown"

    while True:
        elapsed_minutes = (time.monotonic() - start_time) / 60.0
        if elapsed_minutes >= max_minutes:
            stop_reason_final = "wall_clock_cap"
            break
        if tool_call_count >= max_iterations:
            stop_reason_final = "iteration_cap"
            break

        with client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            tools=TOOL_DEFINITIONS,
            messages=messages,
        ) as stream:
            for _ in stream:
                pass
            response = stream.get_final_message()

        assistant_text = "\n".join(
            block.text for block in response.content if block.type == "text"
        )
        for f in extract_findings(assistant_text):
            findings.append({"timestamp": _now_iso(), **f})

        messages.append({"role": "assistant", "content": response.content})

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

        if not tool_use_blocks:
            stop_reason_final = response.stop_reason or "end_turn"
            break

        tool_results = []
        for block in tool_use_blocks:
            if tool_call_count >= max_iterations:
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": "Iteration cap reached; tool not executed.",
                        "is_error": True,
                    }
                )
                continue

            tool_call_count += 1
            call_started = _now_iso()
            output = execute_tool(block.name, block.input, scope_dir)
            transcript.append(
                {
                    "timestamp": call_started,
                    "tool": block.name,
                    "input": block.input,
                    "output": output,
                    "model_reasoning_text": assistant_text,
                }
            )
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(output),
                    "is_error": "error" in output,
                }
            )

        messages.append({"role": "user", "content": tool_results})

        if tool_call_count >= max_iterations:
            stop_reason_final = "iteration_cap"
            break

    ended_at = _now_iso()
    return {
        "metadata": {
            "target": target,
            "objective": objective,
            "scope_dir": scope_dir,
            "model": model,
            "max_iterations": max_iterations,
            "max_minutes": max_minutes,
            "started_at": started_at,
            "ended_at": ended_at,
            "tool_call_count": tool_call_count,
            "stop_reason": stop_reason_final,
        },
        "transcript": transcript,
        "findings": findings,
    }

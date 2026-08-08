# AI Pentesting Agent Harness

A minimal, standalone CLI harness that gives Claude a small set of sandboxed
tools and lets it reason step-by-step over a target to find vulnerabilities.
Every tool call and finding is logged to a JSON transcript.

This is deliberately a **thin harness**, not a framework: one tool-calling
loop, a handful of tools, no database, no message queue, no orchestration DAG.

Tools live behind a standalone **MCP tool server** (`ronin-tools-mcp/`,
stdio transport) rather than being imported directly. Two ways to run it:

- **Single-agent** (`main.py` → `loop.py`) — the original mode: one agent,
  every tool available.
- **Two-agent** (`run.py`) — a recon agent explores and hands off structured
  candidate findings to a separate exploit agent that validates them one at
  a time, each restricted to a different slice of the tool server by a
  client-side allowlist. See [Two-agent mode](#two-agent-mode-recon--exploit)
  below.

Both share the same `agent_core.py` loop mechanics and the same MCP server —
there's one implementation of "call Claude, run a tool, log it, repeat,"
not one per agent.

> ## ⚠️ Authorized testing only
>
> This tool sends live HTTP requests, resolves DNS, and can read files. **Only
> run it against targets you own, or for which you have explicit written
> authorization to test** (e.g. a bug bounty program in scope, a client
> engagement letter, or your own infrastructure). Unauthorized scanning or
> exploitation of systems you do not own or have permission to test is
> illegal in most jurisdictions. You are responsible for how you use this
> tool.

---

## What it does

1. You give it a `--target` and an `--objective`.
2. `main.py` spawns the `ronin-tools-mcp` server as a subprocess and connects
   to it over stdio. Claude gets the tools it exposes (`http_request`,
   `dns_lookup`, `code_search`, `file_read`, `probe_variant`) and reasons
   step by step, calling tools to investigate.
3. Whenever Claude identifies a vulnerability, it emits a structured
   finding (title, severity, evidence, reproduction steps).
4. The loop stops when Claude decides it's done, or when the iteration cap
   (default 40 tool calls) or wall-clock cap (default 20 minutes) is hit.
5. Everything — every tool call, its input/output, the model's reasoning
   text at that point, and all findings — is written to a timestamped JSON
   transcript file.

## Setup

```bash
pip install -r requirements.txt
```

You also need:
- [ripgrep](https://github.com/BurntSushi/ripgrep#installation) (`rg`) on
  your `PATH` — used by `code_search`.
- Docker, running — used by `execute_python` (two-agent mode only; the
  single-agent mode doesn't need it). The sandbox image builds itself on
  first use.

Set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Running it

```bash
python main.py \
  --target http://localhost:3000 \
  --objective "Find any authentication or IDOR vulnerabilities in the login and account endpoints" \
  --scope-dir ./juice-shop-source \
  --max-iterations 40 \
  --max-minutes 20
```

### CLI flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--target` | yes | — | Target URL or host |
| `--objective` | yes | — | Free-text objective for the agent |
| `--scope-dir` | yes | — | Local directory that `code_search`/`file_read` are sandboxed to |
| `--max-iterations` | no | `40` | Max total tool calls before stopping |
| `--max-minutes` | no | `20` | Wall-clock cap in minutes before stopping |
| `--model` | no | `claude-sonnet-4-6` | Claude model ID |
| `--output-dir` | no | `.` | Where to write the transcript JSON file |

## Two-agent mode (recon → exploit)

```bash
python run.py \
  --target http://localhost:3000 \
  --objective "Find authentication, IDOR, and injection vulnerabilities" \
  --scope-dir . \
  --findings-path findings.json
```

`recon_agent` (tools: `recon` + `fileops` only) explores and writes candidate
findings to `findings.json`:

```jsonc
{
  "findings": [
    {
      "id": "f1", "type": "sql_injection", "target": "/rest/products/search",
      "evidence": "...", "status": "new", "discovered_by": "recon-agent",
      "exploit_attempts": []
    }
  ]
}
```

`exploit_agent` (tools: `web_exploit` + `exploit_runtime` only) then reads
that file and processes each `status == "new"` entry one at a time —
`new → claimed → exploited | dead-end` — each with its own fresh, focused
conversation (own iteration/time budget) and its own entry appended to
`exploit_attempts` (full transcript + verdict). It prefers the pre-built
`probe_variant` tool when a finding fits that pattern, and falls back to
`execute_python` — a sandboxed Python runtime — when it needs custom logic
(a specific payload, a multi-request chain, extracting and reusing a token).

Every `execute_python` call — the code submitted *and* its stdout/stderr —
is logged to the transcript verbatim, same as any other tool call; that's
the audit trail for what actually ran against the target.

### `execute_python` sandboxing

Each call runs in a fresh, disposable Docker container (`python:3.11-slim` +
`requests`, image builds itself on first use):

- **Filesystem**: root FS is read-only; the only writable path is a fresh
  per-call scratch directory bind-mounted in — nothing else on the host is
  reachable from inside the container, full stop.
- **Resources**: capped at 256MB memory, 0.5 CPU, 64 pids. A hung container
  gets an explicit `docker kill`, not just an abandoned `docker run`.
- **Network**: the container can reach the target (needed to actually test
  it) — this is the one place scope enforcement is a *soft* guarantee, not a
  hard one. An injected `ronin_target.py` helper re-checks the target host
  against the same allowlist every other tool enforces, and the tool
  description + exploit_agent's prompt both push the model to use
  `ronin_target.request(...)` instead of raw `requests`/`socket`/`urllib` —
  but code that deliberately bypasses the helper isn't technically blocked.
  This tradeoff was deliberate (see `ronin-tools-mcp/categories/exploit_runtime.py`
  for the full writeup) — closing it for real would mean a Docker network
  with an egress allowlist, which is more infrastructure than this harness
  takes on for now.

## Tools available to the agent

Tools are implemented in [`ronin-tools-mcp/`](ronin-tools-mcp), organized by
category (see [`manifest.yaml`](ronin-tools-mcp/manifest.yaml) for the
registry: name, category, description, timeout). Every tool call has a hard
per-tool timeout (15–20s depending on the tool).

- **recon** (`categories/recon.py`) — `http_request(method, url, headers, body)`
  and `dns_lookup(hostname)`, ported from the original in-process tools.
- **fileops** (`categories/fileops.py`) — `code_search(pattern, path)` (`rg --json`,
  no shell) and `file_read(path)`, scoped to `--scope-dir`.
- **web_exploit** (`categories/web_exploit.py`) — `probe_variant(...)`: sends a
  baseline request and a modified variant, diffs the two responses. For
  testing auth-bypass / IDOR patterns.
- **exploit_runtime** (`categories/exploit_runtime.py`) — `execute_python(code, timeout)`:
  runs code in a sandboxed Docker container for exploits `probe_variant`
  can't express. See [Two-agent mode](#two-agent-mode-recon--exploit) above
  for the full sandboxing writeup.
- **network_exploit** — reserved for a future part, no tools yet.

**Scope enforcement** ([`ronin-tools-mcp/scope.py`](ronin-tools-mcp/scope.py))
is centralized and applies to every tool, network tools included:
`code_search`/`file_read` resolve every path with `os.path.realpath` and
reject anything outside `--scope-dir` (`../` traversal, absolute-path
escapes, symlink escapes); `http_request`/`dns_lookup`/`probe_variant`
validate the target host against an allowed-hosts list (derived from
`--target` by default) *before* touching the network — a disallowed host is
rejected in code, not just discouraged by the system prompt. See
[`tests/test_scope.py`](tests/test_scope.py) (unit tests) and
[`tests/test_mcp_server.py`](tests/test_mcp_server.py) (end-to-end, through
the real server).

## Output

Each run writes `transcript_<target>_<timestamp>.json` containing:

```jsonc
{
  "metadata": {
    "target": "...", "objective": "...", "scope_dir": "...", "model": "...",
    "max_iterations": 40, "max_minutes": 20,
    "started_at": "...", "ended_at": "...",
    "tool_call_count": 7,
    "stop_reason": "end_turn"  // or "iteration_cap" / "wall_clock_cap"
  },
  "transcript": [
    {
      "timestamp": "2026-08-01T12:00:01Z",
      "tool": "http_request",
      "input": { "method": "GET", "url": "http://localhost:3000/rest/user/whoami" },
      "output": { "status_code": 200, "headers": {...}, "body": "..." },
      "model_reasoning_text": "I'll check whether the whoami endpoint leaks user data without auth..."
    }
  ],
  "findings": [
    {
      "timestamp": "2026-08-01T12:00:04Z",
      "title": "Broken access control on /rest/user/whoami",
      "severity": "high",
      "evidence": "Request without an Authorization header returned a valid user object.",
      "reproduction_steps": ["curl http://localhost:3000/rest/user/whoami"]
    }
  ]
}
```

### Example console output

```
[+] Target:      http://localhost:3000
[+] Objective:   Find authentication or IDOR vulnerabilities
[+] Scope dir:   D:\juice-shop-source
[+] Model:       claude-sonnet-4-6
[+] Max iters:   40   Max minutes: 20
[+] Starting agent loop...

[+] Stopped: end_turn
[+] Tool calls made: 11
[+] Findings: 2
[+] Transcript written to: ./transcript_localhost-3000_20260801T120500Z.json
```

## Testing

```bash
pip install pytest
pytest tests/test_scope.py -v          # unit tests on the Scope class, no subprocess/network/API key needed
pytest tests/test_mcp_server.py -v     # spins up the real MCP server, exercises every tool through it
pytest tests/test_execute_python.py -v -s  # real Docker sandbox checks (skips if Docker isn't available)
pytest tests/test_e2e.py -v -s         # full single-agent loop against a local test server (or Juice Shop at :3000)
```

`test_e2e.py` makes a real call to the Anthropic API and is skipped
automatically if `ANTHROPIC_API_KEY` is not set. It spins up a throwaway
local HTTP server if Juice Shop isn't already running at
`http://localhost:3000`, runs the CLI end to end with a small iteration cap,
and asserts a transcript file was produced — it does not assert that any
particular vulnerability was found.

## What this is *not*

By design, this harness does not include: retry/backoff logic, a web UI, a
database, authentication, a service mesh, or a message queue. `loop.py` is
async only because the MCP client requires it, not as a step toward
concurrent scanning.

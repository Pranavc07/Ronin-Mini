# AI Pentesting Agent Harness

A minimal, standalone CLI harness that gives Claude a small set of sandboxed
tools and lets it reason step-by-step over a target to find vulnerabilities.
Every tool call and finding is logged to a JSON transcript.

This is deliberately a **thin harness**, not a framework: one tool-calling
loop, four tools, no database, no message queue, no orchestration DAG.

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
2. Claude gets 4 tools (`http_request`, `dns_lookup`, `code_search`,
   `file_read`) and reasons step by step, calling tools to investigate.
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

You also need [ripgrep](https://github.com/BurntSushi/ripgrep#installation)
(`rg`) installed and on your `PATH` — it's used by the `code_search` tool.

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

## Tools available to the agent

All tools run in-process except `code_search`, which subprocesses `ripgrep`
directly (no shell). Every tool call has a hard 15-second timeout.

- **`http_request(method, url, headers, body)`** — sends an HTTP request via
  `requests`. Response body truncated to ~4000 chars.
- **`dns_lookup(hostname)`** — resolves A/AAAA/CNAME/TXT records via
  `dnspython`.
- **`code_search(pattern, path)`** — greps source code with `rg --json`,
  scoped to `--scope-dir`. Cannot read outside it.
- **`file_read(path)`** — read-only file read, scoped to `--scope-dir`,
  capped at ~4000 chars. Cannot read outside it, and cannot write.

`code_search` and `file_read` resolve every path with `os.path.realpath`
and reject anything that resolves outside the scope directory (blocking
`../` traversal, absolute-path escapes, and symlink escapes). See
[`tests/test_sandbox.py`](tests/test_sandbox.py).

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
pytest tests/test_sandbox.py -v      # path-traversal / sandbox-escape tests, no network or API key needed
pytest tests/test_e2e.py -v -s       # full loop against a local test server (or Juice Shop at :3000 if running)
```

`test_e2e.py` makes a real call to the Anthropic API and is skipped
automatically if `ANTHROPIC_API_KEY` is not set. It spins up a throwaway
local HTTP server if Juice Shop isn't already running at
`http://localhost:3000`, runs the CLI end to end with a small iteration cap,
and asserts a transcript file was produced — it does not assert that any
particular vulnerability was found.

## What this is *not*

By design, this harness does not include: retry/backoff logic, async
execution, a web UI, a database, authentication, orchestration beyond the
single tool-calling loop, or any tools beyond the four listed above.

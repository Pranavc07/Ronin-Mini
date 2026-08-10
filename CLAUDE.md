# Ronin-Mini — architecture notes for Claude

Minimal AI pentesting harness. Published: github.com/Pranavc07/Ronin-Mini.
Read this + `docs/progress.md` at session start instead of re-exploring.

## Two ways to run it

- **Single-agent** (`main.py` → `loop.py`): one agent, all tools. The original
  Ronin-Mini mode.
- **Three-agent** (`run.py`): recon → exploit → verify, sequential, one
  process, handing off through `findings.json`. This is the current focus.

All loops share `agent_core.py` — the one implementation of the Claude↔tool
loop (`run_tool_loop`, `mcp_server_params`, `filter_tools_by_category`,
`execute_tool`, `extract_blocks`, plus `load_agent_prompt`/`load_skill`).
`loop.py`, `recon_agent/loop.py`, `exploit_agent/loop.py`, and
`verify_agent/loop.py` are thin wrappers; they differ only in role prompt,
tool allowlist, and what they do with the result.

## Role prompts and skills are externalized markdown

- `agents/<role>.md` — role prompts (`recon`, `exploit`, `verify`), loaded via
  `agent_core.load_agent_prompt()` as `str.format()` templates. Placeholders use
  `{name}`; literal JSON examples inside them use `{{ }}` escaping — preserve
  that when editing.
- `skills/<type>.md` — per-vuln-class methodology. exploit_agent loads
  `skills/{finding.type}.md` and appends it AFTER formatting (as a literal
  string, so skills may contain braces/payloads freely). `sqli/idor/xss/
  auth_bypass` are fully written; the other 10 are stubs. A finding type with no
  matching file → no skill appended (explicit fallback; `skill_loaded=None`).

## Tools live behind an MCP server, not imports

`ronin-tools-mcp/server.py` is a standalone MCP server (stdio). Agents connect
as MCP clients — they do NOT import tool functions. The server is spawned as a
subprocess per run. Tools are grouped into categories under
`ronin-tools-mcp/categories/`:

- `recon` → `http_request`, `dns_lookup`
- `fileops` → `code_search`, `file_read`
- `web_exploit` → `probe_variant` (baseline-vs-variant request differ)
- `exploit_runtime` → `execute_python` (Docker sandbox — see below)
- `verify` → `replay_probe` (re-runs a finding's winning attempt; see below)
- `network_exploit` → reserved, empty stub

`probe_variant` / `execute_python` each have their execution body extracted to a
module-level `run_*` function so `replay_probe` reuses the identical scope-checked
path with no duplication. `agent_core.execute_tool` uses a per-tool read timeout
derived from the manifest (not a flat 15s) so slow tools aren't cut off.

`manifest.yaml` is the registry (category + per-tool timeout); `manifest.py`
loads it. Every tool call routes through `scope.py` (`Scope` class) BEFORE
touching anything: `resolve_safe_path` (path-traversal defense, realpath-based)
for fileops, `validate_host` (allowlist) for all network tools. Scope is
enforced in code, not by prompting — a disallowed host/path is rejected
regardless of what the model asks for.

## Per-agent tool allowlisting (client-side)

The server exposes everything; each agent narrows what it sees via
`filter_tools_by_category` against `manifest.yaml`:

- **recon_agent**: `{recon, fileops}` — explores, does NOT exploit.
- **exploit_agent**: `{web_exploit, exploit_runtime}` — validates findings.
- **verify_agent**: `{verify}` — ONLY `replay_probe`. Deliberately cannot reach
  recon/exploit tools; it can only reproduce recorded attempts, not invent new
  ones. Enforced at the schema level, not just by prompt.

## Three-agent flow & findings.json

Each agent processes findings one at a time in its own fresh conversation (own
iteration/time budget), claiming a finding by advancing its status first, then
appending an attempt record. recon assigns `id`/`status`/`discovered_by` in host
code, not via the model.

- recon → writes `status: new` candidates.
- exploit → each `new`: `claimed → exploited | dead-end | incomplete`, appends to
  `exploit_attempts`. Each attempt records `skill_loaded` (type or null).
  `incomplete` = never produced a verdict (e.g. burned budget) — NOT the same as
  `dead-end` (investigated, concluded not vulnerable).
- verify → each `exploited`: `verifying → verified | false_positive |
  verify_incomplete`, appends to `verify_attempts`. `replay_probe` reads the
  winning attempt from findings.json (server gets `--findings-path`) and replays
  its recorded tool calls (all of them, capped at 12).

Schema: `{"findings": [{id, type, target, evidence, status, discovered_by,
exploit_attempts:[...], verify_attempts:[...]}]}`.

## execute_python sandbox (the one genuinely risky tool)

Each call runs in a fresh throwaway Docker container (`python:3.11-slim` +
`requests`; image self-builds on first use via
`ronin-tools-mcp/docker/exploit-runtime.Dockerfile`). Read-only root FS, only a
per-call scratch dir is writable, capped mem/cpu/pids, hard timeout with an
explicit `docker kill` fallback. Networking is bridge (must reach the target),
so **network scope here is a SOFT guarantee**: an injected `ronin_target.py`
helper re-checks the host and the prompt pushes the model to use
`ronin_target.request(...)`, but raw sockets aren't technically blocked. This
tradeoff was chosen deliberately (Option A); the full writeup is in
`categories/exploit_runtime.py`'s module docstring. Closing it fully = a Docker
egress-allowlist network, intentionally deferred.

**Convention: prefer `probe_variant` over `execute_python`.** The exploit agent
is prompted to reach for the pre-built tool when a finding fits it, and only
write code when it genuinely doesn't — matched tool calls are faster and easier
to audit. Empirically: JSON/REST targets (Juice Shop) lean on probe_variant;
HTML-form/session-cookie targets (DVWA) lean on execute_python.

## Deliberate non-goals (do not add without being asked)

No Kafka, no Postgres/database, no service framework, no message queue, no
dynamic agent graph, no FOURTH agent, no scoring/severity ranking. State is
files (`findings.json`). Orchestration is `run.py` running three loops in
sequence. `loop.py` is async only because the MCP client requires it, not as a
step toward concurrency. Keeping the whole thing readable top-to-bottom is a
hard constraint.

## Test targets (all local, authorized)

- **OWASP Juice Shop** — `http://localhost:3000` (Docker, Node/JS, JWT auth).
- **DVWA** — `http://localhost:4280` (Docker, PHP/MySQL, session-cookie auth;
  needs DB init + security=low; admin/password). Session cookie must be
  threaded manually via headers — **no cookie jar in the tools**. KNOWN
  LIMITATION: exploit_agent re-logs-in per finding in a fresh conversation, and
  DVWA's stateful CSRF login is fiddly, so many DVWA findings `incomplete` out
  (budget burned on login) rather than exploiting. Juice Shop's stateless JWT
  doesn't hit this. Fixing session handling is deferred, deliberately.

Everything is authorized-testing-only; both apps exist to be broken. Scope
(`--scope-dir`, host allowlist) must never be widened to a real third party.

## Tests

`pytest tests/` — `test_scope.py` (unit, no deps), `test_mcp_server.py` +
`test_execute_python.py` (spin up real server/Docker), `test_e2e.py` (needs
`ANTHROPIC_API_KEY`, else skips). NOTE: `test_execute_python.py` currently
*errors* (not skips) when the Docker daemon is down — its guard only checks the
binary exists. Harmless; a known 2-line fix if it annoys you.

## Current state

<!-- One-line status, updated manually each session. See docs/progress.md for detail. -->
- verify_agent (3rd agent) + skills/externalized-prompts BUILT & verified offline; NOT yet live-tested end-to-end via run.py. Next: run.py against Juice Shop (Docker up), confirm the [verify] stage. Uncommitted on `main`.

# Ronin-Mini — architecture notes for Claude

Minimal AI pentesting harness. Published: github.com/Pranavc07/Ronin-Mini.
Read this + `docs/progress.md` + `docs/roadmap.md` at session start instead of
re-exploring.

## Two ways to run it

- **Single-agent** (`main.py` → `loop.py`): one agent, all tools. The original
  Ronin-Mini mode.
- **Three-agent** (`run.py`): recon → exploit → verify, sequential, one
  process, handing off through `findings.json`. This is the current focus.

All loops share `agent_core.py` — the one implementation of the model↔tool
loop (`run_tool_loop`, `mcp_server_params`, `filter_tools_by_category`,
`execute_tool`, `confirm_tool_call`, `extract_blocks`, plus
`load_agent_prompt`/`load_skill`). `loop.py`, `recon_agent/loop.py`,
`exploit_agent/loop.py`, and `verify_agent/loop.py` are thin wrappers; they
differ only in role prompt, tool allowlist, and what they do with the result.

## Model provider is behind an adapter, not a raw SDK call

`run_tool_loop` talks only to a `models.ModelAdapter` — never to
`anthropic.AsyncAnthropic()` directly. `models/base.py` defines the neutral
shapes (`Turn`, `ToolCall`, `ToolResult`, `ModelResponse`) and the
`ModelAdapter.send_messages(system, messages, tools, max_tokens)` interface;
`models/anthropic_adapter.py`'s `AnthropicAdapter` is the only real
implementation, translating the *entire* `Turn` history to/from Anthropic's
native message-block shape on every call (not just the response) — that's
what keeps `agent_core.py` provider-agnostic rather than just wrapping one
provider's response. `models/__init__.py`'s `build_adapter(provider, model)`
is the one seam every `run_*_agent()` calls through; each takes a
`provider: str = "anthropic"` param threaded from the CLI's `--provider`
flag (`main.py`, `run.py`). Adding a second provider is a new adapter file +
one more branch in `build_adapter` — no router, no per-turn model
selection, no rewrite of `agent_core.py` or any agent loop.

## HITL approval gate — three modes, `hitl_mode`, default `auto`

Gated tools (per `manifest.yaml`'s `categories:` block, resolved onto
`ToolMeta.require_approval`): `probe_variant`, `execute_python`,
`replay_probe` (each is the sole tool in its category; `network_exploit` —
Phase 2's future Kali tools — is pre-gated too, so new tools inherit the
gate without anyone remembering to set it per-tool). `run_tool_loop`'s
`hitl_mode` param (threaded from every `run_*_agent()`'s own `hitl_mode`
param, in turn from `--hitl-mode` on `main.py`/`run.py`, default `"auto"`)
picks the behavior:

- **`auto`** (default) — never prompts, every tool call executes
  immediately, gated or not. Use when you trust the run and don't want to
  babysit it.
- **`manual`** — `agent_core.confirm_tool_call(name, tool_input, manifest)`
  prompts `[y/n/edit]` on every gated call, blocking on `input()`
  (acceptable since the harness runs one turn at a time, nothing else
  competes for the event loop). Denies fail-safe on `EOFError`
  (non-interactive stdin) rather than crashing the run.
- **`plan`** — `agent_core.confirm_plan_for_run(gated_tool_names)` asks
  once, before the *first* gated call of a `run_tool_loop` invocation (one
  finding's investigation, for exploit/verify — each finding gets a fresh
  `run_tool_loop` call already, so this lands naturally at finding
  granularity; the whole run, for recon/the legacy single-agent loop, which
  have no per-finding boundary). That one decision governs every gated call
  for the rest of that invocation — no further prompts until the next
  finding/run starts fresh. Never prompts at all if a run happens not to
  need any gated tool.

A denial (from either `manual` or `plan`) becomes a normal tool-result error
(`"Tool call denied by operator (HITL gate)."`) the model sees and can adapt
to, same as any other tool error.

## Role prompts and skills are externalized markdown

- `agents/<role>.md` — role prompts (`recon`, `exploit`, `verify`), loaded via
  `agent_core.load_agent_prompt()` as `str.format()` templates. Placeholders use
  `{name}`; literal JSON examples inside them use `{{ }}` escaping — preserve
  that when editing.
- `skills/<type>.md` — per-vuln-class methodology, with a YAML frontmatter
  block (`status: full|stub`, `cwe`, `attack_technique`, `attack_tactic`)
  parsed by `agent_core.load_skill()` into a `SkillDoc(metadata, body)`.
  exploit_agent appends `body` AFTER formatting (as a literal string, so
  skills may contain braces/payloads freely). `sqli/idor/xss/auth_bypass` are
  `status: full`; the other 10 are `status: stub` — a finding type with no
  matching file at all → `load_skill` returns `None` (explicit fallback,
  `skill_loaded=None`, distinct from a `stub` file that exists but has no
  real methodology yet).

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
- `attack_reference` → `lookup_attack_technique` (local, offline lookup over a
  slim copy of MITRE's public Enterprise ATT&CK data —
  `ronin-tools-mcp/data/attack_enterprise_slim.json`, regenerated via
  `ronin-tools-mcp/data/build_attack_data.py`). exploit_agent's fallback when
  a finding's skill is only a `stub`: the prompt nudges it to look up the
  skill's `attack_technique` id and reason from the returned description
  instead of guessing. Deliberately not a live/networked lookup — no
  third-party runtime dependency.
- `network_exploit` → `nmap`, `nikto`, `sqlmap`, `hydra`, `gobuster`,
  `enum4linux`, `searchsploit` — Phase 2's Kali attack box tools (see below).

`probe_variant` / `execute_python` each have their execution body extracted to a
module-level `run_*` function so `replay_probe` reuses the identical scope-checked
path with no duplication. `agent_core.execute_tool` uses a per-tool read timeout
derived from the manifest (not a flat 15s) so slow tools aren't cut off.

`manifest.yaml` is the registry (category + per-tool timeout + per-category
`require_approval` default); `manifest.py` loads it. Every tool call routes
through `scope.py` (`Scope` class) BEFORE touching anything: `resolve_safe_path`
(path-traversal defense, realpath-based) for fileops, `validate_host`
(allowlist) for all network tools. Scope is enforced in code, not by
prompting — a disallowed host/path is rejected regardless of what the model
asks for.

## Per-agent tool allowlisting (client-side)

The server exposes everything; each agent narrows what it sees via
`filter_tools_by_category` against `manifest.yaml`:

- **recon_agent**: `{recon, fileops}` — explores, does NOT exploit.
- **exploit_agent**: `{web_exploit, exploit_runtime, attack_reference}` — validates findings.
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
  `exploit_attempts`. Each attempt records `skill_loaded` (type or null),
  `skill_status` (`full`/`stub`/null), `cwe`, `attack_technique` — all from the
  matched skill's frontmatter, purely additive metadata for reporting.
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

## Kali attack box (network_exploit)

`ronin-tools-mcp/docker/kali-tools.Dockerfile` — a purpose-built,
reproducible image (`kalilinux/kali-rolling` base + `apt-get install`
exactly `nmap`, `nikto`, `sqlmap`, `hydra`, `wordlists`, `seclists`,
`gobuster`, `enum4linux-ng`, `exploitdb`). Deliberately narrow: exactly what
Ronin needs today, not the full Kali toolset — same discipline as
`skills/*.md` growing 4 → 14, new tools get added one at a time when a
concrete capability gap shows up, not preemptively.

Unlike `execute_python`'s ephemeral per-call containers, this is a
**long-lived** container (`executor.ensure_kali_container_ready()` builds
the image + starts `ronin-kali-box` once, idempotent; `run_in_kali_container(args, timeout)`
runs `docker exec ronin-kali-box <args>` per call — `args` is always a real
argv list, never a shell string, so there's no shell for injected
metacharacters to reach regardless of parameter content).

Every tool in `categories/network_exploit.py` takes structured, typed
parameters only — enums for scan types/wordlists, regex-validated port
strings, no raw flag passthrough — and validates its target through
`scope.validate_host` before building a command. `searchsploit` is the one
exception: it's a local offline exploit-db lookup with no target host at
all (see its docstring).

**Loopback host translation**: these tools run *inside* the Kali container,
so a target of `localhost`/`127.0.0.1` (how DVWA/Juice Shop's scope is
configured) means the container itself, not the actual test target.
`network_exploit.py`'s `_container_target`/`_container_url` translate
loopback hosts to `host.docker.internal` *after* `scope.validate_host`
confirms the original host is authorized — validation always checks what
the operator actually allowlisted; only the argv sent into the container
uses the translated address. (Caught by the integration test: without this,
`nmap localhost` would scan the Kali box itself and always report nothing
open.)

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
`ANTHROPIC_API_KEY`, else skips), `test_network_exploit.py` (unit, mocked
`run_in_kali_container`, no Docker needed) + `test_network_exploit_integration.py`
(real Docker + the real `ronin-kali-box` container against DVWA — first run
builds the ~4GB image). NOTE: `test_execute_python.py` currently *errors*
(not skips) when the Docker daemon is down — its guard only checks the
binary exists. Harmless; a known 2-line fix if it annoys you.

## Current state

<!-- One-line status, updated manually each session. See docs/progress.md for detail. -->
- Phase 1 (skills + verify_agent) shipped and live-tested end-to-end against
  Juice Shop. Phase 1.5 (CWE/ATT&CK skill tagging + `attack_reference`
  fallback tool) and Phase 0 (HITL gate w/ 3 modes + model-agnostic
  `ModelAdapter`) both shipped and live-tested end-to-end against DVWA --
  full recon->exploit->verify pipeline completed, every stub-type finding
  used the `lookup_attack_technique` fallback and reached `verified`.
  Phase 2 (Kali attack box, 7 tools: nmap/nikto/sqlmap/hydra/gobuster/
  enum4linux/searchsploit) implemented and integration-tested against DVWA
  (real Docker, real container); the Metasploitable-specific live check
  (hydra/enum4linux against real weak-cred/SMB findings) is still pending --
  no Metasploitable target exists in this environment yet. See
  `docs/roadmap.md` for the full phase plan.

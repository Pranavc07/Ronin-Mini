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
`models/anthropic_adapter.py`'s `AnthropicAdapter` translates the *entire*
`Turn` history to/from Anthropic's native message-block shape on every call
(not just the response) — that's what keeps `agent_core.py` provider-agnostic
rather than just wrapping one provider's response. `models/__init__.py`'s
`build_adapter(provider, model)` is the one seam every `run_*_agent()` calls
through; each takes a `provider: str = "anthropic"` param threaded from the
CLI's `--provider` flag (`main.py`, `run.py`).

Second provider, proving the design: `models/openai_compatible_adapter.py`'s
`OpenAICompatibleAdapter` speaks the OpenAI chat-completions wire format
(`tools`/`tool_calls`, one `role: "tool"` message per result rather than
Anthropic's single user-turn-with-multiple-blocks shape), so it works for
*any* OpenAI-compatible provider — OpenRouter, GLM/Zhipu direct, OpenAI
itself — not just one. `base_url` and which env var holds the API key are
constructor params, not hardcoded in the class; `models/__init__.py`'s
`"openrouter"` provider wires it to OpenRouter (`https://openrouter.ai/api/v1`,
key from `OPENROUTER_API_KEY`) — one provider entry covers every model
OpenRouter fronts (GLM, Qwen, DeepSeek, ...), selected via `--model`
(e.g. `--model qwen/qwen3.6-plus`), not a new provider name per model
family. A genuinely different endpoint (GLM/Zhipu direct rather than via
OpenRouter) would be its own `_build_*` factory pointed at a different
`base_url`/`api_key_env`, same adapter class, no new class needed.
`finish_reason` values are normalized to
Anthropic's vocabulary (`"tool_calls"` → `"tool_use"`, `"stop"` →
`"end_turn"`) so `run.py`'s printed `stop_reason` reads consistently
regardless of which adapter produced it. Confirms adding a provider really
is a new adapter file + one more branch in `build_adapter` — no router, no
per-turn model selection, no rewrite of `agent_core.py` or any agent loop.

## Token usage + cost tracking

`ModelResponse` carries a `usage: Usage` field (`input_tokens`,
`output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens` —
`models/base.py`). `AnthropicAdapter.send_messages` populates it from the
real API response's `.usage` (getattr-guarded, so test doubles without a
`.usage` attribute default to zero instead of raising).
`agent_core.run_tool_loop` sums `Usage` across every model call it makes
within one invocation and returns it as `result["usage"]` (a plain dict, not
the dataclass — the boundary out of agent_core.py is dicts, same as
everything else it returns). Each `run_*_agent()` threads that through:
recon puts it in `metadata["usage"]` (one `run_tool_loop` call per recon
run); exploit/verify record `usage` per-finding on each `exploit_attempts`/
`verify_attempts` entry (mirrors `tool_call_count`, already there) and also
return a `run`-level total (`models.sum_usage(*per_finding_usages)`).
`models/pricing.py`'s `estimate_cost_usd(model, usage_dict)` converts a
usage dict to a dollar figure via a **static, maintained pricing table** —
not a live lookup, since Anthropic doesn't expose a pricing API — with a
Sonnet-tier fallback for any model id not in the table. `run.py` prints
per-stage (`[recon]`/`[exploit]`/`[verify]`) and total token counts + cost
after each stage; `main.py` prints the same for the single-agent loop. Every
printed cost line is explicitly labeled approximate and points to
`console.anthropic.com`'s billing dashboard as the authoritative source —
this exists to give a same-session ballpark, not to replace real billing
data.

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
- `metasploit_exploit` → `metasploit` — runs a real Metasploit exploit
  module. `exploit_agent`-only, never `recon_agent` (see "Per-agent tool
  allowlisting" below). The one deliberate exception to "fixed enum, no raw
  passthrough": `module` is a free-text Metasploit module path, by explicit
  choice — see `categories/metasploit.py`'s module docstring for the
  reasoning and what's still enforced regardless (scope, injection guard,
  `lport` range).

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

- **recon_agent**: `{recon, fileops, network_exploit}` — explores using the full
  recon/network toolset (http_request/dns_lookup plus nmap/nikto/sqlmap/hydra/
  gobuster/enum4linux/searchsploit), decides which tools fit the target's scope
  itself. Does NOT do the formal validation pass -- exploit_agent still owns that.
  (Originally scoped to HTTP/DNS-only; deliberately reconsidered -- see
  `docs/roadmap.md`'s Phase 2 section for why.)
- **exploit_agent**: `{web_exploit, exploit_runtime, attack_reference, network_exploit,
  metasploit_exploit}` — validates findings. The only agent with `metasploit` access —
  recon can *find* candidates (nmap/searchsploit) but never runs actual exploit
  modules itself, by explicit design.
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
  unverifiable | verify_incomplete`, appends to `verify_attempts`.
  `replay_probe` (`categories/verify.py`'s `run_replay_probe`) reads the
  winning attempt from findings.json (server gets `--findings-path`) and
  walks its recorded tool calls (capped at 12 *actually replayed* calls —
  stub entries for undeclared tools don't count against the cap). For each
  call it either genuinely replays it (real dispatch, `_replay_call`) or, if
  no replay support exists for that tool, returns an explicit
  `{"replayable": false, "reason": ...}` stub — every call from the original
  transcript shows up in the output, none are silently dropped.
  `unverifiable` is the status for "the tooling has no way to confirm or
  refute this" (a coverage gap) — distinct from `false_positive`, which is
  reserved for "a replay actually ran and its output contradicted the
  claim." This happened for real, twice, in different forms: (1) originally,
  a winning attempt using a tool `replay_probe` didn't know how to run
  filtered down to zero replayable calls, and verify read that emptiness as
  disproof — network_exploit's 7 tools and `metasploit` were added to
  exploit_agent without `categories/verify.py` being updated, and a live run
  against Metasploitable mislabeled 3 genuine Metasploit-confirmed exploits
  (incl. a root shell) as `false_positive`. That specific gap is fixed —
  every tool exploit_agent can reach today has real replay support. (2) The
  *structural* version of the same bug: nothing stopped it from recurring
  for the next tool added without anyone deciding what replay should do with
  it. Fixed by making replay coverage manifest-declared and enforced at two
  layers: `manifest.yaml` requires every tool to declare
  `replayable: "true" | "false" | "partial"` (`manifest.py` reads it via
  required-key indexing, not `.get()` — a missing field fails loudly at
  `load_manifest()` time, before any test even runs); and
  `categories/verify.py`'s `REPLAYABLE_TOOLS` set is *derived* from that
  field rather than hand-maintained, with `tests/test_replay_coverage.py`
  asserting every `replayable: "true"/"partial"` tool reachable by
  exploit_agent has a real `_replay_call` dispatch case (not the generic
  fallback). A tool correctly declared `replayable: "false"` now produces
  the explicit stub, and `agents/verify.md` instructs the model: if the
  calls central to a claim are unreplayable and nothing else in the
  transcript contradicts it, conclude `unverifiable`, never `false_positive`.
  **Separately** (not the same issue, not addressed by any of the above):
  replaying a *live exploit* a second time can legitimately fail for reasons
  outside the code's control — some exploits are one-shot on the target
  (e.g. the vsftpd 2.3.4 backdoor doesn't reliably re-trigger without a
  service restart), and reverse-payload replay depends on the same
  LHOST/network topology caveat as the original run. `metasploit` and
  `hydra` are declared `replayable: "partial"` in `manifest.yaml` to flag
  this in-band — real dispatch exists and genuinely re-executes the action,
  but replay fidelity for these two isn't guaranteed the way it is for
  idempotent scans/lookups. A `false_positive` from a genuinely-failed live
  replay of a real exploit is a different thing from either bug above — this
  remains an open, harder problem, not fixed here.

  **A third, distinct bug** surfaced live-testing a non-Anthropic provider
  (Qwen3.6 Plus via OpenRouter, see the model-adapter section above):
  `replay_probe` crashed outright on some recorded calls with real Python
  `TypeError`s (`'<=' not supported between instances of 'int' and 'str'`;
  `'str' object has no attribute 'items'`) rather than replaying them.
  Root cause: unlike Claude's native tool use, that model didn't always emit
  correctly-typed nested tool-call arguments matching the declared JSON
  schema — a `metasploit` call's `lport`/`port` came back as strings, a
  `probe_variant` call's headers as JSON-encoded strings instead of actual
  objects. The *original* `exploit_agent` calls apparently succeeded anyway
  (the MCP server layer likely coerces types before the registered tool
  function runs); replay bypasses that layer entirely, calling the raw
  `run_*` function directly, so the mismatch that got smoothed over the
  first time crashed on replay. `verify_agent` correctly treated the crash
  as `unverifiable` rather than misreading it as disproof (the system
  working as designed even under an unanticipated failure mode) — but the
  crash itself was a real bug. Fixed with `_coerce_dict`/`_coerce_int`
  helpers in `categories/verify.py`'s `_replay_call`, applied to the
  specific int/dict-typed fields (`probe_variant`'s four header/params
  params, `metasploit`'s `port`/`lport`/`options`) that had no defensive
  casting — `run_sqlmap`'s `level`/`risk` already wrap `int(...)` internally
  so needed no change. 10 new regression tests reproduce the exact recorded
  shapes from the live run that crashed.

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

## Metasploit (metasploit_exploit, exploit_agent-only)

`ronin-tools-mcp/categories/metasploit.py` — one tool, `metasploit`, runs a
real Metasploit exploit module inside the same long-lived `ronin-kali-box`
container (`metasploit-framework` added to `kali-tools.Dockerfile`, no
`msfdb init` — database-less scripted use is fine for non-interactive runs).
`exploit_agent`-only, never `recon_agent` — its own category
(`metasploit_exploit`), separate from `network_exploit`, specifically so it
can be added to one agent's allowlist without the other. This is a real
jump in risk tier from every other tool here, **by explicit user choice**:

- **`module` is free-text, not a fixed enum** — the one deliberate exception
  to "fixed enum, no raw passthrough" that every other tool in this repo
  follows. A curated-allowlist alternative was proposed and explicitly
  declined. What's still enforced regardless: `scope.validate_host` on the
  target (host allowlist is a hard boundary independent of module choice),
  and a resource-script injection guard — `module`/`payload`/`options`/
  `post_exploit_command` are rejected if they contain a newline, since
  they're written into a line-based `.rc` file the console interprets one
  command per line. This isn't about restricting *which* module runs, only
  preventing a parameter value from smuggling in *extra* commands.
- **Reverse-shell payloads are supported** (`payload`/`lhost`/`lport`), also
  by explicit choice over a backdoor/bind-only-for-now alternative. This
  needed real container networking changes: `ensure_kali_container_ready()`
  now publishes a fixed port range (`executor.KALI_LPORT_RANGE`,
  `44440-44450`) so a reverse listener inside the container is externally
  reachable — `lport` is validated against this range before anything runs,
  otherwise a listener would open that nothing could ever reach. Docker
  can't add port publishing to an already-running container, so
  `ensure_kali_container_ready()` detects an existing `ronin-kali-box`
  missing these published ports and recreates it (remove + re-run) rather
  than just starting it.
- **LHOST is operator-supplied, not auto-detected** — for a reverse shell to
  actually reach back from an external target (e.g. a Metasploitable VM on
  a VirtualBox host-only network), `lhost` needs to be an IP the target can
  route to. That's typically the Windows host's own IP on that network
  adapter (e.g. `192.168.56.1`), not the container's internal bridge IP —
  Docker Desktop on Windows publishes container ports to all host
  interfaces by default, so a published port is reachable via that adapter
  too. This is environment topology the operator supplies; the code can't
  infer it.
- The category is `require_approval: true`, same gating discipline as
  everywhere else — that's the actual safety control here, not a curated
  module list. Under `--hitl-mode auto` this tool runs unattended like
  everything else gated; worth being aware of given the elevated
  capability.

No file-mount into the long-lived container (unlike `execute_python`'s
ephemeral containers) — `executor.write_file_in_kali_container()` writes the
generated resource script in via `docker exec -i ... tee`, stdin-piped, no
shell, no quoting needed for the script content itself.

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
builds the ~4.3GB image incl. metasploit-framework), `test_metasploit.py`
(unit, mocked, resource-script construction + injection guard + lport range)
+ `test_metasploit_integration.py` (real Docker, confirms
metasploit-framework is installed and a real module run completes without
hanging). NOTE: `test_execute_python.py` currently *errors* (not skips)
when the Docker daemon is down — its guard only checks the binary exists.
Harmless; a known 2-line fix if it annoys you.

## Current state

<!-- One-line status, updated manually each session. See docs/progress.md for detail. -->
- Phase 1 (skills + verify_agent) shipped and live-tested end-to-end against
  Juice Shop. Phase 1.5 (CWE/ATT&CK skill tagging + `attack_reference`
  fallback tool) and Phase 0 (HITL gate w/ 3 modes + model-agnostic
  `ModelAdapter`) both shipped and live-tested end-to-end against DVWA --
  full recon->exploit->verify pipeline completed, every stub-type finding
  used the `lookup_attack_technique` fallback and reached `verified`.
  Phase 2 (Kali attack box, 7 tools: nmap/nikto/sqlmap/hydra/gobuster/
  enum4linux/searchsploit) implemented and live-tested against DVWA (Docker
  integration) and a real Metasploitable box (nmap fingerprinted vsftpd
  2.3.4/Samba, enum4linux-ng pulled real SMB shares, searchsploit found the
  real CVE-2011-2523 backdoor off nmap's own output). The tool-level-only
  gap that testing surfaced (recon_agent had no network_exploit access, so
  no full agent pipeline run could ever reach these tools) is now closed:
  recon_agent has real agent-level access to all 7 tools, plus two new
  finding types (`known_vulnerable_service`, `weak_credentials`) with full
  skills pairing them to `searchsploit`/`hydra`. `metasploit` (its own
  `metasploit_exploit` category, exploit_agent-only) added on top for
  running real exploit modules -- free-text module + reverse-shell payload
  support by explicit user choice, the one deliberate exception to this
  repo's fixed-enum-everywhere discipline. Live pipeline check against real
  Metasploitable pending for both the recon-agent-level-access fix and
  `metasploit`. See `docs/roadmap.md` for the full phase plan.

# Ronin-Mini

Source-available under **BSL 1.1** — free for almost any use (including
commercial), converts automatically to Apache 2.0 on 2030-08-18. See
[LICENSE](LICENSE) for the exact terms, or [What the license means in
practice](#what-the-license-means-in-practice) below for the plain-language
version.

A minimal, standalone AI pentesting harness. It is model agnostic, so any
model reasons step-by-step over a target through a small, scoped set of
tools, and every tool call is logged to an auditable transcript.

Three-agent mode uses MongoDB for mission/finding state (one document per
mission, no ORM, no service layer around it — see "Mission storage" in
[Architecture at a glance](#architecture-at-a-glance) below), made because
the tool output it stores is genuinely heterogeneous. See
[`docs/roadmap.md`](docs/roadmap.md) for what's shipped and what's
deliberately deferred, and [`docs/progress.md`](docs/progress.md) for a
running log of what changed and why.

Tools live behind a standalone **MCP tool server** (`ronin-tools-mcp/`, stdio
transport) — agents connect to it as MCP clients, they don't import tool
functions directly. Two ways to run it:

- **Single-agent** (`main.py` → `loop.py`) — the original mode: one agent,
  every tool available.
- **Three-agent** (`run.py`) — this is the current focus. `recon_agent`
  explores and writes candidate findings, `exploit_agent` validates each one
  with real tool calls, `verify_agent` independently re-checks anything
  `exploit_agent` claims to have exploited before it's trusted. Each agent
  only sees the slice of the tool server its role needs, enforced client-side
  by category, not just by prompting. See [Three-agent mode](#three-agent-mode-recon--exploit--verify)
  below.

Both modes share `agent_core.py` — one implementation of "call the model, run
a tool, log it, repeat" — and both talk to the model only through a
model-agnostic adapter (`models/`), never to a provider SDK directly.

> ## ⚠️ Authorized testing only
>
> This tool sends live HTTP requests, resolves DNS, reads files, runs network
> scans (nmap/nikto/sqlmap/hydra/gobuster/enum4linux), looks up exploits
> (searchsploit), and can run real Metasploit exploit modules — including
> ones with reverse-shell payloads. **Only run it against targets you own, or
> for which you have explicit written authorization to test** (e.g. a bug
> bounty program in scope, a client engagement letter, or your own lab
> infrastructure). Unauthorized scanning or exploitation of systems you do
> not own or have permission to test is illegal in most jurisdictions. You
> are responsible for how you use this tool.

---

## What the license means in practice

Ronin-Mini is licensed under the [Business Source License 1.1](LICENSE), not
MIT or Apache — here's what that actually means if you're reading this repo:

- **You can clone it, read every line, run it, modify it, and fork it.**
  Nothing about the source is hidden or restricted from inspection.
- **You can use it for your own security work** — run it against your own
  systems, use it as part of a paid client engagement you deliver yourself,
  build on it for internal tooling, include it in a portfolio, whatever.
  That's all covered as ordinary use, commercial or not.
- **You can contribute** — PRs, forks, modifications are all fine under this
  license.
- **The one thing you can't do**: stand up Ronin (or something substantially
  similar to it) as a hosted, managed, or as-a-service product and sell
  access to *it* to third parties — i.e. don't turn this into a competing
  pentesting-as-a-service platform without a commercial license from me.
  Using Ronin as a tool to deliver your own separately-branded consulting or
  pentest engagements is not what this restricts.
- **It's temporary**: on 2030-08-18, this specific restriction lapses
  automatically and the code becomes available under the fully permissive
  Apache License 2.0.

This isn't legal advice — read [LICENSE](LICENSE) for the actual terms if
your use case is anywhere near the line.

---

## Architecture at a glance

- **`agent_core.py`** — the one model↔tool loop (`run_tool_loop`), shared by
  every agent. Also owns MCP server spawning, per-agent tool filtering, tool
  execution, the HITL approval gate, and loading externalized prompts/skills.
- **`models/`** — `ModelAdapter` interface (`base.py`) + `AnthropicAdapter`
  (`anthropic_adapter.py`) + `OpenAICompatibleAdapter`
  (`openai_compatible_adapter.py`, backs any OpenAI-compatible provider —
  OpenRouter, GLM/Zhipu direct, OpenAI itself — via constructor args, not a
  new class per provider) + `build_adapter(provider, model)` (`__init__.py`),
  the one seam every agent goes through. `agent_core.py` never imports a
  provider SDK directly. `--provider openrouter --model qwen/qwen3.6-plus`
  (or `z-ai/glm-5.2`, `deepseek/deepseek-v4-pro`, any other OpenRouter model
  slug) runs against it via OpenRouter (needs `OPENROUTER_API_KEY` set) —
  one provider name covers every model OpenRouter fronts, picked via
  `--model`; see `models/__init__.py` for the provider registry.
- **`agents/*.md`** — externalized role prompts (`recon.md`, `exploit.md`,
  `verify.md`), loaded as `str.format()` templates.
- **`skills/*.md`** — per-vulnerability-class methodology (16 files: 14
  web-app vuln types + `known_vulnerable_service`/`weak_credentials` for
  network-layer findings), each tagged with `status` (`full`/`stub`), `cwe`,
  `attack_technique` (MITRE ATT&CK id), `attack_tactic` in YAML frontmatter.
  All 16 are `status: full` with real, hand-authored methodology as of
  2026-08-19 — `exploit_agent` loads the matching skill for a finding's
  type; a future `stub` skill (the mechanism still exists, no shipped file
  uses it right now) falls back to a local, offline ATT&CK lookup tool
  instead of guessing.
- **`ronin-tools-mcp/`** — the MCP server. Tools are grouped into categories
  (`manifest.yaml` is the registry: timeouts + HITL default + declared replay
  coverage per tool — see [Replay coverage](#replay-coverage-and-the-unverifiable-status)
  below); every call routes through `scope.py` before touching anything, so a
  disallowed host or path is rejected in code, not just discouraged by the
  prompt.
- **HITL approval gate** — three modes (`--hitl-mode`, default `auto`):
  `auto` never prompts, `manual` prompts `[y/n/edit]` on every gated tool
  call, `plan` prompts once per finding/run and reuses that decision. Gated
  by default: `probe_variant`, `execute_python`, `replay_probe`, every
  `network_exploit` tool, `metasploit`, and both `oob_interaction` tools
  (`generate_oob_url`/`poll_oob_interactions`).
- **Mission storage (MongoDB)** — three-agent mode hands findings off through
  a Mongo document per mission (`findings_store.FindingsStore`, one document
  in the `ronin.missions` collection; `--mongo-uri` to point elsewhere,
  default `mongodb://localhost:27017`), not a `findings.json` file anymore.
  Same state machine as before: `new → claimed → exploited | dead-end |
  incomplete → verifying → verified | false_positive | unverifiable |
  verify_incomplete`. `unverifiable` means the verification tooling has no
  way to confirm or refute the claim (a coverage gap) — distinct from
  `false_positive`, which means a replay actually ran and contradicted it.
  `run.py` prints the mission id at startup; pass it back via `--mission-id`
  to resume a mission (skips recon if it already has findings) or to inspect
  it later straight from Mongo.
- **Token usage + cost** — every model call's token usage is captured on
  `ModelResponse` and summed across a run by `agent_core.run_tool_loop`.
  `main.py`/`run.py` print token counts and an estimated dollar cost after
  each stage, via a static pricing table (`models/pricing.py` — currently
  covers Claude Opus/Sonnet/Haiku plus `qwen/qwen3.6-plus` and `z-ai/glm-5.2`
  via OpenRouter; an unrecognized model id falls back to Sonnet-tier rates
  rather than silently showing $0) — treat the dollar figure as an
  approximate, same-session ballpark, not authoritative billing; check your
  provider's real billing dashboard for real spend.
- **Real-time live logging** — every model reasoning turn and every tool
  call/result prints immediately as it happens (prefixed `[recon]`,
  `[exploit:f3]`, `[verify:f9]`, etc. — a terminal watching the whole
  pipeline can tell which stage/finding a line belongs to), and the same
  events get appended to a JSONL log file (`logs/run_<target>_<timestamp>.jsonl`
  by default, override with `--log-path`) for a persistent, replayable
  record of the whole run — including recon's own reasoning, which used to
  be discarded entirely once recon returned only its extracted findings.

## Setup

Full, from-scratch setup for anyone cloning this repo. Windows/PowerShell
notes are called out where a step differs from the Linux/macOS command.

### Fast path: Docker

Skip the manual Python/ripgrep/Docker-Desktop walkthrough below entirely —
the harness itself is packaged as an image:

```bash
git clone https://github.com/Pranavc07/Ronin-Mini.git
cd Ronin-Mini
cp .env.example .env   # fill in ANTHROPIC_API_KEY or OPENROUTER_API_KEY
docker-compose up -d mongo
docker-compose run --rm ronin /app/run.py \
  --target http://host.docker.internal:4280 \
  --objective "Find authentication, IDOR, injection, and network-service vulnerabilities" \
  --scope-dir . \
  --mongo-uri mongodb://mongo:27017
```

Only Docker itself is required on the host — no Python venv, no manual
ripgrep install. Two things differ from running `run.py` directly on a
host, both because this container has its own network namespace:

- A locally published target (DVWA/Juice Shop on `localhost`) needs
  `host.docker.internal` in `--target` instead of `localhost` — same
  convention already used for the Kali attack box's own tools.
- Mongo is reachable at the `mongo` service name, not `localhost` — pass
  `--mongo-uri mongodb://mongo:27017` explicitly.

`--scope-dir .` maps to the project directory on your host (the whole repo
is bind-mounted into the container) — point it at a different local
directory by editing `docker-compose.yml`'s `ronin` service `volumes:` if
you want `code_search`/`file_read` scoped somewhere else. `docker-compose
run --rm ronin /app/main.py ...` runs single-agent mode instead.

This container manages *sibling* containers on the host (for
`execute_python`'s sandbox and the Kali attack box) via the host's mounted
Docker socket — real, standard for "a container that manages containers"
(same pattern most CI runners use), but worth knowing it gives the `ronin`
container effectively root-equivalent access to your Docker daemon. See
`CLAUDE.md`'s "Docker-packaged orchestrator" section for the full design.

Skip to [Get API keys and configure `.env`](#5-get-api-keys-and-configure-env)
below if you haven't created `.env` yet — everything else in this section
is for running the harness directly on your host instead.

### 1. Clone and install Python dependencies

```bash
git clone https://github.com/Pranavc07/Ronin-Mini.git
cd Ronin-Mini
python -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

Requires Python 3.11+. `requirements.txt` pulls in the Anthropic SDK, the
OpenAI SDK (used for any OpenAI-compatible provider, including OpenRouter),
`pymongo`, `mcp`, and the rest of the harness's real dependencies — no
extras needed for the core pipeline.

### 2. Install ripgrep

`code_search` (a `fileops` tool both `recon_agent` and the single-agent loop
can reach) shells out to `rg`. Install it and confirm it's on your `PATH`:

- macOS: `brew install ripgrep`
- Debian/Ubuntu: `sudo apt install ripgrep`
- Windows: `winget install BurntSushi.ripgrep.MSVC` or `choco install ripgrep`
- Verify: `rg --version`

Everything else works without it; only `code_search` calls fail (loudly,
not silently) if it's missing.

### 3. Install and start Docker

Required for `execute_python` (single-agent and three-agent mode both use
it), the Kali attack box (`network_exploit`/`metasploit` tools), and
MongoDB if you run it via the bundled `docker-compose.yml`.

- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  (Windows/macOS) or Docker Engine (Linux), and make sure the daemon is
  actually running (`docker version` should print both a `Client:` and
  `Server:` block with no connection error).
- No manual image builds needed — `execute_python`'s sandbox image and the
  Kali attack box (`ronin-kali-box`, ~4.3GB: Kali + nmap/nikto/sqlmap/hydra/
  gobuster/enum4linux-ng/exploitdb/metasploit-framework) both build
  themselves automatically on first use. The first `network_exploit` or
  `metasploit` call in a fresh environment will take a while; every call
  after that reuses the already-built image/container.

### 4. Start MongoDB (three-agent mode only)

`run.py` (three-agent mode) stores mission/finding state in MongoDB via
`findings_store.py`; `main.py` (single-agent mode) doesn't need this at all.

```bash
docker-compose up -d mongo
```

This starts a local MongoDB 7 instance on `localhost:27017` with a named
volume (`ronin-mongo-data`) so data survives container restarts. Already
running MongoDB somewhere else? Skip this and pass `--mongo-uri` pointing at
it instead (any standard connection string, e.g.
`mongodb://user:pass@host:27017`).

### 5. Get API keys and configure `.env`

Ronin talks to models through a provider-agnostic adapter
(`models/build_adapter`) — pick **Anthropic direct**, **OpenRouter**
(fronting many providers through one account), or both.

Create a `.env` file in the repo root. The harness itself doesn't auto-load
`.env` (no `python-dotenv` dependency) — running via Docker Compose picks it
up automatically (`env_file: .env` on the `ronin` service), but running
`main.py`/`run.py` directly needs the variables actually exported into your
shell first, e.g. `set -a && source .env && set +a` (bash) before invoking
Python, or just `export` them directly:

```bash
# Anthropic direct -- used when you run with --provider anthropic (the default)
ANTHROPIC_API_KEY=sk-ant-...

# OpenRouter -- used when you run with --provider openrouter
OPENROUTER_API_KEY=sk-or-v1-...
```

You only need the key for whichever provider(s) you actually plan to use.
`main.py`/`run.py` print a warning (not a hard failure) if
`ANTHROPIC_API_KEY` is unset, regardless of which provider you're actually
using — harmless if you're running with `--provider openrouter`.

**Anthropic direct** — get a key at
[console.anthropic.com](https://console.anthropic.com/settings/keys). Run
with `--provider anthropic --model claude-sonnet-4-6` (or omit both; that's
the default).

**OpenRouter** — one account/key fronts many different model providers
(Qwen, GLM/Zhipu, DeepSeek, and more), so you don't need a separate key per
model family:

1. Sign up and get a key at [openrouter.ai/keys](https://openrouter.ai/keys).
   Add credits — OpenRouter is pay-as-you-go, not a monthly subscription.
2. Set `OPENROUTER_API_KEY` as shown above.
3. Run with `--provider openrouter --model <full-model-slug>`, e.g.:

   ```bash
   python run.py --target http://localhost:4280 \
     --objective "..." --scope-dir . \
     --provider openrouter --model qwen/qwen3.6-plus
   ```

   Other confirmed-working slugs: `z-ai/glm-5.2`, `deepseek/deepseek-v4-pro`.
   **Watch for `:free` suffixes** (e.g. `z-ai/glm-5.2:free`) — OpenRouter's
   free tiers commonly don't support tool calling at all, which this
   harness requires end-to-end; use the paid (no-suffix) model id instead.
   Browse [openrouter.ai/models](https://openrouter.ai/models) (filter by
   "Supports tools") for other options.

Adding a genuinely different endpoint (e.g. GLM/Zhipu's own API directly,
rather than via OpenRouter) is a small addition — see `models/__init__.py`'s
`_build_openrouter_adapter` for the pattern (`OpenAICompatibleAdapter`
pointed at a specific `base_url`/API-key env var); no new adapter class
needed, just a new provider entry.

### 6. Sanity-check the setup

```bash
docker version    # confirms Docker daemon is reachable
docker-compose ps # confirms mongo is Up (three-agent mode)
rg --version       # confirms ripgrep is on PATH
pytest tests/      # full suite -- Docker/API-dependent tests skip automatically if unavailable
```

You're ready to run either mode — see below.

## Running it (single-agent)

```bash
python main.py \
  --target http://localhost:3000 \
  --objective "Find any authentication or IDOR vulnerabilities in the login and account endpoints" \
  --scope-dir ./juice-shop-source \
  --max-iterations 40 \
  --max-minutes 20
```

### CLI flags (`main.py`)

| Flag | Required | Default | Description |
|---|---|---|---|
| `--target` | yes | — | Target URL or host |
| `--objective` | yes | — | Free-text objective for the agent |
| `--scope-dir` | yes | — | Local directory that `code_search`/`file_read` are sandboxed to |
| `--max-iterations` | no | `40` | Max total tool calls before stopping |
| `--max-minutes` | no | `20` | Wall-clock cap in minutes before stopping |
| `--model` | no | `claude-sonnet-4-6` | Model ID |
| `--provider` | no | `anthropic` | Model provider adapter (see `models/__init__.py`) |
| `--hitl-mode` | no | `auto` | `auto` \| `manual` \| `plan` — see HITL section above |
| `--output-dir` | no | `.` | Where to write the transcript JSON file |
| `--log-path` | no | auto (`logs/run_<target>_<timestamp>.jsonl`) | Live JSONL log of every reasoning turn + tool call/result |

## Three-agent mode (recon → exploit → verify)

```bash
python run.py \
  --target 192.168.56.5 \
  --objective "Find authentication, IDOR, injection, and network-service vulnerabilities" \
  --scope-dir .
```

`run.py` prints the generated mission id at startup (`[+] Mission id: <id>`);
pass `--mission-id <id>` on a later invocation to resume that mission
(recon is skipped if it already has findings) or to inspect it from Mongo
directly (`mongosh`, Compass, whatever you already use).

### CLI flags (`run.py`)

| Flag | Required | Default | Description |
|---|---|---|---|
| `--target` | yes | — | Target URL or host |
| `--objective` | yes | — | Free-text recon objective |
| `--scope-dir` | yes | — | Directory `code_search`/`file_read` are sandboxed to |
| `--mongo-uri` | no | `mongodb://localhost:27017` | MongoDB connection URI where mission findings are stored |
| `--mission-id` | no | auto-generated | Resume an existing mission instead of starting a fresh one |
| `--budget-usd` | no | none | Optional mission-level cost cap (approximate); the run stops before starting a stage that would exceed it |
| `--recon-max-iterations` / `--recon-max-minutes` | no | `40` / `20.0` | Recon's own budget |
| `--exploit-per-finding-max-iterations` / `--exploit-per-finding-max-minutes` | no | `10` / `5.0` | Budget *per finding* for exploit_agent (each finding gets a fresh conversation) |
| `--exploit-worker-count` | no | `1` | Concurrent exploit_agent workers claiming findings from the same mission (see "Concurrent finding processing" below) |
| `--verify-per-finding-max-iterations` / `--verify-per-finding-max-minutes` | no | `6` / `5.0` | Budget *per finding* for verify_agent |
| `--verify-worker-count` | no | `1` | Concurrent verify_agent workers, same mechanism as `--exploit-worker-count` |
| `--allow-high-worker-count` | no | off | Lift the default cap of `25` on the two worker-count flags above |
| `--model` | no | `claude-sonnet-4-6` | Model ID |
| `--provider` | no | `anthropic` | Model provider adapter |
| `--hitl-mode` | no | `auto` | `auto` \| `manual` \| `plan` |
| `--log-path` | no | auto (`logs/run_<target>_<timestamp>.jsonl`) | Live JSONL log across all three stages |

Recon's budget is the ceiling on how much of the target actually gets
explored — a narrow budget with a broad target (many open services) will cut
recon off mid-sweep well before it's covered everything. Widen
`--recon-max-iterations`/`--recon-max-minutes` and give an objective that
explicitly asks for full-surface coverage if you want recon to enumerate
everything before going deep on the first interesting thing it finds.

### Concurrent finding processing

By default, exploit_agent and verify_agent each process one finding at a
time, sequentially. Pass `--exploit-worker-count N` / `--verify-worker-count
N` to run `N` workers concurrently against the same mission instead — each
worker opens its own MCP session and atomically claims the next unclaimed
finding (MongoDB's per-document `update_one` is the compare-and-swap; no
Redis, no separate task queue).

```bash
python run.py \
  --target 192.168.56.5 \
  --objective "Find authentication, IDOR, injection, and network-service vulnerabilities" \
  --scope-dir . \
  --exploit-worker-count 4 --verify-worker-count 2
```

There's a default cap of `25` on both flags. It's a *measured* number, not a
guess: a live stress test scaled cleanly through 10/20/40/80 concurrent
workers (getting faster each step), then broke hard at 150 — not from
MongoDB or a model-provider rate limit, but from the host OS running out of
process/handle table space to spawn that many concurrent subprocesses.
`--allow-high-worker-count` lifts the cap if you've confirmed your machine
has more headroom than that.

One caveat: `--budget-usd` is only checked *between* stages, not mid-stage,
so a higher worker count can burn past the cap further before it's caught
than it would running sequentially.

### The flow

1. **`recon_agent`** (tools: `recon` + `fileops` + `network_exploit` — it can
   reach for nmap/nikto/sqlmap/hydra/gobuster/enum4linux/searchsploit itself,
   deciding what fits the target) explores and writes candidate findings,
   typed from a fixed 14-word vocabulary, into the mission's `findings` list
   in Mongo:

   ```jsonc
   // shape of the mission document's "findings" field (ronin.missions in Mongo)
   [
     {
       "id": "f1", "type": "sqli", "target": "/rest/products/search",
       "evidence": "...", "status": "new", "discovered_by": "recon-agent",
       "exploit_attempts": [], "verify_attempts": []
     }
   ]
   ```

2. **`exploit_agent`** (tools: `web_exploit` + `exploit_runtime` +
   `attack_reference` + `network_exploit` + `metasploit_exploit` +
   `oob_interaction` — the only agent with Metasploit and out-of-band-testing
   access) processes each `status: new` finding in its
   own fresh conversation: `new → claimed → exploited | dead-end |
   incomplete`, appending a full attempt record (skill used, CWE, ATT&CK
   technique, transcript, verdict) to `exploit_attempts`. It prefers a
   matched pre-built tool (`probe_variant`, a `network_exploit` tool, or
   `metasploit` once `searchsploit` identifies a real module) over
   hand-rolling exploits in `execute_python`, reaching for the latter only
   when a finding needs custom logic no pre-built tool covers.

3. **`verify_agent`** (tools: **only** `replay_probe` — it cannot reach
   recon/exploit tools, by design) re-checks each `status: exploited`
   finding: `verifying → verified | false_positive | unverifiable |
   verify_incomplete`. `replay_probe` literally re-runs the winning
   attempt's recorded tool calls and diffs original-vs-replayed output —
   independent confirmation, not new exploration.

### Replay coverage and the `unverifiable` status

`replay_probe` walks every recorded call in a winning attempt's transcript.
For a call to a tool with real replay support, it genuinely re-executes it
and returns original-vs-replayed output. For a call to a tool with no
declared replay support, it returns an explicit `{"replayable": false,
"reason": ...}` stub instead of silently dropping the call — every call from
the original transcript shows up, none vanish. `verify_agent`'s prompt
(`agents/verify.md`) is instructed accordingly: `false_positive` is reserved
for "a replay actually ran and contradicted the claim"; `unverifiable` means
"the tooling has no way to confirm or refute this" — a coverage gap, not a
falsification.

Coverage is manifest-declared, not hand-maintained: every tool in
`manifest.yaml` requires a `replayable: "true" | "false" | "partial"` field
(`manifest.py` reads it via required-key indexing — a tool added without
declaring this fails loudly at `load_manifest()` time, not silently).
`categories/verify.py`'s replayable-tool set is *derived* from that field, so
it can't drift out of sync with the manifest the way a separately
hand-maintained list can. `tests/test_replay_coverage.py` asserts every
`"true"`/`"partial"` tool reachable by `exploit_agent` has a real dispatch
case in `_replay_call` — this is what fails automatically the moment a new
tool lands in a category `exploit_agent` can reach without anyone deciding
what replay should do with it, which is exactly how a real Metasploit-
confirmed root shell once got mislabeled `false_positive` (see `CLAUDE.md`
for the full incident writeup). `"partial"` (currently `hydra` and
`metasploit`) marks tools with real dispatch whose replay fidelity has a
known live-environment caveat — e.g. a one-shot exploit trigger, or a
reverse-shell payload depending on network topology matching the original
run — separate from the coverage-gap problem `unverifiable` solves.

### `execute_python` sandboxing

Each call runs in a fresh, disposable Docker container (`python:3.11-slim` +
`requests`, image builds itself on first use):

- **Filesystem**: root FS is read-only; the only writable path is a fresh
  per-call scratch directory bind-mounted in.
- **Resources**: capped memory/CPU/pids. A hung container gets an explicit
  `docker kill`, not just an abandoned `docker run`.
- **Network**: the container can reach the target (needed to actually test
  it) — this is the one place scope enforcement is a *soft* guarantee, not a
  hard one. An injected `ronin_target.py` helper re-checks the target host
  against the same allowlist every other tool enforces, and both the tool
  description and `exploit_agent`'s prompt push the model to use
  `ronin_target.request(...)` instead of raw `requests`/`socket`/`urllib` —
  but code that deliberately bypasses the helper isn't technically blocked.
  Closing this for real would mean a Docker network with an egress
  allowlist; deferred deliberately (see
  `ronin-tools-mcp/categories/exploit_runtime.py` for the full writeup).

### The Kali attack box (`network_exploit`)

A long-lived container (`ronin-kali-box`, not ephemeral like
`execute_python`) built from `ronin-tools-mcp/docker/kali-tools.Dockerfile`.
Every tool takes structured, typed parameters — enums for scan types/
wordlists, regex-validated port strings, never raw flag passthrough — and
validates its target through `scope.py` before building a command, run as a
real argv list via `docker exec` (never a shell string, so there's no shell
for injected metacharacters to reach). Loopback targets (`localhost`) are
translated to `host.docker.internal` after scope validation, since these
tools run *inside* the Kali container.

### Metasploit (`metasploit_exploit`, `exploit_agent`-only)

Runs a real Metasploit exploit module inside the same Kali container via a
generated resource script. The one deliberate exception to this repo's
fixed-enum-everywhere discipline: `module` is free-text (not a curated
allowlist), and reverse-shell payloads (`payload`/`lhost`/`lport`) are
supported — both by explicit design choice. What's still enforced
regardless: `scope.py` host validation, a resource-script injection guard
(no newlines in module/payload/options), and `lport` must fall in a fixed
published port range so a reverse listener is actually externally reachable.
Gated by HITL like everything else higher-risk here — see
[`CLAUDE.md`](CLAUDE.md) for the full design writeup, including the
LHOST-networking caveat for reverse shells.

### Out-of-band testing (`oob_interaction`, `exploit_agent`-only, Phase 4)

`generate_oob_url` + `poll_oob_interactions` confirm blind SSRF/XXE/
command-injection — cases where the target's direct HTTP response can't
show the effect (e.g. it fetches a URL server-side but never echoes the
result). Backed by [interactsh](https://github.com/projectdiscovery/interactsh),
the free, open-source OOB interaction service — **not Burp Collaborator**,
which requires a paid Burp Suite Professional license and would make this
capability inaccessible to anyone using `ronin-mini` without one.

`generate_oob_url` registers a fresh session (its own RSA keypair,
correlation id, secret key — generated client-side, persisted per-mission
via `FindingsStore` so a later `poll_oob_interactions` call, including one
made much later during `verify_agent`'s replay in a completely separate
process, can still decrypt interactions on it) and returns a unique URL to
embed in a payload. `poll_oob_interactions` checks whether the target
actually reached out to it — a real DNS/HTTP callback is direct,
independent proof of impact that doesn't depend on any response content
leaking back at all. No official Python client exists for interactsh, so
the protocol (RSA-OAEP key exchange, AES-CTR interaction decryption) is
implemented directly against interactsh's own Go client/server source —
see `categories/oob_interaction.py`'s module docstring for the exact
reasoning, and `tests/test_oob_interaction.py` for a real (not mocked)
crypto round-trip proving the decryption is protocol-compatible.

`generate_oob_url` is declared `replayable: "false"` in `manifest.yaml` —
re-registering a fresh session during `verify_agent`'s replay proves
nothing about the original finding. The actual replay value is in the
payload call that used the URL (already replayable via its own tool) plus
a fresh `poll_oob_interactions` call on the *same* correlation id, which
**is** replayable (`"partial"` — interactsh retains interactions only for a
limited server-side TTL, a live-environment caveat, not a coverage gap;
same category as `hydra`/`metasploit`).

## Tools available to the agents

Tools are implemented in [`ronin_mini/ronin-tools-mcp/`](ronin_mini/ronin-tools-mcp),
organized by category (see
[`manifest.yaml`](ronin_mini/ronin-tools-mcp/manifest.yaml) for the full
registry — name, category, description, timeout, HITL default).

| Category | Tools | Gated? |
|---|---|---|
| `recon` | `http_request`, `dns_lookup` | no |
| `fileops` | `code_search`, `file_read` | no |
| `attack_reference` | `lookup_attack_technique` (local, offline MITRE ATT&CK lookup) | no |
| `web_exploit` | `probe_variant` (baseline-vs-variant request diff) | yes |
| `exploit_runtime` | `execute_python` | yes |
| `verify` | `replay_probe` | yes |
| `network_exploit` | `nmap`, `nikto`, `sqlmap`, `hydra`, `gobuster`, `enum4linux`, `searchsploit` | yes |
| `metasploit_exploit` | `metasploit` | yes |
| `oob_interaction` | `generate_oob_url`, `poll_oob_interactions` (interactsh-backed out-of-band testing) | yes |

### Per-agent tool allowlisting

The MCP server exposes everything; each agent narrows what it sees via a
client-side category filter against `manifest.yaml` — a disallowed tool
isn't just discouraged, it's never presented to the model in that agent's
conversation:

- **recon_agent**: `recon`, `fileops`, `network_exploit`
- **exploit_agent**: `web_exploit`, `exploit_runtime`, `attack_reference`,
  `network_exploit`, `metasploit_exploit`, `oob_interaction`
- **verify_agent**: `verify` only

**Scope enforcement** ([`ronin-tools-mcp/scope.py`](ronin-tools-mcp/scope.py))
is centralized and applies to every tool, network tools included:
`code_search`/`file_read` resolve every path with `os.path.realpath` and
reject anything outside `--scope-dir`; every network tool validates the
target host against an allowlist (derived from `--target` by default)
*before* touching the network — including every hop of an HTTP redirect,
not just the initial URL (`executor.run_http` follows redirects manually,
re-validating each destination; a target can't redirect an in-scope request
out of scope). See [`tests/test_scope.py`](tests/test_scope.py) (unit),
[`tests/test_redirect_scope.py`](tests/test_redirect_scope.py) (redirect
validation), and [`tests/test_mcp_server.py`](tests/test_mcp_server.py)
(end-to-end, through the real server).

**Prompt-injection mitigation**: target-controlled content (tool output,
and evidence text quoting target content) is wrapped with a fresh,
unpredictable per-conversation token before it reaches the model
(`agent_core.wrap_untrusted_data`), with an explicit "this is data, not
instructions" notice — a random token, not a fixed delimiter, so a target
response can't spoof the boundary by guessing it. This is a structural
mitigation, not a guarantee against every injection technique; see
[`tests/test_prompt_injection.py`](tests/test_prompt_injection.py) and
`CLAUDE.md`'s prompt-injection section for the documented scope/limits.

## Testing

```bash
pytest tests/
```

Notable files:
- `test_scope.py` — unit, no dependencies.
- `test_mcp_server.py` / `test_execute_python.py` — spin up the real MCP
  server / real Docker.
- `test_e2e.py` — full agent loop against a real Anthropic API call; skipped
  automatically if `ANTHROPIC_API_KEY` isn't set.
- `test_network_exploit.py` — unit, mocked Kali container calls, no Docker
  needed. `test_network_exploit_integration.py` — real Docker + the real
  `ronin-kali-box`; first run builds the ~4.3GB image.
- `test_metasploit.py` — unit, mocked (resource-script construction,
  injection guard, lport range). `test_metasploit_integration.py` — real
  Docker, confirms a real module run completes without hanging.
- `test_findings_store.py` — unit, `mongomock` in place of a real
  `pymongo.MongoClient`; runs without MongoDB installed at all
  (`pytest.importorskip("mongomock")` skips it if that package isn't
  present, rather than failing).
- `test_oob_interaction.py` — unit, mocked interactsh HTTP calls, but the
  RSA-OAEP/AES-CTR decryption is tested for real (a genuine keypair,
  genuine encryption against it, genuine decryption back) — not just that
  mocks were called.

## What this is *not*

By design, this harness does not include: a web UI, a dynamic agent graph,
or a fourth agent. State lives in one Mongo document per mission (Phase 3 —
see `findings_store.py`), a deliberate exception to "no database" made
specifically because the tool output it stores (nmap XML-derived data,
sqlmap/hydra/metasploit results, HTTP probe diffs) is genuinely
heterogeneous, not because this is heading toward a service architecture.
Concurrent finding processing (Phase 5 — see above) is a similar deliberate
exception to "no message queue": it's opt-in (`worker_count` defaults to
`1`, today's exact sequential behavior) and uses MongoDB's own per-document
atomicity for claiming work rather than adding a broker like Redis.
Orchestration is still `run.py` running recon → exploit → verify in
sequence — only *within* the exploit/verify stages can multiple findings
now process concurrently. See [`docs/roadmap.md`](docs/roadmap.md) for
what's deliberately staying out of scope even as this grows.

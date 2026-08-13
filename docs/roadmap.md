# Ronin Roadmap — Current State → Pentest Copilot Scale

Non-negotiable across every phase: per-agent tool allowlisting (client-side, enforced at MCP connection) and scope.py-style target validation on every tool call. These stay even as tools, agents, and infra multiply — this is the one design property that's genuinely stronger than Pentest Copilot's single-generalist-agent model, and it's cheap to preserve now, expensive to retrofit later.

---

## Test Environments Reference

Juice Shop/DVWA only exercise web-layer skills — network/service-layer and out-of-band testing need other targets. Full list, mapped to what each actually validates:

**Network/service-layer (Kali tools, Phase 2)**
- **Metasploitable 2/3** (already have) — real open ports, service fingerprinting, weak-credential targets. Primary target for nmap/nikto/hydra wrappers.
- **VulnHub** — library of downloadable vulnerable VMs, boot2root style. Second network target so exploit_agent isn't just pattern-matching Metasploitable's known quirks.
- **TryHackMe** — already in use for cert study. Guided rooms per-vuln-class are a good fit for validating individual `skills/*.md` files in isolation.
- **HackTheBox** — harder, less guided. Stretch target once the pipeline reliably clears Metasploitable-tier boxes; signal for whether the agent generalizes past its skill files.

**Web-layer, beyond Juice Shop/DVWA (skill generalization + coverage)**
- **WebGoat** (OWASP) — cross-check that a skill file generalizes rather than being tuned to Juice Shop's specific quirks.
- **bWAPP** — 100+ bug classes, good for testing the less-fleshed-out skill stubs (xxe, ssti, deserialization) that Juice Shop/DVWA don't cover deeply.
- **PortSwigger Web Security Academy** — free, isolated labs per vulnerability class with a clear "solved" signal. Closest thing to unit tests for the skills directory — especially valuable for Phase 4's blind SSRF/XXE labs (purpose-built for out-of-band testing).

**API-specific (gap none of the above cover)**
- **crAPI** or **VAmPI** — for when recon tools need to prove they work against pure REST/API surfaces with no HTML frontend to browse.

**Suggested target per phase**

| Phase | Primary target | Secondary/cross-check |
|---|---|---|
| 0 (HITL) | Juice Shop | — |
| 1 (skills + verify) | Juice Shop | WebGoat or bWAPP for skill generalization |
| 2 (Kali box) | **Metasploitable** | VulnHub box for a second network target |
| 3 (Mongo) | same targets, infra swap only | — |
| 4 (Burp/Collaborator) | PortSwigger Academy blind SSRF/XXE labs | — |

Don't stand up all of these at once — add a new target only when an existing one stops giving useful signal for the phase being tested.

---

## Phase 0 — HITL Approval Gate + Model-Agnostic Adapter Layer
**Status: shipped, live-tested end-to-end against DVWA (2026-08-13)**
**Test against: Juice Shop, DVWA (regression check post-refactor)**

HITL gate:
- `require_approval` flag per tool category, resolved onto each `ToolMeta`
  via `manifest.yaml`'s new `categories:` block.
- Gated by default: `execute_python`, `probe_variant`, `replay_probe` (each
  is the sole tool in its category today; new tools landing in a gated
  category — e.g. Phase 2's Kali wrappers in `network_exploit` — inherit
  the gate automatically).
- Three `hitl_mode`s, chosen via `--hitl-mode` (default `auto`): `auto`
  never prompts; `manual` prompts `[y/n/edit]` on every gated call
  (`agent_core.confirm_tool_call`); `plan` prompts once per run/finding
  (`agent_core.confirm_plan_for_run`) and reuses that decision for every
  gated call after, rather than approving one at a time.
- CLI-based, blocks on stdin — no dashboard needed. Fails safe (denies) on
  non-interactive stdin (`EOFError`) rather than crashing a run.
- This pattern becomes mandatory for all Phase 1 Kali tools, so build it before Kali, not after.

Model-agnostic adapter layer (bundled into this phase since it touches the
same file, and is cheap now / expensive to retrofit once 3 agents + Kali
tools have grown provider-specific assumptions):
- `models/base.py` — `ModelAdapter` interface: `send_messages(system, messages, tools, max_tokens) -> ModelResponse`,
  translating provider-specific tool-call blocks into one common format
  (`Turn`/`ToolCall`/`ToolResult`/`ModelResponse`) `agent_core.py` consumes.
- `models/anthropic_adapter.py` — `AnthropicAdapter`, the only real
  implementation for now, wraps current Claude usage (still implicit
  `ANTHROPIC_API_KEY` env auth, unchanged).
- `agent_core.run_tool_loop` calls through `ModelAdapter`, not the Anthropic
  client directly, everywhere across recon/exploit/verify (and the legacy
  single-agent `loop.py`).
- `models/__init__.py`'s `build_adapter(provider, model)` is the one seam —
  no router, no per-turn model selection, no second provider yet. Which
  model/provider an agent uses is set once via `--provider`/`--model` CLI
  flags. A second adapter (OpenAI, a local model, etc.) becomes a new file
  + one dispatch branch later, not a rewrite.
- Explicitly not in scope here: cost/latency-based routing, multi-model
  missions, local model integration — revisit only when there's a concrete
  reason, same discipline as everything else shelved on this roadmap.

## Phase 1 — Skills + Verify Agent
**Status: shipped, live-tested end-to-end against Juice Shop (2026-08-10) — all 6 findings reached `verified` with matching original-vs-replay evidence**
**Test against: Juice Shop, cross-check on WebGoat or bWAPP**

- `agents/*.md` (role prompts), `skills/*.md` (14 web vuln classes, 4 fully written: sqli, idor, xss, auth_bypass — rest stubbed).
- `verify_agent`: read-only on findings.json + `replay_probe` tool, confirms or flags `false_positive` on `exploited` findings.
- `run.py`: recon → exploit → verify, sequential.

## Phase 1.5 — ATT&CK + CWE Tagging, Live ATT&CK Fallback
**Status: shipped, live-tested end-to-end against DVWA (2026-08-13) — every stub-type finding that reached a verdict used `lookup_attack_technique` and was independently confirmed `verified`**
**Test against: Juice Shop (`security_misconfig` / `path_traversal` findings already produced by the last live run are ready-made stub-type test cases)**

- Tag all 14 `skills/*.md` files with lightweight YAML frontmatter: `status`
  (`full`/`stub`), `cwe`, `attack_technique`, `attack_tactic`. CWE gives
  precise vuln-class identity (ATT&CK's Enterprise matrix is too coarse for
  this — nearly every web finding collapses to T1190); ATT&CK gives tactic
  framing that becomes more differentiated once Phase 2 adds network/host
  findings.
- New local, offline `lookup_attack_technique` MCP tool (`attack_reference`
  category) backed by a slim, pre-filtered copy of MITRE's public Enterprise
  ATT&CK data (`ronin-tools-mcp/data/attack_enterprise_slim.json` — no live
  API/network dependency at runtime).
- `exploit_agent` gets `attack_reference` added to its allowlist. When a
  finding's skill is only a `stub` (10 of the 14 today), the prompt nudges it
  to call `lookup_attack_technique` and derive its own approach from the
  returned technique description, instead of guessing from nothing. Skills
  with `status: full` behave exactly as before — this is a fallback, not a
  skill replacement.
- Deliberately not a kill-chain planner: this doesn't chain findings across
  an ATT&CK tactic graph (see "what stays out of scope" — that needs real
  multi-step surface, which arrives with Phase 2's Kali tools).

## Phase 2 — Kali Attack Box
**Status: shipped, integration-tested against DVWA (2026-08-13); Metasploitable-specific live check pending (no Metasploitable target in this environment yet)**
**Test against: Metasploitable (primary), a VulnHub box (secondary)**

- Persistent Kali container (`ronin-kali-box`, `docker exec` per call, not
  ephemeral like `execute_python`) built from a purpose-built, reproducible
  `ronin-tools-mcp/docker/kali-tools.Dockerfile` (`kalilinux/kali-rolling` +
  exactly the packages Ronin needs — see `CLAUDE.md`).
- Seven tools in `categories/network_exploit.py`, all structured params /
  enums / regex-validated, never raw flags: `nmap`, `nikto`, `sqlmap`,
  `hydra` (the original "start narrow" four) plus `gobuster` (content
  discovery — a gap nmap/nikto don't cover), `enum4linux` (SMB enumeration —
  Metasploitable's headline vulnerable service), `searchsploit` (offline
  exploit-db lookup, gives nmap's service/version output somewhere to go).
  Hydra/gobuster wordlists come from Kali's own real `wordlists`/`seclists`
  packages, referenced by a fixed enum resolved to real on-image paths —
  never a raw path from the model.
- All Kali tool calls HITL-gated by default via `manifest.yaml`'s
  `network_exploit` category (`require_approval: true`, inherits the
  Phase 0 `hitl_mode` system like any other gated category — no
  special-casing).
- `network_exploit` category → exploit_agent's allowlist only. Recon stays HTTP/DNS-only; active scanning is a different risk tier from passive requests, keep that boundary.
- Loopback-host translation (`localhost` → `host.docker.internal` after
  scope validation) needed since these tools run *inside* the Kali
  container — caught by the integration test, not anticipated in the
  original design.

## Phase 3 — MongoDB (replaces findings.json)
- Skip SQLite as an intermediate step — you're running a DB server eventually regardless (Redis + dashboard both assume one), and Mongo's flexible schema fits the genuinely heterogeneous tool output you're about to ingest (nmap XML, sqlmap output, Burp results all look structurally different).
- Same claim-state-machine logic (`new → claimed → exploited/dead-end → verified/false_positive`), now backed by a real document store instead of a JSON file.
- Add mission-level token/cost budget tracking here — natural fit once you're in a real DB.
- Deliberately learn Mongo's document model properly at this stage rather than treating it as plumbing — the whole point is understanding every layer.

## Phase 4 — Burp Suite Integration (Collaborator)
**Test against: PortSwigger Web Security Academy blind SSRF/XXE labs**

- The one Pentest Copilot capability that's a genuine non-redundant gap in what you have: out-of-band verification for blind SSRF/XXE/command injection.
- Fits into `verify_agent`'s toolset — direct response inspection can't catch blind vulns, Collaborator can.
- Also expose proxy history / Repeater as tools for exploit_agent if useful once you're here.
- PortSwigger Academy labs are purpose-built for this and give a clear solved/not-solved signal, unlike Juice Shop/DVWA which don't have much blind-vuln surface.

## Phase 5 — Concurrency + Redis
- Only once you actually need real concurrent agent execution (the worker-pool model from earlier — multiple exploit_agent instances pulling from a shared task queue) rather than sequential phases.
- Redis as the task queue / broker at this point — file or Mongo-based claim-locking gets awkward under real concurrency.
- Triggered by an actual bottleneck (missions taking too long sequentially), not added speculatively.

## Phase 6 — Visibility Layer
- `ronin status <mission_id>` — CLI table view of mission/findings state, before committing to a frontend.
- Validates you actually want dashboard-level visibility before paying for the frontend build.

## Phase 7 — Web Dashboard + Docker Compose
- Full product layer: live mission view, Redis pub/sub for real-time updates, Docker Compose orchestration across services.
- Browser automation (Magnitude-style) for JS-heavy app testing can land around here too — real capability gap, but a big enough addition to deserve its own scoped pass rather than folding into an earlier phase.
- VPN management — only relevant once you're testing against real external engagements, not localhost targets.
- If Ronin ever needs to handle pure REST/API targets with no HTML frontend, crAPI or VAmPI are the purpose-built test environments for that — add only when recon tooling needs to prove it works against API-only surfaces.

---

## What stays deliberately out of scope, even at full maturity

- A single generalist agent with unscoped access to all tools — the core critique of Pentest Copilot's architecture; don't converge toward this even as capability grows.
- Kafka / full microservices / dynamic agent graph — revisit only if Phase 5's concurrency needs genuinely outgrow Redis + Mongo, not by default.
- Multi-provider ModelAdapter / model router — build only if a concrete cost or capability reason forces it.

## How to work each phase

Same discipline as Phases 0-1: scoped Claude Code prompt per phase, test against real targets (Juice Shop/DVWA, plus a boot2root VM from Phase 2 on) before moving to the next, update `docs/progress.md` at the end of each session, `/clear` freely since CLAUDE.md + progress.md carry continuity.

# Ronin Roadmap — Current State → Pentest Copilot Scale

Non-negotiable across every phase: per-agent tool allowlisting (client-side, enforced at MCP connection) and scope.py-style target validation on every tool call. These stay even as tools, agents, and infra multiply — this is the one design property that's genuinely stronger than Pentest Copilot's single-generalist-agent model, and it's cheap to preserve now, expensive to retrofit later.

**This is the public, BSL-licensed core (Track A) — this file only covers what's in this repo.** As of 2026-08-19, `ronin-mini` is packaged as a real pip-installable library (`ronin_mini/`, tagged `v0.5.0`) specifically so it can be depended on, not forked. A second, proprietary repo — [`ronin-pro`](https://github.com/Pranavc07/ronin-pro), private — depends on this repo's tagged commits and holds the agentic-AI security testing + SOC 2 compliance-mapping direction ("Track B"). See `ronin-pro`'s own `docs/roadmap.md` for that plan; nothing from Track B lands in this repo. Bugfixes and core improvements always land here first and flow into `ronin-pro` by bumping its pinned dependency commit.

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
- **bWAPP** — 100+ bug classes, good for cross-checking skill generalization on classes Juice Shop/DVWA don't cover deeply (xxe, ssti, deserialization — all now `status: full`, but never live-tested against a real target for those specific classes).
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

- `agents/*.md` (role prompts), `skills/*.md` (14 web vuln classes, 4 fully written at the time: sqli, idor, xss, auth_bypass — rest stubbed; all 10 remaining stubs later completed 2026-08-19, see `docs/progress.md`).
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
  finding's skill is only a `stub` (10 of the 14 at the time this phase
  shipped; all later completed to `status: full`, 2026-08-19), the prompt nudges it
  to call `lookup_attack_technique` and derive its own approach from the
  returned technique description, instead of guessing from nothing. Skills
  with `status: full` behave exactly as before — this is a fallback, not a
  skill replacement.
- Deliberately not a kill-chain planner: this doesn't chain findings across
  an ATT&CK tactic graph (see "what stays out of scope" — that needs real
  multi-step surface, which arrives with Phase 2's Kali tools).

## Phase 2 — Kali Attack Box
**Status: shipped, live-tested against DVWA + real Metasploitable (2026-08-13) — nmap correctly fingerprinted vsftpd 2.3.4/Samba 3.0.20, enum4linux-ng pulled real SMB shares, searchsploit found the real CVE-2011-2523 backdoor off nmap's own output, hydra confirmed real SSH attack connectivity. Tool-level only — see the known gap below.**
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
- **Reconsidered after the initial live test surfaced a real gap** (2026-08-13):
  `network_exploit` was originally exploit_agent-only, with recon deliberately kept
  HTTP/DNS-only ("active scanning is a different risk tier, keep that boundary").
  That meant no full `recon → exploit → verify` run could ever produce a finding
  that reached these tools at all. Decision: recon_agent now has real agent-level
  access to the full `network_exploit` toolset too (`ALLOWED_CATEGORIES` includes
  it, same mechanism exploit_agent already used) — it decides which recon tools fit
  the target's scope itself, real `tool_use` turns, not host-code-triggered. The
  safety control was never "which agent can reach the category" — it's
  `require_approval: true` on `network_exploit` in `manifest.yaml`, which still
  gates every call from either agent under `--hitl-mode manual`/`plan`. Two new
  finding types (`known_vulnerable_service`, `weak_credentials`, full skills,
  genuine ATT&CK differentiation from T1190 via T1210/T1110) give recon's
  network-layer discoveries somewhere to go.
- Loopback-host translation (`localhost` → `host.docker.internal` after
  scope validation) needed since these tools run *inside* the Kali
  container — caught by the integration test, not anticipated in the
  original design.
- **`metasploit` added on top** (2026-08-15): a real Metasploit exploit
  module runner, its own `metasploit_exploit` category, `exploit_agent`-only
  (never `recon_agent` — explicit direction, unlike the other 7 tools which
  both agents share). The one deliberate exception to this repo's
  fixed-enum-everywhere discipline: `module` is a free-text Metasploit
  module path, and reverse-shell payloads (`payload`/`lhost`/`lport`) are
  supported — both by explicit user choice over narrower alternatives
  (a curated module allowlist; backdoor/bind-only payloads) proposed and
  declined. What's still enforced regardless: `scope.validate_host` on the
  target, a resource-script injection guard (no newlines in
  module/payload/options/post_exploit_command), and `lport` validated
  against a fixed published range (`executor.KALI_LPORT_RANGE`,
  `44440-44450`) so a reverse listener is actually reachable. See
  `CLAUDE.md`'s Metasploit section for the full design, including the
  LHOST networking caveat (operator-supplied, not auto-detected).

## Phase 3 — MongoDB (replaces findings.json)
**Status: shipped, live-tested end-to-end against DVWA (2026-08-19) — two full recon→exploit→verify runs (Qwen3.6 Plus, GLM 5.2) confirmed mission creation, `--mission-id` resume after a mid-run crash, per-stage `stage_usage` recording, and the MCP-subprocess's own Mongo connection for `replay_probe` all work on real data**
**Test against: Metasploitable still pending (DVWA only so far) — this phase changes storage, not agent behavior, so any prior live-tested target is a valid regression check**

- Skip SQLite as an intermediate step — you're running a DB server eventually regardless (Redis + dashboard both assume one), and Mongo's flexible schema fits the genuinely heterogeneous tool output you're about to ingest (nmap XML, sqlmap output, Burp results all look structurally different).
- Same claim-state-machine logic (`new → claimed → exploited/dead-end → verified/false_positive`), now backed by a real document store instead of a JSON file. `findings_store.py`'s `FindingsStore` wraps `pymongo.MongoClient`: one document per mission in the `ronin.missions` collection, `findings` embedded as a list and rewritten wholesale on every save (`$set`) — mirrors the old file-based `_save_findings`'s "load, mutate, rewrite" pattern exactly, so `recon_agent`/`exploit_agent`/`verify_agent`'s `loop.py` logic didn't need to change, only the I/O calls around it.
- Added mission-level token/cost budget tracking as planned: `stage_usage.<stage>` on the mission document (`store.record_stage_usage`), and `run.py --budget-usd` checks cumulative estimated cost between stages, stopping before a stage that would exceed the cap.
- `run.py` creates a mission at startup and prints its id; `--mission-id` resumes an existing one (skips recon if it already has findings) instead of starting over from scratch — a real resume path `findings.json` never had.
- `categories/verify.py`'s `replay_probe` runs inside a separate MCP-server subprocess with no access to the host's `FindingsStore`, so it needed its own path to Mongo: `run_replay_probe`/`register()` were decoupled from storage entirely (they take an already-loaded findings list / a `findings_loader` callable, no Mongo awareness), and `server.py`'s `build_server` is the only place that constructs a real `FindingsStore` from `--mongo-uri`/`--mission-id` (deferred-imported, so recon/exploit's server spawns — which pass neither — never need `pymongo` importable).
- `docker-compose.yml` added for a one-line local Mongo (`docker-compose up -d mongo`); `--mongo-uri` points at any other instance.
- Deliberately learn Mongo's document model properly at this stage rather than treating it as plumbing — the whole point is understanding every layer.
- Live-tested 2026-08-19 against DVWA: confirmed the full recon→exploit→verify pipeline behaves correctly on real Mongo (not mongomock), `--mission-id` resume works after a real mid-run crash, and `--budget-usd` tracking works across stages. Two real bugs surfaced and fixed during this pass, unrelated to the storage migration itself: a Windows-console Unicode crash in the live-logging code, and a pricing-table bug that mispriced both OpenRouter models tested (see `docs/progress.md`'s 2026-08-19 entry for both).
- NEXT: no committed next step for Phase 3 itself. A live check against Metasploitable (network-layer findings, not just web-layer) would be the remaining cross-check if it comes up.

## Phase 4 — Out-of-band testing (interactsh, not Burp Collaborator)
**Status: implemented and unit-tested (2026-08-19), NOT yet live-tested against a real target**
**Test against: PortSwigger Web Security Academy blind SSRF/XXE labs**

- The one Pentest Copilot capability that's a genuine non-redundant gap in what you have: out-of-band verification for blind SSRF/XXE/command injection.
- **Reconsidered from the original "Burp Suite Integration (Collaborator)" framing**: Collaborator's polling API requires a paid Burp Suite Professional license, which would make this capability inaccessible to anyone using `ronin-mini` without one -- cuts against the OSS spirit of the repo. Built on [interactsh](https://github.com/projectdiscovery/interactsh) instead: free, open-source, self-hostable, mechanically equivalent (unique subdomains, poll for DNS/HTTP/SMTP callbacks). User decision, made explicitly before any code was written.
- New `oob_interaction` category (exploit_agent-only, not verify_agent as originally sketched -- exploit_agent is the one that actually crafts the payload embedding the OOB URL, so it needs to *generate* the URL, not just verify after the fact). Two tools: `generate_oob_url` (registers a session, returns a payload URL), `poll_oob_interactions` (checks for callbacks). No official Python interactsh client exists, so the protocol (RSA-OAEP key exchange, AES-CTR interaction decryption) is implemented directly against interactsh's own Go source -- see `CLAUDE.md`'s Phase 4 section for the full protocol writeup.
- Session keys persisted per-mission via `FindingsStore` (embedded `oob_sessions` dict, keyed by correlation_id) -- required, not a nicety, since exploit_agent and verify_agent spawn separate MCP server subprocesses and a keypair held only in one subprocess's memory wouldn't survive to a later replay.
- Fits into the *existing* replay-coverage machinery with no structural changes to verify_agent (still only ever calls `replay_probe`): `generate_oob_url` declared `replayable: "false"` (re-registering a session on replay proves nothing), `poll_oob_interactions` declared `replayable: "partial"` (real re-poll, but interactsh's retention TTL is a live-environment caveat, same class as `hydra`/`metasploit`). This is the first real case of an exploit_agent-reachable tool declared `"false"` -- `tests/test_replay_coverage.py`'s dynamic checks picked it up with zero test-logic changes, exactly as that test file's own comments anticipated.
- `skills/ssrf.md`, `skills/xxe.md`, `skills/command_injection.md` updated with real OOB methodology, replacing their old "unconfirmable with current tooling" language.
- Proxy history / Repeater tools for exploit_agent (the original roadmap's secondary bullet) not built -- no concrete need identified yet, same "don't build ahead of a real requirement" discipline as everything else here.
- PortSwigger Academy labs are purpose-built for this and give a clear solved/not-solved signal, unlike Juice Shop/DVWA which don't have much blind-vuln surface.
- NEXT: live-test against a real target (a PortSwigger blind SSRF/XXE lab) to confirm the interactsh round-trip works end-to-end against a real target, not just the synthetic crypto proof in `tests/test_oob_interaction.py`.

## Phase 5 — Concurrency (Mongo-atomic first cut; Redis deferred)
**Status: shipped a scoped-down first cut — concurrent findings within one mission, via MongoDB atomic claiming, no Redis (2026-08-21)**

- Built without a recorded sequential-time bottleneck (this phase's own gating language says "triggered by an actual bottleneck... not added speculatively" — worth being honest that this one shipped ahead of that trigger, at the user's explicit direction). Given that, deliberately scoped down from the original Redis-broker plan below: fixed the real concurrent-write race in `findings_store.py`'s old whole-list `save_findings` (last-writer-wins under concurrent callers) with MongoDB's own per-document atomicity (`claim_next_finding`/`complete_finding`, a real compare-and-swap claim) instead of adding new broker infrastructure. See `CLAUDE.md`'s "Concurrent finding processing" section for the full design.
- `exploit_agent`/`verify_agent` each gained a `worker_count` param (`run.py --exploit-worker-count`/`--verify-worker-count`, both default `1` = unchanged sequential behavior) — multiple workers claim different findings from the *same* mission concurrently, each with its own MCP session/subprocess.
- **Original plan, not built, still the trigger for a real Phase 5b**: Redis as the task queue / broker — only once Mongo-atomic claiming genuinely bottlenecks under real concurrent load (contention, not just "would be nice"), not by default. Cross-mission concurrency (parallel whole pipelines) is also still unaddressed — a different problem from this phase's within-mission concurrency.
- Known caveat: `--budget-usd` is checked between stages only, so higher worker counts can overshoot the cap further before it's caught — not fixed in this pass.
- NEXT: live-test with `--exploit-worker-count > 1` against a real target (e.g. re-run a DVWA mission's remaining findings concurrently) to confirm no duplicated/dropped attempts on real Mongo, not just mongomock unit tests.

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

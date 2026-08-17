# Progress log

Running log, most recent first. Keep entries to 3-5 lines. Update at the end of
each work session with: what changed, what's in progress, next concrete step.

---

## 2026-08-16 — Structural fix: `unverifiable` status + manifest-declared replay coverage
- Follow-up to the false-positive replay bug fixed 2026-08-15. That fix
  (extending `REPLAYABLE_TOOLS` to cover `network_exploit` + `metasploit`)
  addressed the specific tools involved, but left the *mechanism* unfixed:
  `REPLAYABLE_TOOLS` was still a hand-maintained tuple that happened to be
  kept in sync by one regression test -- a new tool landing in a category
  `exploit_agent` can reach, without anyone updating that tuple, would
  silently reopen the identical bug. Worth noting: by the time this session
  started, `metasploit` already had real replay support (confirmed by
  reading the current code before touching anything) -- the user's initial
  framing described the pre-fix symptom, which no longer matches what's in
  the repo; flagged and corrected before writing any code.
- New finding status `unverifiable`, distinct from `false_positive`: means
  the verification tooling has no way to confirm or refute a claim (a
  coverage gap), never a disproof. `categories/verify.py`'s
  `run_replay_probe` (refactored out of the `register()` closure into a
  testable module-level function, matching every other category's `run_*`
  pattern) now walks every recorded call in a winning attempt and returns
  either a real replay (tool has dispatch support) or an explicit
  `{"replayable": false, "reason": ...}` stub (tool doesn't) -- every call
  from the original transcript is visible in the output, none silently
  vanish. `agents/verify.md` updated: `false_positive` is reserved for "a
  replay actually ran and contradicted the claim"; `unverifiable` for
  everything else. `verify_agent/loop.py` recognizes `unverifiable` as a
  terminal verdict status.
- `manifest.yaml` now requires every tool to declare
  `replayable: "true" | "false" | "partial"`; `manifest.py` reads it via
  required-key indexing (`entry["replayable"]`, not `.get()`), so a tool
  added without deciding this fails loudly at `load_manifest()` time --
  every code path that loads the manifest, not just a dedicated test.
  `categories/verify.py`'s replayable-tool set is now *derived* from this
  field instead of hand-maintained, structurally preventing the drift that
  caused the original bug. Audited and declared for all 17 existing tools:
  11 `"true"` (deterministic/idempotent -- probe_variant, execute_python,
  the 6 idempotent network_exploit scans/lookups, lookup_attack_technique),
  2 `"partial"` (hydra, metasploit -- real dispatch exists and genuinely
  re-executes, but replay fidelity has a known live-environment caveat:
  account lockout/rate-limiting for hydra, one-shot exploit triggers and
  LHOST/network-topology dependence for metasploit), 4 `"false"`
  (http_request, dns_lookup, code_search, file_read, replay_probe itself --
  all structurally unreachable by exploit_agent, so replay coverage is moot
  for them, not a gap).
- `tests/test_replay_coverage.py` (new, 8 tests): asserts every manifest
  tool declares a valid `replayable` value; `load_manifest()` raises
  (behaviorally tested, not just inspected) on a missing or invalid
  `replayable` field; every `"true"`/`"partial"` tool `exploit_agent` can
  reach has a real `_replay_call` dispatch case (parametrized per tool,
  fails with a specific message naming the missing case); `"false"` tools
  never reach real dispatch. `tests/test_verify.py` gained 4 more:
  regression-checks the *original* bug against current code (a
  reconstructed CVE-2011-2523-shaped metasploit winning attempt dispatches
  to real replay, not a stub -- proving that bug stays fixed); a synthetic
  undeclared-tool case proving the *new* unverifiable mechanism actually
  fires (metasploit itself can't exercise this path anymore since it's
  already replayable -- used a synthetic tool name instead, and said so
  explicitly rather than silently substituting); a mixed-calls case;
  existing `test_every_exploit_agent_tool_is_replayable` generalized to
  allow a legitimately-declared `"false"` tool rather than requiring every
  exploit-agent tool be replayable. 128/129 tests pass (Docker/live-API
  tests skipped as usual); the one failure is the pre-existing, unrelated
  `test_mcp_server_full_flow` stale-tool-list issue, already flagged as a
  separate background task.
- NEXT: no committed next step for this fix. Two related, explicitly
  out-of-scope items surfaced but not built: (1) real metasploit-module
  replay improvements (this pass only prevents mislabeling, doesn't improve
  live-replay fidelity) -- a real feature deserving its own scoped design;
  (2) the separate, still-open problem of a *genuinely-run* live replay
  failing for one-shot/network-topology reasons and getting conflated with
  a real `false_positive` -- `"partial"` flags this in-band now but doesn't
  solve it. Awaiting user decision on whether/when to commit this change.

## 2026-08-16 — Token usage + cost tracking
- Added after a live Metasploitable full-pwn run hit `credit balance too low`
  mid-exploit-stage, and there was no way to answer "how much has this
  actually cost" beyond guessing from tool-call counts -- the harness never
  tracked tokens anywhere.
- `models/base.py`'s `ModelResponse` now carries a `usage: Usage` field
  (input/output/cache tokens); `AnthropicAdapter` populates it from the real
  API response, getattr-guarded so mocked responses default to zero instead
  of raising. `agent_core.run_tool_loop` sums usage across every model call
  in one invocation and returns it; each `run_*_agent()` threads it through
  (recon: run-level; exploit/verify: per-finding on each attempt record,
  plus a run-level total via new `models.sum_usage`). `models/pricing.py`
  converts a usage dict to a dollar estimate via a static, maintained
  pricing table (Sonnet-tier fallback for unrecognized model ids) --
  explicitly not a live lookup, Anthropic doesn't expose one. `run.py`
  prints per-stage + total tokens/cost; `main.py` prints the same for
  single-agent runs. Every cost line is labeled approximate and points at
  `console.anthropic.com` as the real source of truth.
- 11 new unit tests (`tests/test_usage_tracking.py`): Usage arithmetic,
  pricing table lookup + unknown-model fallback + missing-key defaults,
  adapter usage extraction (present and absent), run_tool_loop accumulation
  across single and multiple model calls. Full suite still passes (109/110;
  the one failure, `test_mcp_server_full_flow`, is pre-existing and
  unrelated -- a stale expected-tool-name set that predates the Kali/
  Metasploit tools, flagged separately, not fixed here).
- NEXT: no committed next step. The interrupted Metasploitable full-pwn run
  (54 findings, 12 processed before the credit error) is still sitting in
  `findings_metasploitable_fullpwn.json`, gitignored -- resume once credits
  are topped up. `run.py` has no resume-from-partial-file support yet
  (reruns recon from scratch), worth a look if this comes up again.

## 2026-08-15 — Live Metasploitable run + fixed a real verify bug it found
- Ran the full `recon -> exploit -> verify` pipeline against real
  Metasploitable (192.168.56.5) with `--objective` explicitly asking for
  exploitation, not just enumeration. Results: recon made 40 real tool
  calls (nmap/enum4linux/etc, its own tool_use turns) and produced 11
  candidate findings; exploit_agent processed all 11, reaching real
  Metasploit-confirmed exploits including a root shell via
  `exploit/multi/samba/usermap_script` (CVE-2007-2447) and a real backdoor
  session via `exploit/unix/ftp/vsftpd_234_backdoor` (CVE-2011-2523) --
  full proof the recon-agent-access fix and `metasploit` tool both work
  end-to-end through the real agent pipeline, not just tool-level.
- Found and fixed a real bug this run surfaced: `categories/verify.py`'s
  `replay_probe` only ever replayed `probe_variant`/`execute_python` calls
  -- a filter that predates network_exploit/metasploit. 3 genuinely
  exploited findings (the two CVEs above + a Ghostcat/CVE-2020-1938 file
  read) got marked `false_positive` purely because replay found zero calls
  it knew how to run, not because the exploits weren't real. Fixed by
  extending `REPLAYABLE_TOOLS`/`_replay_call` to cover all 7 network_exploit
  tools + `metasploit` + `lookup_attack_technique`, with a regression-guard
  test (`test_every_exploit_agent_tool_is_replayable`) that diffs
  exploit_agent's actual toolset against what verify can replay, so this
  can't silently drift again when a tool is added.
- Confirmed the fix works mechanically (replaying f2/f3's real metasploit
  calls now genuinely re-attempts them, where before it found nothing to
  run) -- but also surfaced a *separate*, not-a-bug nuance while doing so:
  live-exploit replay can legitimately fail a second time for reasons
  outside the code (vsftpd's backdoor is one-shot on the target; LHOST for
  reverse payloads is host network topology, not a container-internal IP).
  Documented both distinctly in CLAUDE.md so they don't get conflated later.
- 104 tests pass (7 new in test_verify.py). Committed.
- NEXT: no committed next step. The `false_positive`s from this specific
  run stay as historical record in findings_metasploitable.json (gitignored,
  not committed) -- a fresh pipeline run would now verify them correctly
  for the repeatable exploits (Samba/Ghostcat), modulo the live-replay
  caveat above.

## 2026-08-15 — Added metasploit (exploit_agent-only)
- New `metasploit_exploit` category (separate from `network_exploit` so it
  can go to `exploit_agent` only, not `recon_agent` -- explicit user
  direction). `categories/metasploit.py`'s `metasploit` tool runs a real
  Metasploit module against a scope-validated target inside the same
  long-lived Kali container, via a generated resource script (`docker exec
  -i ... tee` to write it in, no bind mount available on this container).
- Two explicit, deliberate exceptions to this repo's usual discipline, by
  user choice after I proposed narrower alternatives and they declined
  both: `module` is free-text (no curated allowlist), and reverse-shell
  payloads are supported (`payload`/`lhost`/`lport`). What's still
  enforced: scope validation, a resource-script newline-injection guard,
  and `lport` must fall in a fixed published range
  (`executor.KALI_LPORT_RANGE`, 44440-44450) -- `ensure_kali_container_ready()`
  now publishes that range and recreates the container if an existing one
  predates it (Docker can't add port publishing after creation).
- `skills/known_vulnerable_service.md` + `agents/exploit.md` updated:
  prefer `metasploit` over hand-rolled `execute_python` when a matching
  module exists, `execute_python` stays the fallback.
- 13 new unit tests (mocked) + a Docker-integration test file (metasploit-
  framework installed, a real module run against a closed port completes
  without hanging). Image rebuild with `metasploit-framework` (~4.3GB+)
  kicked off; still running as of this entry -- confirm it finished and the
  integration test actually passes before considering this shipped.
- NEXT: once the image build finishes, run the full suite + the new
  integration tests, then the live check -- exploit_agent should call
  `metasploit` with `exploit/unix/ftp/vsftpd_234_backdoor` against the real
  Metasploitable box and get a real session-opened result. Everything here
  is uncommitted on `main`, stacked on top of the also-uncommitted
  recon-agent-access fix below.

## 2026-08-14 — Closed the recon->network_exploit reachability gap
- Reconsidered the Phase 2 boundary decision after the user pushed back:
  `recon_agent.ALLOWED_CATEGORIES` now includes `network_exploit` (real
  agent-level tool access, same mechanism exploit_agent already had) --
  recon decides itself which of the 7 Kali tools fit the target's scope,
  real `tool_use` turns, not host-code-triggered. Superseded the original
  "recon stays HTTP/DNS-only" note in `docs/roadmap.md` explicitly rather
  than leaving it stale; HITL gating (`require_approval` on
  `network_exploit`) is what actually keeps this safe, unchanged.
- Two new finding types (`known_vulnerable_service` -> `searchsploit`,
  `weak_credentials` -> `hydra`), both `status: full` skills with real
  CWE/ATT&CK tags verified against `attack_enterprise_slim.json` (T1210
  Lateral Movement, T1110 Credential Access -- first genuine ATT&CK
  differentiation from T1190 since Phase 1.5 promised it would happen).
  `agents/recon.md` and `agents/exploit.md` updated with tool guidance.
- 4 new wiring tests + full regression suite pass (77 tests; Docker Desktop
  was down for this run so `test_execute_python.py`/the 3 Kali integration
  tests didn't execute -- pre-existing documented behavior, not a
  regression).
- NEXT: live check handed to user -- run `run.py` against real
  Metasploitable (192.168.56.5) and confirm recon_agent itself calls
  nmap/enum4linux/etc. (visible in its own transcript) and produces
  known_vulnerable_service/weak_credentials findings that exploit_agent
  then validates. This is what actually closes the gap end-to-end.
  Everything here is uncommitted on `main`.

## 2026-08-13 — Phase 2 (Kali attack box) built and integration-tested
- New `ronin-tools-mcp/docker/kali-tools.Dockerfile` (kalilinux/kali-rolling
  + nmap/nikto/sqlmap/hydra/wordlists/seclists/gobuster/enum4linux-ng/
  exploitdb, ~4.3GB built image). `executor.py` gained
  `ensure_kali_container_ready()`/`run_in_kali_container()` for a long-lived
  container (`ronin-kali-box`, `docker exec` per call) rather than
  execute_python's ephemeral-per-call pattern.
- `categories/network_exploit.py`: 7 tools (nmap, nikto, sqlmap, hydra,
  gobuster, enum4linux, searchsploit), all structured params/enums, no raw
  flags. Started at the roadmap's original 4, extended to 7 after
  identifying concrete gaps (content discovery, SMB enum, exploit-db
  lookup) -- each got the same parameter-design review/sign-off as the
  original four before any code was written.
- Real bugs caught by the Docker-integration test (not the mocked unit
  tests): nmap's `-F` and `-p` flags are mutually exclusive -- fixed by
  dropping `-F` when explicit ports are given; gobuster's guessed "medium"
  wordlist filename was wrong (actual: `DirBuster-2007_directory-list-2.3-
  medium.txt`) -- fixed by listing the real installed seclists tree instead
  of guessing. Also added loopback-host translation
  (`localhost`->`host.docker.internal`) since these tools run inside the
  Kali container, not through a scope-checked helper like execute_python --
  without it every scan would hit the Kali box itself instead of DVWA/Juice
  Shop.
- 32 unit tests (mocked `run_in_kali_container`) + 3 real Docker/DVWA
  integration tests all pass. Both roadmap copies + CLAUDE.md updated.
- Metasploitable live check DONE (2026-08-13, user stood up a real
  Metasploitable at 192.168.56.5): ran the 7 tools directly (tool-level, not
  through an agent -- see the gap noted below) against a real target.
  `nmap default_scripts` correctly fingerprinted vsftpd 2.3.4, anonymous FTP,
  Samba 3.0.20, and every classic Metasploitable open port; `enum4linux-ng`
  pulled real domain/OS info and all 5 SMB shares (incl. the world-writable
  `tmp` share); `searchsploit "vsftpd 2.3.4"` found the actual CVE-2011-2523
  backdoor exploit off nmap's own output -- exactly the gap that tool was
  added to close; `hydra` confirmed real connectivity and a real attack
  in-flight against SSH (didn't finish within a bounded timeout against
  10k real password attempts -- expected, not a bug).
- GAP SURFACED, not yet fixed: `recon_agent` has no `network_exploit`
  access and the 14-word finding-type vocabulary is entirely web-vuln-class
  -- there is currently no path for a full `recon -> exploit -> verify`
  pipeline run to ever hand `exploit_agent` a finding that would make it
  reach for `nmap`/`hydra`/etc. Today's Kali tools are real and tested at
  the tool level, but not yet reachable through the actual agent pipeline
  end-to-end. Needs its own scoped pass (network-layer finding types +
  either recon getting narrow nmap-discovery access, or a way to seed
  network-layer findings directly) -- not done as part of Phase 2.

## 2026-08-11 — Phase 0 (HITL gate + model-agnostic adapter) + Phase 1.5 (ATT&CK/CWE) built
- Phase 0: new `models/` package (`base.py`'s `ModelAdapter`/`Turn`/`ToolCall`/
  `ToolResult`/`ModelResponse`, `anthropic_adapter.py`'s `AnthropicAdapter`,
  `__init__.py`'s `build_adapter(provider, model)`); `agent_core.run_tool_loop`
  rewritten to talk only to the adapter, never `anthropic.AsyncAnthropic()`
  directly. HITL gate wired in via `manifest.yaml`'s new `categories:` block
  (`require_approval` on `web_exploit`/`exploit_runtime`/`verify`/
  `network_exploit`), with three modes (`--hitl-mode`, default `auto`):
  `auto` never prompts, `manual` prompts every gated call
  (`agent_core.confirm_tool_call`, `[y/n/edit]`), `plan` prompts once per
  run/finding (`agent_core.confirm_plan_for_run`) and reuses that decision
  for the rest of the run -- added after initial build once live-testing
  surfaced that per-call manual prompts were too much friction for routine
  runs. All 4 agent loops + `main.py`/`run.py` (`--provider`, `--hitl-mode`
  flags) updated. 23 unit tests pass (HITL scenarios incl. all 3 modes,
  manifest resolution, Turn<->Anthropic-block translation with a mocked
  client) plus a real-MCP-server integration check with a fake adapter
  (dns_lookup ran ungated, no HITL prompt, transcript/extract_blocks
  intact). NOT yet live-tested interactively with a real model (needs a
  human at the `[y/n/edit]`/plan prompt to sanity-check the UX feel).
- Phase 1.5: skills tagged with CWE/ATT&CK frontmatter, `lookup_attack_technique`
  MCP tool + local slim ATT&CK dataset, exploit_agent fallback for `stub`
  skills. 9 unit tests pass. NOT yet live-tested against DVWA (prepared
  `findings_dvwa_test.json` with a reset stub-type + full-type finding,
  handed to user to run since it needs `ANTHROPIC_API_KEY`).
- Both roadmap copies (`docs/roadmap.md`, `Downloads/ronin-roadmap.md`)
  updated: Phase 1 marked shipped, Phase 1.5 added, Phase 0 expanded with
  the adapter layer.
- Both live checks DONE: user ran `run.py` against DVWA end-to-end
  (`findings_dvwa_live.json`, gitignored). Confirms Phase 0's adapter
  rewrite is functionally transparent (full recon->exploit->verify pipeline
  completed on real API calls) AND Phase 1.5's fallback works live -- every
  stub-type finding that reached a verdict (command_injection,
  path_traversal, csrf, file_upload, security_misconfig) called
  `lookup_attack_technique` before probing and was independently confirmed
  `verified` by verify_agent. `business_logic` correctly got
  `attack_technique: None`. The `incomplete` results match DVWA's documented
  session/login limitation, not a regression.
- Ready to commit: everything from 2026-08-11 (Phase 0 + Phase 1.5) is
  implemented, unit-tested, and now live-verified.

## 2026-08-10 — Part 2 live-tested end-to-end: verify stage confirmed
- Ran `run.py` against Juice Shop (recon -> exploit -> verify, full pipeline,
  fresh findings.json). All 6 findings (2 sqli, 3 security_misconfig, 1
  path_traversal) went `new -> exploited -> verified`; `replay_probe` reproduced
  matching original-vs-replay output for every winning attempt.
- Confirms the isolation design works in practice, not just offline: verify_agent
  only ever called `replay_probe`, never invented new probes.
- Ready to commit everything from 2026-08-10 (Part 1 + Part 2 + this live test).
- NEXT: no committed next step. Candidate directions if resumed — DVWA session/
  cookie-jar support (the known limitation from 2026-08-09), the execute_python
  egress-allowlist network (Option B, deferred at 2026-08-09), or writing the
  remaining 10 skill stubs beyond sqli/idor/xss/auth_bypass.

## 2026-08-10 — Skills + externalized prompts (Part 1), verify agent (Part 2), incomplete status (C)
- Part 1 DONE & live-tested on DVWA: role prompts moved to `agents/*.md`, per-vuln
  methodology in `skills/*.md` (4 full: sqli/idor/xss/auth_bypass; 10 stubs),
  recon now types findings from a fixed 14-word vocabulary, exploit loads the
  matching skill (records `skill_loaded`). All verified in that run.
- Part 2 + C BUILT & verified offline, NOT yet live-tested: verify_agent (3rd loop,
  tool = only `replay_probe`, isolation confirmed at schema level); `replay_probe`
  literally re-runs a finding's winning attempt; run.py is now recon→exploit→verify.
  C: exploit_agent emits `incomplete` (not `dead-end`) when it never reaches a verdict.
- Surfaced: DVWA session/cookie limitation — exploit re-logs-in per finding and
  mostly `incomplete`s out fighting DVWA's CSRF login (Juice Shop unaffected). Deferred.
- NEXT: live-test Part 2 via `run.py` against Juice Shop (Docker up), confirm the
  `[verify]` stage produces verified/false_positive with real replay transcripts.
  Then commit (all changes uncommitted on `main`). Everything from 2026-08-09 IS committed.

## 2026-08-09 — MCP server + two-agent split + sandboxed execute_python
- Refactored the 4 in-process tools into a standalone MCP server
  (`ronin-tools-mcp/`) with category-based organization and centralized
  `scope.py` enforcement; added the two-agent recon→exploit flow (`run.py`,
  `recon_agent/`, `exploit_agent/`, shared `agent_core.py`) and a
  Docker-sandboxed `execute_python`.
- Validated end-to-end: Juice Shop (recon→exploit, all findings confirmed) and
  DVWA (11/11 exploited incl. blind SQLi, command injection, LFI). Merged to
  `main` and pushed; LinkedIn post drafted.
- Next: no committed next step. Candidate directions if resumed — a verification
  agent, cookie-jar/session support in the tools (DVWA needed manual cookie
  threading), or the execute_python egress-allowlist network (Option B).
